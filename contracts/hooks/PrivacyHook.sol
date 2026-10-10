// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseERC8183Hook} from "../BaseERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";

/// @dev Optional proof verifier. Proof-system agnostic within the instance's gas cap; the public
///      inputs are fixed (see FORMAT). Only a 32-byte return word equal to 1 counts as accepted.
interface IZKVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}

/// @dev The one view a hook router must expose for the constructor check (MultiHookRouter does).
interface IHookRouter {
    function erc8183Contract() external view returns (address);
}

/**
 * @title PrivacyHook
 * @notice Example ERC-8183 hook for confidential deliverables. Profile C (experimental, high-risk).
 *         The provider submits keccak256(ciphertext) as the deliverable together with hash
 *         commitments to the data key and to each recipient's wrapped copy of it. The hook checks
 *         them against an immutable per-instance policy and records one binding per job. No
 *         ciphertext, plaintext or key material goes on-chain; only hashes, a suite id and an
 *         optional proof. There is no owner.
 *
 * USE CASE
 * --------
 * A provider delivers encrypted work to the job's client and evaluator. Escrow, settlement and
 * attestation stay public; the deliverable's contents do not. By convention `deliverable` is
 * keccak256(ciphertext), so a recipient can check the bytes it fetched against the chain. The hook
 * records, per job, a binding over that value and over commitments to the data key and to each
 * recipient's wrapped copy. It never sees the ciphertext, the key or the wrapped keys and checks
 * none of them; recipients verify off-chain against the binding.
 *
 * FLOW (all interactions through core contract -> hook callbacks)
 * ----
 *  1. Deploy one instance per policy (allowedSuites, minLeaves, requireProof, verifier,
 *     verifierGasCap). The core admin whitelists the instance.
 *  2. createJob(provider, evaluator, expiredAt, description, hook = this instance or a
 *     MultiHookRouter). Behind a router the client attaches this instance to `submit` with
 *     configureHooks. The client therefore chooses the policy; the provider cannot change it.
 *  3. setBudget / fund: no hook logic. Their optParams are untouched and free for other hooks.
 *  4. Off-chain: the provider encrypts the deliverable under a random data key dk, wraps dk for each
 *     recipient under the chosen suite, and delivers ciphertext and wrapped keys off-chain. Wrapped
 *     keys are never published.
 *  5. submit(jobId, deliverable, abi.encode(bytes32[] leaves, bytes32 dkCommit, uint8 suiteId,
 *     bytes proof)). Behind MultiHookRouter the optParams MUST be wrapped as abi.encode(bytes[]) with
 *     one slice per configured hook, even when this is the only hook. Empty or unwrapped optParams
 *     revert InvalidOptParams; encodings below the minimal valid length revert the same way;
 *     malformed longer encodings revert inside the ABI decoder without a named error; trailing or
 *     non-canonical bytes are accepted because every hash is over the decoded values.
 *     -> _preSubmit: validate policy, verify the proof if required, store the binding, emit
 *        EncryptedSubmission (before the core's JobSubmitted in the same receipt).
 *  6. complete / reject / claimRefund: core flow; this hook does nothing.
 *
 * FORMAT (byte-exact; Solidity abi.encode; hashes are over decoded values, never raw optParams)
 * ------
 *  optParams       abi.encode(bytes32[] leaves, bytes32 dkCommit, uint8 suiteId, bytes proof)
 *  deliverable     keccak256(ciphertext)                                         [checked != 0]
 *  dkCommit        keccak256(dk), dk = 32 random bytes                           [checked != 0]
 *  leaf_i          keccak256(abi.encode(uint8 role, bytes32 keccak256(pk), bytes32 keccak256(wk)))
 *                  role: 1 client, 2 evaluator, 3 provider, 4 other. pk: the recipient's per-job
 *                  public key as the suite encodes it. wk: dk wrapped to pk.   [opaque, unchecked]
 *  keysCommitment  keccak256(abi.encode(uint8 suiteId, bytes32 dkCommit, bytes32[] leaves))
 *  binding         computeBinding(): keccak256(abi.encode(TAG, block.chainid, core, address(this),
 *                  jobId, deliverable, keysCommitment, dkCommit, suiteId)) with
 *                  TAG = keccak256("erc8183.privacy-hook.v2"). dkCommit and suiteId repeat so the
 *                  binding can be rebuilt from the event without the leaves.
 *  proof inputs    [bytes32(jobId), deliverable, keysCommitment, binding]. The proof is public
 *                  calldata and is not committed; it is ignored when requireProof is false.
 *
 * SUITES (bit s of allowedSuites enables suite s; suite internals are not checked on-chain and
 * are listed so independent implementations interoperate)
 * ------
 *  0x00  invalid.  0x01  reserved: v1's 94-byte wrapped-key format; never allowed.
 *  0x02  RFC 9180 HPKE base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
 *        pk = 32 bytes; wk = enc(32) || ct(48); aad empty;
 *        info = "erc8183.privacy-hook.v2" || uint8 suiteId || keccak256(abi.encode(
 *               uint256 chainid, address core, uint256 jobId, uint8 role, bytes32 deliverable));
 *        ciphertext = nonce(12) || AES-256-GCM(dk, nonce, plaintext) with 16-byte tag; no AAD.
 *  0x03  HPKE base mode with the PQ/T hybrid KEM MLKEM1024-P384 (draft-ietf-hpke-pq-05, KEM id
 *        0x0051; draft-irtf-cfrg-concrete-hybrid-kems-03 section 4.3, CG framework, label
 *        "MLKEM1024-P384"), HKDF-SHA384, AES-256-GCM. pk = 1665 bytes (ML-KEM-1024 ek || P-384
 *        point, SEC1 uncompressed); wk = enc(1665) || ct(48); aad empty; info and ciphertext as
 *        in 0x02 with suiteId 0x03.
 *
 * TRUST MODEL
 * -----------
 *  - Enforces: non-zero deliverable; suite in the allow-list; non-zero dkCommit; at least minLeaves
 *    leaves; proof accepted when required; the binding is reproducible by anyone from calldata and
 *    the event. One binding per job follows from the core, which accepts one submit per job; the
 *    hook does not re-check it and would store the latest binding on a core that allowed more.
 *  - Does NOT enforce: that the ciphertext is reachable or actually encrypted; that `deliverable`
 *    is the hash of any ciphertext; that dkCommit commits to the data key; that leaves wrap dk to
 *    the right keys or roles; any proof semantics beyond the chosen circuit. The hook cannot stop
 *    the provider or a recipient from disclosing dk or the plaintext off-chain. The binding makes
 *    mis-delivery provable by a recipient, not impossible. Recipients verify off-chain.
 *  - minLeaves counts leaves, not verified recipients. A floor of 1 suits jobs whose evaluator is
 *    the client; use 2 or more when the evaluator must read the work. A floor stops honest
 *    misconfiguration, not a provider padding with junk leaves; a recipient that finds no leaf for
 *    its own key should reject.
 *  - `leafCount` in the event is leaves.length. Leaves are opaque to the hook, so zero, duplicate
 *    and junk leaves all count; it is not the number of parties who can decrypt.
 *  - EncryptedSubmission and getBinding are NOT authoritative alone: any contract set as a job's
 *    hook can emit the event and write the mapping for its OWN jobs. Consumers MUST require, in
 *    the same receipt, the core's JobSubmitted(jobId) with the same `deliverable` (a data field,
 *    not indexed), and that the emitter is the job's hook (job.hook == this, or job.hook is a
 *    router the consumer trusts whose submit hooks for that job contain this).
 *  - `core` is the escrow whose JobSubmitted consumers must match; it is hashed into every binding
 *    and into the off-chain key-wrap context. For a router-bound instance the constructor checks
 *    it against the router's erc8183Contract().
 *  - No owner. Each instance's policy is fixed at deployment, and the core admin's hook whitelist
 *    decides which instances jobs may use. To change policy, deploy a new instance and rotate the
 *    whitelist. Remediation is bounded to new jobs: de-whitelisting makes routers skip this hook
 *    (fail-open) and does not stop direct callbacks on in-flight jobs.
 *  - The verifier is trusted code: a proxy or EIP-7702 account passes the code-size check, so its
 *    logic may change after deployment. Choose instances whose verifier is immutable. A proof
 *    submit needs about verifierGasCap * 64/63 + VERIFIER_GAS_RESERVE gas available at the hook,
 *    whatever the verifier actually uses.
 *  - Exit paths are never blocked when the instance is deployed as documented: this hook overrides
 *    no callback but submit, claimRefund is not hookable, and the base ignores selectors it does not
 *    route (fail-open). The same fail-open means a core upgrade that renames submit would bypass
 *    this hook silently; pin the core commit. Misdeployment caveat: a router-bound instance set
 *    directly as job.hook fails the base's caller check on every callback, so such a job cannot be
 *    budgeted, funded or rejected and can only expire; no funds are at risk.
 *  - On cores with milestone claims (not the pinned core), claim callbacks are not routed by this
 *    base, so a claim's deliverable bypasses this hook. Use single-submit jobs for confidential
 *    work.
 *  - The core is upgradeable (UUPS): its admin may upgrade, pause, withdraw, detach this hook from a
 *    job, or de-whitelist it. Pin the core address and commit in deployment records.
 *  - Router configuration is the client's choice and is frozen at fund; a zero-budget Open job may
 *    be submitted before funding, so confidentiality there rests on the client's configuration.
 *  - Deployment modes: standalone (erc8183Contract = core) or behind a router (erc8183Contract =
 *    router). A core-bound instance also works behind a router, but the base then reads core.getJob
 *    on every callback, which costs gas proportional to the job description and ties access control
 *    to the core's Job layout. Behind a router, bind to the router.
 *
 * KEY PROPERTY: nothing on-chain decrypts the deliverable; the submitted hash is bound to
 * commitments over the data key and every wrapped copy, and anyone can recompute the binding.
 */
contract PrivacyHook is BaseERC8183Hook, IERC8183HookMetadata {
    // --- Policy (immutable per instance) ---

    /// @notice The ERC-8183 escrow proxy. Hashed into every binding (erc8183Contract may be a
    ///         router).
    address public immutable core;
    /// @notice Bitmask over uint8 suiteId; bit s set means suite s is accepted.
    uint256 public immutable allowedSuites;
    /// @notice Minimum number of leaves per submission (>= 1; 2 for client + evaluator).
    uint8 public immutable minLeaves;
    /// @notice Whether every submission must carry a proof accepted by `verifier`.
    bool public immutable requireProof;
    /// @notice Proof verifier; non-zero iff requireProof.
    address public immutable verifier;
    /// @notice Gas forwarded to the verifier; in [1, MAX_VERIFIER_GAS_CAP] iff requireProof, else 0.
    uint256 public immutable verifierGasCap;

    // --- State ---

    mapping(uint256 => bytes32) private _bindings;

    // --- Constants ---

    bytes32 public constant TAG = keccak256("erc8183.privacy-hook.v2");
    /// @dev Bounds per-submit cost so no instance can demand a large share of a block. Pairing-based
    ///      SNARK verifiers fit far below it; the cap is per instance so other proof systems fit too.
    uint256 public constant MAX_VERIFIER_GAS_CAP = 5_000_000;
    /// @dev Gas the hook keeps for itself after the verifier call (event emission and return).
    uint256 public constant VERIFIER_GAS_RESERVE = 50_000;
    /// @dev abi.encode(bytes32[], bytes32, uint8, bytes) with empty arrays: 4 head words + 2 length
    ///      words.
    uint256 public constant OPT_PARAMS_MIN_LENGTH = 192;
    /// @dev Suites 0x00 (invalid) and 0x01 (v1 wrapped-key format) may never be allowed.
    uint256 private constant RESERVED_SUITE_MASK = 0x03;
    bytes4 private constant SEL_SUBMIT = bytes4(keccak256("submit(uint256,bytes32,bytes)"));

    // --- Errors ---

    error InvalidCore();
    error RouterCoreMismatch();
    error NoSuiteAllowed();
    error ReservedSuiteInMask();
    error ZeroMinLeaves();
    error InvalidVerifier();
    error VerifierWithoutProof();
    error InvalidVerifierGasCap(uint256 cap);
    error ZeroDeliverable();
    error InvalidOptParams(uint256 length);
    error SuiteNotAllowed(uint8 suiteId);
    error ZeroDataKeyCommitment();
    error TooFewLeaves(uint256 provided, uint256 required);
    error ProofRequired();
    error InsufficientGasForVerifier(uint256 available, uint256 required);
    error ProofVerificationFailed();

    // --- Events ---

    /// @dev Emitted from _preSubmit, so it precedes the core's JobSubmitted in the receipt.
    event EncryptedSubmission(
        uint256 indexed jobId,
        bytes32 indexed deliverable,
        bytes32 keysCommitment,
        bytes32 dkCommit,
        uint8 suiteId,
        uint256 leafCount
    );

    /// @param erc8183Contract_ Core proxy (standalone) or MultiHookRouter (router-bound).
    /// @param core_            The ERC-8183 core proxy; equals erc8183Contract_ unless router-bound.
    /// @param allowedSuites_   Bitmask of accepted suite ids; bits 0 and 1 must be clear.
    /// @param minLeaves_       Minimum leaves per submission, at least 1.
    /// @param requireProof_    Whether submissions must carry a proof accepted by verifier_.
    /// @param verifier_        IZKVerifier with code when requireProof_, address(0) otherwise.
    /// @param verifierGasCap_  Gas forwarded to the verifier; 1..MAX_VERIFIER_GAS_CAP iff
    ///                         requireProof_, otherwise 0.
    constructor(
        address erc8183Contract_,
        address core_,
        uint256 allowedSuites_,
        uint8 minLeaves_,
        bool requireProof_,
        address verifier_,
        uint256 verifierGasCap_
    ) BaseERC8183Hook(erc8183Contract_) {
        if (core_ == address(0) || core_.code.length == 0) revert InvalidCore();
        if (erc8183Contract_ != core_) {
            // Router-bound: the router must point at the same core, or bindings and the off-chain
            // key-wrap context would name an escrow that never calls this hook. Low-level call with a
            // length check, because try/catch cannot catch a return-data decode failure.
            if (erc8183Contract_.code.length == 0) revert RouterCoreMismatch();
            (bool ok, bytes memory ret) =
                erc8183Contract_.staticcall(abi.encodeCall(IHookRouter.erc8183Contract, ()));
            if (!ok || ret.length != 32 || abi.decode(ret, (address)) != core_) {
                revert RouterCoreMismatch();
            }
        }
        if (allowedSuites_ == 0) revert NoSuiteAllowed();
        if (allowedSuites_ & RESERVED_SUITE_MASK != 0) revert ReservedSuiteInMask();
        if (minLeaves_ == 0) revert ZeroMinLeaves();
        if (requireProof_) {
            // An EOA returns success with empty returndata from staticcall; require code up front.
            if (verifier_ == address(0) || verifier_.code.length == 0) revert InvalidVerifier();
            if (verifierGasCap_ == 0 || verifierGasCap_ > MAX_VERIFIER_GAS_CAP) {
                revert InvalidVerifierGasCap(verifierGasCap_);
            }
        } else {
            // Proof intent must be stated twice so a typo cannot silently disable or enable proofs.
            if (verifier_ != address(0)) revert VerifierWithoutProof();
            if (verifierGasCap_ != 0) revert InvalidVerifierGasCap(verifierGasCap_);
        }
        core = core_;
        allowedSuites = allowedSuites_;
        minLeaves = minLeaves_;
        requireProof = requireProof_;
        verifier = verifier_;
        verifierGasCap = verifierGasCap_;
    }

    // --- Views ---

    function isSuiteAllowed(uint8 suiteId) public view returns (bool) {
        return ((allowedSuites >> suiteId) & 1) == 1;
    }

    /// @notice Binding stored at submit; never deleted, so it stays readable after complete/reject.
    function getBinding(uint256 jobId) external view returns (bytes32) {
        return _bindings[jobId];
    }

    /// @notice Recomputes a binding from public data (see FORMAT). Uses the live block.chainid.
    function computeBinding(
        uint256 jobId,
        bytes32 deliverable,
        bytes32 keysCommitment,
        bytes32 dkCommit,
        uint8 suiteId
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                TAG,
                block.chainid,
                core,
                address(this),
                jobId,
                deliverable,
                keysCommitment,
                dkCommit,
                suiteId
            )
        );
    }

    // --- Hook callbacks only (no direct external functions) ---

    /// @dev Runs before the core changes state; any revert aborts the submit.
    function _preSubmit(
        uint256 jobId,
        address,
        bytes32 deliverable,
        bytes memory optParams
    ) internal override {
        if (deliverable == bytes32(0)) revert ZeroDeliverable();
        if (optParams.length < OPT_PARAMS_MIN_LENGTH) revert InvalidOptParams(optParams.length);
        (bytes32[] memory leaves, bytes32 dkCommit, uint8 suiteId, bytes memory proof) =
            abi.decode(optParams, (bytes32[], bytes32, uint8, bytes));
        if (!isSuiteAllowed(suiteId)) revert SuiteNotAllowed(suiteId);
        if (dkCommit == bytes32(0)) revert ZeroDataKeyCommitment();
        if (leaves.length < minLeaves) revert TooFewLeaves(leaves.length, minLeaves);
        bytes32 keysCommitment = keccak256(abi.encode(suiteId, dkCommit, leaves));
        bytes32 binding = computeBinding(jobId, deliverable, keysCommitment, dkCommit, suiteId);
        // Effects before the external call. The verifier is reached by staticcall, so nothing can
        // re-enter, and a rejected proof reverts the write.
        _bindings[jobId] = binding;
        if (requireProof) _verifyProof(proof, jobId, deliverable, keysCommitment, binding);
        emit EncryptedSubmission(jobId, deliverable, keysCommitment, dkCommit, suiteId, leaves.length);
    }

    /// @dev Gas-capped staticcall to the verifier. The binding among the public inputs covers
    ///      chainid, core and this instance, so a proof cannot be replayed across deployments. A
    ///      verifier that reverts, runs out of gas, writes state, or returns anything but exactly one
    ///      32-byte word equal to 1 is treated as a failed proof. Assembly copies at most 32 bytes of
    ///      returndata, so a misbehaving verifier cannot force unbounded memory expansion.
    function _verifyProof(
        bytes memory proof,
        uint256 jobId,
        bytes32 deliverable,
        bytes32 keysCommitment,
        bytes32 binding
    ) private view {
        if (proof.length == 0) revert ProofRequired();
        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = bytes32(jobId);
        publicInputs[1] = deliverable;
        publicInputs[2] = keysCommitment;
        publicInputs[3] = binding;
        bytes memory cd = abi.encodeCall(IZKVerifier.verify, (proof, publicInputs));
        // EIP-150 forwards at most 63/64 of the remaining gas, so require enough that the verifier
        // really receives the full cap and this function can still emit afterwards.
        uint256 cap = verifierGasCap;
        uint256 required = cap + cap / 63 + VERIFIER_GAS_RESERVE;
        uint256 available = gasleft();
        if (available < required) revert InsufficientGasForVerifier(available, required);
        address v = verifier;
        bool ok;
        uint256 ret;
        assembly ("memory-safe") {
            ok := staticcall(cap, v, add(cd, 32), mload(cd), 0, 32)
            if and(ok, eq(returndatasize(), 32)) { ret := mload(0) }
        }
        if (!ok || ret != 1) revert ProofVerificationFailed();
    }

    // --- IERC8183HookMetadata ---

    /// @dev Only submit carries hook logic. Declaring it lets the router reject configurations that
    ///      attach this hook to other selectors but not to submit.
    function requiredSelectors() external pure returns (bytes4[] memory) {
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = SEL_SUBMIT;
        return sels;
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
