// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseERC8183Hook} from "../BaseERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";
import {ERC8183} from "@erc8183/ERC8183.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @dev Generic interface for zero-knowledge proof verification.
///      Proof-system agnostic — works with Groth16, PLONK, etc.
interface IZKVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/**
 * @title PrivacyHook
 * @notice Example ERC-8183 hook requiring encrypted envelope submissions.
 *         Providers submit a 32-byte content commitment (e.g. sha256(CID)) with
 *         ECDH-wrapped AES keys instead of a plaintext deliverable. The hook
 *         enforces envelope structure and optionally verifies a ZK proof over
 *         the encrypted data.
 *
 *         NOTE: The on-chain `cid` field is `bytes32`, dictated by the core
 *         submit signature. Real IPFS CIDs do not fit (CIDv0 is 34 bytes,
 *         CIDv1 is variable), so the field carries a 32-byte commitment to the
 *         CID, not the CID itself.
 *
 * USE CASE
 * --------
 * When a job's deliverable should remain confidential between provider,
 * client, and evaluator while the escrow flow stays public. The provider
 * encrypts the deliverable with AES-256-GCM, wraps the AES key per
 * recipient via ECDH, uploads the ciphertext to IPFS, and submits a 32-byte
 * commitment over the resulting CID on-chain. The hook validates envelope
 * shape and an optional ZK proof over job-specific constraints on the
 * encrypted data.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *  2. setBudget(jobId, amount, optParams=abi.encode(zkVerifier, minWrappedKeys))
 *     → _postSetBudget: store privacy config for this jobId (one-time, immutable).
 *     Optionally: abi.encode(zkVerifier, minWrappedKeys, numPublicInputs) for
 *     circuits with more than 2 public inputs.
 *  3. fund(jobId, expectedBudget, "") — normal funding, no hook logic.
 *  4. Off-chain: encrypt deliverable, ECDH-wrap the AES key per recipient,
 *     upload ciphertext to IPFS, optionally generate a ZK proof whose public
 *     inputs are (jobId, cid, …) — where `cid` is the 32-byte commitment that
 *     will be submitted on-chain, not the raw IPFS CID.
 *  5. submit(jobId, cid, optParams=abi.encode(cid, wrappedKeys, zkProof))
 *     → _preSubmit: validate envelope structure, verify ZK proof if required,
 *       store envelope commitment hash.
 *     For numPublicInputs > 2:
 *       optParams=abi.encode(cid, wrappedKeys, zkProof, extraPublicInputs)
 *     → core: set Submitted.
 *     → _postSubmit: emit EncryptedSubmission event for off-chain indexing.
 *  6. complete / reject — normal flow.
 *
 * WRAPPED KEY FORMAT (v1, 94 bytes)
 * ---------------------------------
 *   version(1) || ephemeralPub(33 compressed) || iv(12) || authTag(16) || encAESKey(32)
 *
 * TRUST MODEL
 * -----------
 * The hook checks ENVELOPE SHAPE only:
 * - That the submission contains a 32-byte content commitment, a wrapped-key
 *   array, and a proof field.
 * - That each wrapped key is the right length and starts with the v1 version byte.
 * - That the wrapped-key array size is within configured bounds.
 *
 * The hook DOES NOT enforce:
 * - That the data referenced by the CID is actually encrypted.
 * - That the wrapped keys decrypt to anything, or are wrapped to the right people.
 * - That the ZK proof relates to the encrypted contents in any meaningful way.
 * - That the CID is reachable, pinned, or in a valid IPFS format.
 *
 * The user must:
 * - Pick a `zkVerifier` that the hook admin has marked as trusted.
 * - Use a circuit whose public inputs bind (jobId, cid commitment, …) to
 *   constraints that matter for their use case. A circuit that proves
 *   `1 == 1` will pass.
 * - Verify recipients off-chain — the hook cannot do this.
 * - Set `minWrappedKeys >= 2` if privacy beyond self-broadcast is intended;
 *   `minWrappedKeys = 1` is permitted but means a single recipient and
 *   provides no confidentiality between submitter and that recipient.
 *
 * Per-job config is frozen at the first setBudget call. If the hook owner
 * later removes a verifier from the whitelist, jobs that already configured
 * that verifier continue to use it at submit time — remediation is bounded
 * to future jobs only.
 *
 * The hook never reads or stores envelope contents; it only stores metadata
 * (the 32-byte content commitment, wrapped-key blobs in transit, and an
 * envelope commitment hash).
 */
contract PrivacyHook is BaseERC8183Hook, IERC8183HookMetadata, Ownable {
    struct PrivacyConfig {
        address zkVerifier;      // IZKVerifier address, or address(0) if no ZK required
        uint8 minWrappedKeys;    // minimum wrapped keys required (e.g. 2 = client + evaluator)
        uint8 numPublicInputs;   // number of ZK public inputs (default 2: jobId + cid)
        bool configured;         // distinguishes "not set" from "set with defaults"
    }

    uint256 public constant MAX_WRAPPED_KEYS = 50;

    /// @dev Wrapped key format version byte.
    uint8 public constant WRAPPED_KEY_VERSION = 0x01;
    /// @dev Expected length of a v1 wrapped key: version(1) + ephemeralPub(33) + iv(12) + authTag(16) + encAESKey(32) = 94
    uint256 public constant WRAPPED_KEY_V1_LENGTH = 94;

    mapping(uint256 => PrivacyConfig) public privacyConfigs;
    mapping(uint256 => bytes32) public envelopeCommitments;
    mapping(address => bool) public trustedVerifiers;

    error PrivacyNotConfigured();
    error ConfigAlreadySet();
    error CidMismatch();
    error InsufficientWrappedKeys();
    error TooManyWrappedKeys();
    error InvalidWrappedKeyLength();
    error InvalidWrappedKeyVersion();
    error ZKVerificationFailed();
    error EnvelopeAlreadyCommitted();
    error InvalidVerifierAddress();
    error InvalidNumPublicInputs();
    error ExtraInputsLengthMismatch();
    error InvalidMinWrappedKeys();
    error InvalidOptParamsLength();
    error Unauthorized();

    event PrivacyConfigSet(uint256 indexed jobId, address zkVerifier, uint8 minWrappedKeys, uint8 numPublicInputs);
    event EncryptedSubmission(uint256 indexed jobId, bytes32 indexed cid, bytes32 envelopeHash, uint256 wrappedKeyCount);
    event TrustedVerifierUpdated(address verifier, bool trusted);

    constructor(address erc8183Contract_, address owner_)
        BaseERC8183Hook(erc8183Contract_)
        Ownable(owner_)
    {}

    function setTrustedVerifier(address verifier, bool trusted) external onlyOwner {
        if (verifier == address(0)) revert InvalidVerifierAddress();
        trustedVerifiers[verifier] = trusted;
        emit TrustedVerifierUpdated(verifier, trusted);
    }

    // --- Hook callbacks (called by ERC8183 via beforeAction/afterAction) ---

    /// @dev Store privacy config from setBudget optParams. Config is immutable once set.
    ///      64-byte optParams → (address, uint8) with numPublicInputs=2.
    ///      96-byte optParams → (address, uint8, uint8) with explicit numPublicInputs.
    ///
    ///      Gating is by the `config.configured` sentinel, not by optParams length:
    ///      - First call (configured = false) must include optParams or reverts
    ///        PrivacyNotConfigured (fail loudly at config time, not at submit).
    ///      - Subsequent calls with empty optParams are no-ops, so core's allowed
    ///        multi-setBudget semantics (e.g. budget updates) still work.
    ///      - Subsequent calls with non-empty optParams revert ConfigAlreadySet.
    ///      - Only the job's client may write the initial privacy config; a
    ///        non-empty optParams call from the provider reverts Unauthorized.
    ///        Intentional: otherwise the provider could race the client and
    ///        pick a permissive zkVerifier before the client configures privacy.
    function _postSetBudget(
        uint256 jobId,
        address caller,
        address,
        uint256,
        bytes memory optParams
    ) internal override {
        PrivacyConfig storage config = privacyConfigs[jobId];

        if (optParams.length == 0) {
            if (!config.configured) revert PrivacyNotConfigured();
            return;
        }

        if (config.configured) revert ConfigAlreadySet();
        if (caller != ERC8183(erc8183Contract).getJob(jobId).client) revert Unauthorized();

        address zkVerifier;
        uint8 minWrappedKeys;
        uint8 numPubInputs;

        if (optParams.length == 96) {
            (zkVerifier, minWrappedKeys, numPubInputs) = abi.decode(optParams, (address, uint8, uint8));
        } else if (optParams.length == 64) {
            (zkVerifier, minWrappedKeys) = abi.decode(optParams, (address, uint8));
            numPubInputs = 2;
        } else {
            revert InvalidOptParamsLength();
        }

        if (minWrappedKeys < 1) revert InvalidMinWrappedKeys();
        if (numPubInputs < 2) revert InvalidNumPublicInputs();
        if (zkVerifier != address(0) && !trustedVerifiers[zkVerifier]) revert InvalidVerifierAddress();

        privacyConfigs[jobId] = PrivacyConfig({
            zkVerifier: zkVerifier,
            minWrappedKeys: minWrappedKeys,
            numPublicInputs: numPubInputs,
            configured: true
        });
        emit PrivacyConfigSet(jobId, zkVerifier, minWrappedKeys, numPubInputs);
    }

    /// @dev Validate encrypted envelope structure and optional ZK proof.
    function _preSubmit(
        uint256 jobId,
        address,
        bytes32 deliverable,
        bytes memory optParams
    ) internal override {
        PrivacyConfig memory config = privacyConfigs[jobId];
        if (!config.configured) revert PrivacyNotConfigured();
        if (envelopeCommitments[jobId] != bytes32(0)) revert EnvelopeAlreadyCommitted();

        bytes32 cid;
        bytes[] memory wrappedKeys;
        bytes memory zkProof;
        bytes32[] memory extraPublicInputs;

        if (config.numPublicInputs > 2) {
            // Extended format: (bytes32, bytes[], bytes, bytes32[])
            (cid, wrappedKeys, zkProof, extraPublicInputs) =
                abi.decode(optParams, (bytes32, bytes[], bytes, bytes32[]));
        } else {
            // Standard format: (bytes32, bytes[], bytes)
            (cid, wrappedKeys, zkProof) =
                abi.decode(optParams, (bytes32, bytes[], bytes));
        }

        // cid in envelope must match the deliverable (32-byte content commitment)
        if (cid != deliverable) revert CidMismatch();

        // NOTE: This validates wrapped-key SHAPE only (length 94, version 0x01).
        // It does NOT prove the keys are wrapped to the client/evaluator pubkeys.
        // Recipient authorization must be enforced by the ZK circuit or off-chain.
        uint256 keyCount = wrappedKeys.length;
        if (keyCount < config.minWrappedKeys) revert InsufficientWrappedKeys();
        if (keyCount > MAX_WRAPPED_KEYS) revert TooManyWrappedKeys();
        for (uint256 i = 0; i < keyCount;) {
            bytes memory key = wrappedKeys[i];
            if (key.length != WRAPPED_KEY_V1_LENGTH) revert InvalidWrappedKeyLength();
            // Read version byte directly from memory (skip length word at offset 0, first data byte at offset 32)
            uint8 version;
            assembly {
                version := byte(0, mload(add(key, 32)))
            }
            if (version != WRAPPED_KEY_VERSION) revert InvalidWrappedKeyVersion();
            unchecked { ++i; }
        }

        // ZK proof verification (if verifier is configured)
        if (config.zkVerifier != address(0)) {
            if (extraPublicInputs.length != uint256(config.numPublicInputs) - 2) revert ExtraInputsLengthMismatch();
            bytes32[] memory publicInputs = new bytes32[](config.numPublicInputs);
            publicInputs[0] = bytes32(jobId);
            publicInputs[1] = cid;
            for (uint256 i = 0; i < extraPublicInputs.length;) {
                publicInputs[2 + i] = extraPublicInputs[i];
                unchecked { ++i; }
            }
            // Use staticcall to enforce the view declaration at runtime — a
            // malicious verifier cannot mutate state during the call.
            (bool ok, bytes memory ret) = config.zkVerifier.staticcall(
                abi.encodeCall(IZKVerifier.verify, (zkProof, publicInputs))
            );
            if (!ok || !abi.decode(ret, (bool))) revert ZKVerificationFailed();
        }

        // Store commitment hash (includes jobId to prevent cross-job analysis)
        envelopeCommitments[jobId] = keccak256(abi.encode(jobId, cid, wrappedKeys, zkProof));
    }

    /// @dev Emit event for off-chain discoverability. Decoding branches on
    ///      `numPublicInputs` so the actual encoded shape is read, rather than
    ///      relying on abi.decode's tolerance of trailing fields.
    function _postSubmit(
        uint256 jobId,
        address,
        bytes32,
        bytes memory optParams
    ) internal override {
        PrivacyConfig memory config = privacyConfigs[jobId];
        bytes32 cid;
        bytes[] memory wrappedKeys;

        if (config.numPublicInputs > 2) {
            // Extended format: (bytes32, bytes[], bytes, bytes32[])
            (cid, wrappedKeys, , ) = abi.decode(optParams, (bytes32, bytes[], bytes, bytes32[]));
        } else {
            // Standard format: (bytes32, bytes[], bytes)
            (cid, wrappedKeys, ) = abi.decode(optParams, (bytes32, bytes[], bytes));
        }

        emit EncryptedSubmission(jobId, cid, envelopeCommitments[jobId], wrappedKeys.length);
    }

    // --- View functions ---

    function getPrivacyConfig(uint256 jobId) external view returns (
        address zkVerifier, uint8 minWrappedKeys, uint8 numPublicInputs, bool configured
    ) {
        PrivacyConfig memory config = privacyConfigs[jobId];
        return (config.zkVerifier, config.minWrappedKeys, config.numPublicInputs, config.configured);
    }

    function getEnvelopeCommitment(uint256 jobId) external view returns (bytes32) {
        return envelopeCommitments[jobId];
    }

    // --- IERC8183HookMetadata ------------------------------------------------

    function requiredSelectors() external pure returns (bytes4[] memory) {
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
        sels[1] = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
        return sels;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
