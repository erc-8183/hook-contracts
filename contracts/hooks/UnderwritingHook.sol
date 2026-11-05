// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseERC8183Hook} from "../BaseERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";
import {ERC8183} from "@erc8183/ERC8183.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @dev Underwriting terms committed at `setBudget(...)`.
struct UnderwriteCommit {
    address underwriter;   // registered underwriter expected to sign the final decision
    uint64 validUntil;     // latest timestamp at which the commit may be created
    bytes32 policyHash;    // commitment to the underwriting policy
    bytes32 quoteIdHash;   // commitment to the quote identifier
    bytes32 termsHash;     // commitment to the underwriting terms
}

/// @dev Evidence submitted by the provider at `submit(...)`; must match the committed terms.
struct SubmitEvidence {
    bytes32 bundleHash;    // commitment to the evidence bundle (submitted as the core `deliverable`)
    bytes32 policyHash;    // must equal UnderwriteCommit.policyHash
    bytes32 quoteIdHash;   // must equal UnderwriteCommit.quoteIdHash
    bytes32 termsHash;     // must equal UnderwriteCommit.termsHash
}

/// @dev Underwriter authorization carried in the `complete(...)` / `reject(...)` optParams.
struct FinalizationAuthority {
    uint64 deadline;       // signature expiry
    uint256 nonce;         // per-underwriter replay protection
    bytes signature;       // EIP-712 signature over the decision by the committed underwriter
}

/**
 * @title UnderwritingHook
 * @notice Experimental single-stage underwriting hook (Profile C).
 *
 * USE CASE
 * --------
 * For jobs that need more than evaluator attestation, this hook lets the
 * client and provider pre-commit underwriting terms at `setBudget(...)`, then
 * requires the provider's submission evidence to match those committed terms
 * before a registered underwriter's signature can finalize the job through
 * `complete(...)` or `reject(...)`.
 *
 * FLOW (all state transitions via the ERC-8183 core → hook callbacks)
 * ----
 *  1. Admin registers the job evaluator and one or more allowed underwriter
 *     signers.
 *  2. createJob(provider, evaluator, ...) with this hook attached (directly
 *     or behind MultiHookRouter).
 *  3. Client or provider calls `setBudget(jobId, token, amount,
 *     optParams = abi.encode(UnderwriteCommit))`
 *     → _preSetBudget: commit-locks {commit, paymentToken, budget}; identical
 *       re-submission is idempotent, any deviation reverts.
 *  4. fund(jobId, budget, "") → _postFund: job becomes `Protected`.
 *  5. Provider calls `submit(jobId, evidence.bundleHash,
 *     optParams = abi.encode(SubmitEvidence))`
 *     → _postSubmit: bundleHash must equal the submitted deliverable and
 *       policy/quote/terms hashes must match the locked commit; job becomes
 *       `EvidenceSubmitted`.
 *  6. The underwriter signs a `CompleteDecision(jobId, reason, deadline,
 *     nonce)` or `RejectDecision(...)` EIP-712 message.
 *  7. Any relayer (typically the evaluator) calls
 *     `complete(jobId, reason, optParams = abi.encode(FinalizationAuthority))`
 *     or the reject equivalent
 *     → _preComplete/_preReject: verifies the underwriter signature, deadline,
 *       and nonce, then consumes the nonce. The core settles between the pre
 *       and post callbacks.
 *
 * MultiHookRouter compatibility
 * -----------------------------
 * - Inherits BaseERC8183Hook, so calls from the router (registered as the
 *   job hook) are accepted via onlyERC8183.
 * - requiredSelectors() declares the full setBudget → fund → submit →
 *   complete/reject dependency chain: the commit stored at setBudget is
 *   consumed by every later selector.
 * - When configured behind a router together with other hooks, callers must
 *   address this hook's optParams via the router's per-hook bytes[] slot
 *   (see docs/multi-hook-router.md); this hook's optParams are always
 *   non-empty ABI-encoded structs and are NOT broadcast-tolerant.
 *
 * TRUST MODEL
 * -----------
 * The ERC-8183 core keeps custody and settlement. This hook only adds
 * underwriting policy: which evaluator and underwriters are allowed, which
 * evidence hashes must match at submit, and that final completion or
 * rejection of a protected job requires a registered underwriter signature
 * after evidence submission.
 *
 * The hook does NOT:
 * - Verify that the committed policy/quote/terms hashes correspond to any
 *   real-world underwriting agreement (they are opaque commitments).
 * - Enforce off-chain underwriting workflow steps; it sees only the five
 *   core lifecycle callbacks.
 * - Protect against a compromised underwriter key beyond nonce + deadline
 *   replay protection.
 */
contract UnderwritingHook is BaseERC8183Hook, IERC8183HookMetadata, EIP712 {
    enum SidecarState {
        None,
        Committed,                 // setBudget locked the underwriting commit
        Protected,                 // fund completed
        EvidenceSubmitted,         // submit evidence matched the commit
        SuccessPendingConfirmation,// complete settled
        RejectSettled              // reject settled
    }

    // ──────────────────── Errors ────────────────────

    error OnlyAdmin();
    error ZeroAddress();
    error EvaluatorAlreadySet();
    error EvaluatorNotSet();
    error UnderwriterNotRegistered();
    error ProviderRequired();
    error EvaluatorMismatch();
    error CommitExpired(uint64 validUntil, uint64 currentTimestamp);
    error CommitLocked();
    error CommitNotFound();
    error CommitRequired();
    error EvidenceRequired();
    error SignatureRequired();
    error EvidenceMismatch();
    error InvalidState();
    error DecisionExpired(uint64 deadline, uint64 currentTimestamp);
    error NonceUsed(address underwriter, uint256 nonce);
    error InvalidSigner(address expected, address actual);

    // ──────────────────── EIP-712 decision typehashes ────────────────────

    bytes32 private constant COMPLETE_TYPEHASH =
        keccak256("CompleteDecision(uint256 jobId,bytes32 reason,uint64 deadline,uint256 nonce)");
    bytes32 private constant REJECT_TYPEHASH =
        keccak256("RejectDecision(uint256 jobId,bytes32 reason,uint64 deadline,uint256 nonce)");

    // ──────────────────── Storage ────────────────────

    /// @notice Admin that may register evaluators and underwriters.
    address public immutable admin;

    /// @notice The single evaluator allowed for jobs using this hook.
    address public evaluator;

    mapping(address => bool) public registeredUnderwriters;

    mapping(uint256 => UnderwriteCommit) internal commits;
    mapping(uint256 => bytes32) internal commitHashByJobId;
    mapping(uint256 => address) internal committedPaymentTokenByJobId;
    mapping(uint256 => uint256) internal committedBudgetByJobId;
    mapping(uint256 => SidecarState) internal sidecarStateByJobId;

    /// @notice Per-underwriter EIP-712 nonce replay protection.
    mapping(address underwriter => mapping(uint256 nonce => bool used)) public usedNonces;

    // ──────────────────── Constructor & admin ────────────────────

    /// @param erc8183Contract_ The ERC-8183 core (standalone) or MultiHookRouter address.
    /// @param admin_ Account allowed to set the evaluator and manage underwriters.
    constructor(address erc8183Contract_, address admin_)
        BaseERC8183Hook(erc8183Contract_)
        EIP712("UnderwritingHook", "1")
    {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
    }

    function setEvaluator(address evaluator_) external {
        if (msg.sender != admin) revert OnlyAdmin();
        if (evaluator_ == address(0)) revert ZeroAddress();
        if (evaluator != address(0)) revert EvaluatorAlreadySet();
        evaluator = evaluator_;
    }

    function registerUnderwriter(address underwriter) external {
        if (msg.sender != admin) revert OnlyAdmin();
        if (underwriter == address(0)) revert ZeroAddress();
        registeredUnderwriters[underwriter] = true;
    }

    function unregisterUnderwriter(address underwriter) external {
        if (msg.sender != admin) revert OnlyAdmin();
        if (underwriter == address(0)) revert ZeroAddress();
        delete registeredUnderwriters[underwriter];
    }

    // ──────────────────── Core view helper ────────────────────

    function _core() internal view returns (ERC8183) {
        return ERC8183(erc8183Contract);
    }

    // ──────────────────── Views ────────────────────

    function getCommit(uint256 jobId) external view returns (UnderwriteCommit memory) {
        return commits[jobId];
    }

    function jobUnderwriter(uint256 jobId) external view returns (address) {
        return _requireCommit(jobId).underwriter;
    }

    function jobSidecarState(uint256 jobId) external view returns (SidecarState) {
        return sidecarStateByJobId[jobId];
    }

    // ──────────────────── IERC8183HookMetadata ────────────────────

    /// @notice The commit stored at setBudget is consumed by every later
    ///         lifecycle selector, so router jobs must co-configure all five.
    function requiredSelectors() external pure returns (bytes4[] memory) {
        bytes4[] memory sels = new bytes4[](5);
        sels[0] = bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
        sels[1] = bytes4(keccak256("fund(uint256,uint256,bytes)"));
        sels[2] = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
        sels[3] = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
        sels[4] = bytes4(keccak256("reject(uint256,bytes32,bytes)"));
        return sels;
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ──────────────────── Hook callbacks ────────────────────

    /// @notice Commit-locks the underwriting terms together with the budget.
    ///         Re-submitting the exact same {commit, token, amount} is
    ///         idempotent; anything else reverts (CommitLocked).
    function _preSetBudget(
        uint256 jobId,
        address,
        address token,
        uint256 amount,
        bytes memory optParams
    ) internal override {
        if (evaluator == address(0)) revert EvaluatorNotSet();
        if (optParams.length == 0) revert CommitRequired();

        ERC8183.Job memory job = _core().getJob(jobId);
        UnderwriteCommit memory commit = abi.decode(optParams, (UnderwriteCommit));
        bytes32 newCommitHash = keccak256(abi.encode(commit));

        if (job.provider == address(0)) revert ProviderRequired();
        if (job.evaluator != evaluator) revert EvaluatorMismatch();

        if (commitHashByJobId[jobId] != bytes32(0)) {
            // Immutable once locked: only the identical triple may replay.
            if (commitHashByJobId[jobId] != newCommitHash) revert CommitLocked();
            if (committedPaymentTokenByJobId[jobId] != token) revert CommitLocked();
            if (committedBudgetByJobId[jobId] != amount) revert CommitLocked();
            return;
        }

        if (commit.validUntil <= block.timestamp) revert CommitExpired(commit.validUntil, uint64(block.timestamp));
        if (!registeredUnderwriters[commit.underwriter]) revert UnderwriterNotRegistered();

        commitHashByJobId[jobId] = newCommitHash;
        committedPaymentTokenByJobId[jobId] = token;
        committedBudgetByJobId[jobId] = amount;
        commits[jobId] = commit;
        sidecarStateByJobId[jobId] = SidecarState.Committed;
    }

    function _preFund(uint256 jobId, address, bytes memory) internal view override {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != SidecarState.Committed) revert InvalidState();
    }

    function _postFund(uint256 jobId, address, bytes memory) internal override {
        if (sidecarStateByJobId[jobId] != SidecarState.Committed) revert InvalidState();
        sidecarStateByJobId[jobId] = SidecarState.Protected;
    }

    function _preSubmit(uint256 jobId, address, bytes32, bytes memory) internal view override {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != SidecarState.Protected) revert InvalidState();
    }

    /// @notice Checks the submitted evidence against the locked commit.
    function _postSubmit(
        uint256 jobId,
        address,
        bytes32 deliverable,
        bytes memory optParams
    ) internal override {
        if (sidecarStateByJobId[jobId] != SidecarState.Protected) revert InvalidState();
        if (optParams.length == 0) revert EvidenceRequired();

        SubmitEvidence memory evidence = abi.decode(optParams, (SubmitEvidence));
        UnderwriteCommit memory commit = _requireCommit(jobId);

        if (deliverable != evidence.bundleHash) revert EvidenceMismatch();
        if (evidence.policyHash != commit.policyHash) revert EvidenceMismatch();
        if (evidence.quoteIdHash != commit.quoteIdHash) revert EvidenceMismatch();
        if (evidence.termsHash != commit.termsHash) revert EvidenceMismatch();

        sidecarStateByJobId[jobId] = SidecarState.EvidenceSubmitted;
    }

    /// @notice Requires a valid underwriter signature before the core pays out.
    function _preComplete(
        uint256 jobId,
        address,
        bytes32 reason,
        bytes memory optParams
    ) internal override {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != SidecarState.EvidenceSubmitted) revert InvalidState();
        if (optParams.length == 0) revert SignatureRequired();

        UnderwriteCommit memory commit = commits[jobId];
        FinalizationAuthority memory authority = abi.decode(optParams, (FinalizationAuthority));

        _consumeNonceAndVerifySigner(
            commit.underwriter,
            authority,
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        COMPLETE_TYPEHASH, jobId, reason, authority.deadline, authority.nonce
                    )
                )
            )
        );
    }

    /// @notice Open-state rejects (unfunded cancellation) bypass underwriting.
    ///         Every other reject requires a valid underwriter signature.
    function _preReject(
        uint256 jobId,
        address,
        bytes32 reason,
        bytes memory optParams
    ) internal override {
        ERC8183.Job memory job = _core().getJob(jobId);
        if (job.status == ERC8183.JobStatus.Open) return;

        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != SidecarState.EvidenceSubmitted) revert InvalidState();
        if (optParams.length == 0) revert SignatureRequired();

        UnderwriteCommit memory commit = commits[jobId];
        FinalizationAuthority memory authority = abi.decode(optParams, (FinalizationAuthority));

        _consumeNonceAndVerifySigner(
            commit.underwriter,
            authority,
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        REJECT_TYPEHASH, jobId, reason, authority.deadline, authority.nonce
                    )
                )
            )
        );
    }

    function _postComplete(uint256 jobId, address, bytes32, bytes memory) internal override {
        _requireCommit(jobId);
        sidecarStateByJobId[jobId] = SidecarState.SuccessPendingConfirmation;
    }

    function _postReject(uint256 jobId, address, bytes32, bytes memory) internal override {
        if (commitHashByJobId[jobId] == bytes32(0)) return;
        sidecarStateByJobId[jobId] = SidecarState.RejectSettled;
    }

    // ──────────────────── Internal helpers ────────────────────

    function _requireCommit(uint256 jobId) internal view returns (UnderwriteCommit memory) {
        if (commitHashByJobId[jobId] == bytes32(0)) revert CommitNotFound();
        return commits[jobId];
    }

    /// @dev Verifies the underwriter's EIP-712 decision signature and burns
    ///      its nonce. Ordered: freshness → replay → signer → consume.
    function _consumeNonceAndVerifySigner(
        address expectedUnderwriter,
        FinalizationAuthority memory authority,
        bytes32 digest
    ) internal {
        if (block.timestamp > authority.deadline) {
            revert DecisionExpired(authority.deadline, uint64(block.timestamp));
        }
        if (usedNonces[expectedUnderwriter][authority.nonce]) {
            revert NonceUsed(expectedUnderwriter, authority.nonce);
        }

        address recovered = ECDSA.recover(digest, authority.signature);
        if (recovered != expectedUnderwriter || expectedUnderwriter == address(0)) {
            revert InvalidSigner(expectedUnderwriter, recovered);
        }

        usedNonces[expectedUnderwriter][authority.nonce] = true;
    }
}
