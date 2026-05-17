// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";

/// @title IReasoningVerifier
/// @notice Minimal interface for on-chain reasoning verification.
/// @dev Implementations MUST bind verification to (jobId, caller, deliverable) to prevent
///      cross-job replay attacks. Once consumed, a verification record SHOULD NOT be reusable.
///      The `caller` parameter is the address that invoked `submit()` on AgenticCommerce —
///      this may be the worker themselves or an operator acting on their behalf.
interface IReasoningVerifier {
    /// @notice Check whether reasoning for a deliverable has been verified.
    /// @param jobId       The ERC-8183 job identifier.
    /// @param caller      The address that called submit() (worker or operator).
    /// @param deliverable Canonical keccak256 hash identifying the claim or deliverable.
    /// @return verified   True if a verification result has been stored for this tuple.
    /// @return confidence Confidence score scaled by 1000 (e.g. 850 = 0.850). Capped at 1000.
    function verifyReasoning(uint256 jobId, address caller, bytes32 deliverable)
        external
        returns (bool verified, uint256 confidence);
}

/// @title ReasoningVerifierHook
/// @notice Minimal ERC-8183 hook that gates `submit` on an external reasoning verifier.
///
/// @dev **Use case:** Prevents unverified AI/computational reasoning outputs from being
///      submitted as deliverables in an ERC-8183 job marketplace. The hook acts as a
///      pre-submission quality gate — only deliverables that pass external reasoning
///      verification (with sufficient confidence) are accepted.
///
/// @dev **Flow (happy path):**
///      1. Worker completes reasoning task off-chain, producing a deliverable hash.
///      2. Worker (or an off-chain oracle) calls the verifier contract to store the
///         verification result for (jobId, caller, deliverable).
///      3. Worker/operator calls `submit(jobId, deliverable, ...)` on AgenticCommerce.
///      4. AgenticCommerce encodes `abi.encode(caller, deliverable, optParams)` and
///         dispatches to the router, which invokes this hook's `_preSubmit`.
///      5. The hook queries the verifier with the full (jobId, caller, deliverable) tuple.
///      6. If verified and confidence >= minConfidence, the submission proceeds.
///      7. The hook marks (jobId, caller) as consumed to prevent replay.
///
/// @dev **Trust model:** The hook trusts the external verifier contract set at deployment.
///      The deployer (typically the job requester or protocol) chooses which verifier to use.
///      This hook does NOT defend against a malicious verifier — it assumes the verifier
///      is operated by a trusted party. If the verifier is compromised, submissions may
///      be approved or blocked incorrectly. The hook also does NOT validate that the
///      deliverable content matches the hash — only that the hash has been verified.
///
/// @dev **Caller semantics:** The `caller` parameter comes from AgenticCommerce's
///      `abi.encode(caller, deliverable, optParams)` encoding. In ERC-8183, `caller` is
///      `msg.sender` of the `submit()` call — which may be the worker or an authorized
///      operator. The hook binds consumption to (jobId, caller) to prevent cross-caller
///      replay while allowing the same job to accept submissions from different callers
///      if the verifier has approved each one independently.
///
/// @custom:audit status=unaudited
contract ReasoningVerifierHook is BaseERC8183Hook, IERC8183HookMetadata {
    IReasoningVerifier public immutable verifier;
    uint256 public immutable minConfidence;

    /// @notice Maximum confidence value. Verifier results above this are capped.
    uint256 public constant MAX_CONFIDENCE = 1000;

    /// @notice Tracks which (jobId, caller) pairs have already been submitted.
    /// @dev Prevents the same caller from replaying a verification on the same job.
    ///      Different callers may still submit for the same job if independently verified.
    mapping(uint256 => mapping(address => bool)) private _consumed;

    error InvalidParameters();
    error NotVerified(uint256 jobId, address caller, bytes32 canonicalHash);
    error ConfidenceTooLow(bytes32 canonicalHash, uint256 actual, uint256 required);
    error AlreadyConsumed(uint256 jobId, address caller);

    /// @notice Emitted when a deliverable passes reasoning verification.
    /// @param jobId       The ERC-8183 job identifier.
    /// @param caller      The address that called submit() (worker or operator).
    /// @param deliverable The canonical hash of the deliverable.
    /// @param confidence  The confidence score returned by the verifier (capped at 1000).
    event ReasoningVerified(
        uint256 indexed jobId,
        address indexed caller,
        bytes32 deliverable,
        uint256 confidence
    );

    constructor(
        address erc8183Contract_,
        IReasoningVerifier verifier_,
        uint256 minConfidence_
    ) BaseERC8183Hook(erc8183Contract_) {
        if (erc8183Contract_ == address(0) || address(verifier_) == address(0)) revert InvalidParameters();
        if (minConfidence_ < 100 || minConfidence_ > MAX_CONFIDENCE) revert InvalidParameters();
        verifier = verifier_;
        minConfidence = minConfidence_;
    }

    /// @notice Gates submit: checks reasoning verification and consumes the record.
    /// @dev Not a `view` — mutates `_consumed` mapping and calls non-view verifier.
    ///      Parameters match BaseERC8183Hook._preSubmit exactly:
    ///        jobId       = ERC-8183 job identifier
    ///        caller      = msg.sender of submit() on AgenticCommerce (worker or operator)
    ///        deliverable = canonical hash from submit(jobId, deliverable, optParams)
    ///        optParams   = optional parameters (unused by this hook)
    function _preSubmit(
        uint256 jobId,
        address caller,
        bytes32 deliverable,
        bytes memory /* optParams */
    ) internal override {
        // Prevent replay of the same (jobId, caller) pair
        if (_consumed[jobId][caller]) revert AlreadyConsumed(jobId, caller);

        // Query verifier with full context (jobId + caller + deliverable)
        (bool verified, uint256 confidence) = verifier.verifyReasoning(jobId, caller, deliverable);

        if (!verified) revert NotVerified(jobId, caller, deliverable);

        // Cap confidence to prevent overflow/abuse from malicious verifiers
        if (confidence > MAX_CONFIDENCE) {
            confidence = MAX_CONFIDENCE;
        }

        if (confidence < minConfidence) {
            revert ConfidenceTooLow(deliverable, confidence, minConfidence);
        }

        // Mark as consumed — single-use per (jobId, caller)
        _consumed[jobId][caller] = true;

        // Emit audit trail event
        emit ReasoningVerified(jobId, caller, deliverable, confidence);
    }

    /// @notice Returns the selectors this hook gates.
    /// @dev Must return the submit selector so the router actually dispatches to this hook.
    function requiredSelectors() external pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
