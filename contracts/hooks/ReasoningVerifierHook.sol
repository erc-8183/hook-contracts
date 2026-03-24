// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IReasoningVerifier.sol";

/// @title ReasoningVerifierHook
/// @notice ERC-8183 hook that gates on-chain actions on a reasoning verification check.
///
///         Implements the IACPHook pattern from ERC-8183:
///         - beforeAction(): reverts to block the action if reasoning is not verified
///           or confidence is below the configured minimum.
///         - afterAction(): informational only; cannot block a completed action.
///
///         This contract is protocol-agnostic: it accepts any IReasoningVerifier in
///         the constructor. Deploy with ThoughtProofReasoningVerifier for
///         ThoughtProof-backed gating, or substitute any compliant verifier.
///
/// @dev Formerly ThoughtProofReasoningHook. Renamed to make the standard-facing
///      abstraction generic. ThoughtProof is the reference implementation, not
///      a required dependency.
///
/// @custom:version 1.0.0
contract ReasoningVerifierHook {

    // ============ State ============

    /// @notice The reasoning verifier this hook delegates to.
    ///         Immutable — deploy a new hook to change the verifier.
    IReasoningVerifier public immutable verifier;

    /// @notice Minimum confidence required to allow an action, scaled by 1000.
    ///         E.g. 700 = 0.700 (70% confidence).
    uint256 public minConfidence;

    address public owner;

    // ============ Events ============

    event ActionAllowed(bytes32 indexed claimHash, uint256 confidence);
    event ActionBlocked(bytes32 indexed claimHash, uint256 confidence, uint256 required);
    event MinConfidenceUpdated(uint256 oldValue, uint256 newValue);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ============ Errors ============

    error Unauthorized();
    error InvalidParameters();
    error NotVerified(bytes32 claimHash);
    error ConfidenceTooLow(bytes32 claimHash, uint256 actual, uint256 required);

    // ============ Constructor ============

    /// @param _verifier      Any IReasoningVerifier implementation.
    ///                       Example: ThoughtProofReasoningVerifier.
    /// @param _minConfidence Minimum confidence * 1000 required to pass (100–1000).
    ///                       E.g. 700 = 0.700 minimum.
    constructor(IReasoningVerifier _verifier, uint256 _minConfidence) {
        if (address(_verifier) == address(0)) revert InvalidParameters();
        if (_minConfidence < 100 || _minConfidence > 1000) revert InvalidParameters();
        verifier = _verifier;
        minConfidence = _minConfidence;
        owner = msg.sender;
    }

    // ============ Hook ============

    /// @notice Called before an ERC-8183 action executes.
    ///         Reverts to block if reasoning is not verified or confidence is too low.
    /// @param claimHash  keccak256 identifying the claim/action to gate.
    ///                   Must match the hash submitted to the verifier by the off-chain service.
    function beforeAction(bytes32 claimHash) external view {
        (bool verified, uint256 confidence) = verifier.verifyReasoning(claimHash);

        if (!verified) revert NotVerified(claimHash);
        if (confidence < minConfidence) revert ConfidenceTooLow(claimHash, confidence, minConfidence);
    }

    /// @notice Called after an ERC-8183 action completes successfully.
    ///         Informational only — cannot revert to undo a completed action.
    /// @param claimHash  keccak256 identifying the completed claim/action.
    function afterAction(bytes32 claimHash) external {
        (bool verified, uint256 confidence) = verifier.verifyReasoning(claimHash);
        if (verified && confidence >= minConfidence) {
            emit ActionAllowed(claimHash, confidence);
        } else {
            // Defensive: action completed but verification state is unexpected.
            // Log for off-chain indexing; cannot revert.
            emit ActionBlocked(claimHash, confidence, minConfidence);
        }
    }

    // ============ Admin ============

    /// @notice Update the minimum confidence threshold.
    function setMinConfidence(uint256 _minConfidence) external {
        if (msg.sender != owner) revert Unauthorized();
        if (_minConfidence < 100 || _minConfidence > 1000) revert InvalidParameters();
        emit MinConfidenceUpdated(minConfidence, _minConfidence);
        minConfidence = _minConfidence;
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert Unauthorized();
        if (newOwner == address(0)) revert InvalidParameters();
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
    }
}
