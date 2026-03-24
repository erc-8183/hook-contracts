// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IReasoningVerifier
/// @notice Generic interface for on-chain reasoning verification.
///
///         Any protocol that needs to gate an on-chain action on verified AI reasoning
///         can depend on this interface instead of a ThoughtProof-specific contract.
///         Hook contracts (e.g. ReasoningVerifierHook) call this interface;
///         the backing implementation can be swapped independently.
///
/// @dev Implementations must be deterministic for a given claimHash:
///      the same claimHash always returns the same (verified, confidence) pair
///      once a record is stored. This allows hook contracts to be stateless views.
interface IReasoningVerifier {
    /// @notice Check whether the reasoning for a given claim has been verified.
    /// @param claimHash  keccak256 hash identifying the claim or action payload.
    ///                   Off-chain services derive this from the content they verify.
    /// @return verified  True if a verification result has been stored for this hash.
    /// @return confidence Confidence score scaled by 1000 (e.g. 850 = 0.850).
    ///                   Meaningful only when verified is true.
    function verifyReasoning(bytes32 claimHash)
        external
        view
        returns (bool verified, uint256 confidence);
}
