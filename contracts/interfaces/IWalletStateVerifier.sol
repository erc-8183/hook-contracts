// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IWalletStateVerifier
/// @notice Minimal interface for on-chain wallet-state verification.
/// @dev Returns a (verified, validUntil) pair for a given (wallet, conditionsHash)
///      so hooks can remain stateless views.
/// @custom:audit status=unaudited
interface IWalletStateVerifier {
    /// @notice Check whether a wallet has a verified attestation matching the condition set.
    /// @param wallet The wallet address being checked (e.g. job.client at _preFund time).
    /// @param conditionsHash Hash identifying the required condition set.
    /// @return verified True if an attestation record exists for (wallet, conditionsHash).
    /// @return validUntil Unix timestamp when the attestation expires (0 if not verified).
    function checkWalletState(address wallet, bytes32 conditionsHash)
        external
        view
        returns (bool verified, uint256 validUntil);
}
