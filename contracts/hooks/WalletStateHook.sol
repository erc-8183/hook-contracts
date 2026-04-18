// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "../interfaces/IWalletStateVerifier.sol";

/// @title WalletStateHook
/// @notice Minimal ERC-8183 hook that gates fund on a condition-based wallet-state verifier.
/// @dev Inherits BaseERC8183Hook and overrides _preFund to check the funding caller
///      against an immutable condition set before the job escrow can form.
///      Deploy one hook per distinct condition set (parallels how ReasoningVerifierHook
///      binds an immutable minConfidence).
/// @custom:audit status=unaudited
contract WalletStateHook is BaseERC8183Hook, IERC8183HookMetadata {
    IWalletStateVerifier public immutable verifier;

    /// @notice Hash identifying the required condition set.
    bytes32 public immutable conditionsHash;

    error InvalidParameters();
    error WalletNotVerified(address wallet, bytes32 conditionsHash);
    error AttestationExpired(address wallet, uint256 validUntil);

    constructor(
        address erc8183Contract_,
        IWalletStateVerifier verifier_,
        bytes32 conditionsHash_
    ) BaseERC8183Hook(erc8183Contract_) {
        if (erc8183Contract_ == address(0) || address(verifier_) == address(0)) {
            revert InvalidParameters();
        }
        if (conditionsHash_ == bytes32(0)) revert InvalidParameters();
        verifier = verifier_;
        conditionsHash = conditionsHash_;
    }

    function _preFund(uint256, address caller, bytes memory) internal view override {
        (bool verified, uint256 validUntil) = verifier.checkWalletState(caller, conditionsHash);
        if (!verified) revert WalletNotVerified(caller, conditionsHash);
        if (block.timestamp > validUntil) revert AttestationExpired(caller, validUntil);
    }

    function requiredSelectors() external pure returns (bytes4[] memory) {
        return new bytes4[](0);
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
