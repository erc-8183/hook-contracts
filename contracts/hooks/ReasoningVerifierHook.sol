// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";

/// @title IReasoningVerifier
/// @notice Minimal interface for on-chain reasoning verification.
/// @dev Implementations should be deterministic for a given canonical hash once a
///      record is stored, so hooks can remain stateless views.
interface IReasoningVerifier {
    /// @notice Check whether reasoning for a canonical hash has been verified.
    /// @param canonicalHash Canonical keccak256 hash identifying the claim or deliverable.
    /// @return verified True if a verification result has been stored for this hash.
    /// @return confidence Confidence score scaled by 1000 (e.g. 850 = 0.850).
    function verifyReasoning(bytes32 canonicalHash)
        external
        view
        returns (bool verified, uint256 confidence);
}

/// @title ReasoningVerifierHook
/// @notice Minimal ERC-8183 hook that gates submit on an external reasoning verifier.
/// @dev Uses the submit deliverable as the canonical hash to avoid extra hook-specific encoding.
/// @custom:audit status=unaudited
contract ReasoningVerifierHook is BaseERC8183Hook, IERC8183HookMetadata {
    IReasoningVerifier public immutable verifier;
    uint256 public immutable minConfidence;

    error InvalidParameters();
    error NotVerified(bytes32 canonicalHash);
    error ConfidenceTooLow(bytes32 canonicalHash, uint256 actual, uint256 required);

    constructor(
        address erc8183Contract_,
        IReasoningVerifier verifier_,
        uint256 minConfidence_
    ) BaseERC8183Hook(erc8183Contract_) {
        if (erc8183Contract_ == address(0) || address(verifier_) == address(0)) revert InvalidParameters();
        if (minConfidence_ < 100 || minConfidence_ > 1000) revert InvalidParameters();
        verifier = verifier_;
        minConfidence = minConfidence_;
    }

    function _preSubmit(uint256, address, bytes32 deliverable, bytes memory) internal view override {
        (bool verified, uint256 confidence) = verifier.verifyReasoning(deliverable);

        if (!verified) revert NotVerified(deliverable);
        if (confidence < minConfidence) {
            revert ConfidenceTooLow(deliverable, confidence, minConfidence);
        }
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
