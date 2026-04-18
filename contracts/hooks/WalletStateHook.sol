// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "../interfaces/IWalletStateVerifier.sol";

/// @title WalletStateHook
/// @notice ERC-8183 hook that gates fund on a condition-based wallet-state verifier.
///
/// USE CASE
/// --------
/// Pre-escrow gating: verify the funding wallet satisfies a named condition set
/// (e.g. "USDC >= 1000 on Base", "KYC attested", "governance NFT held") before the
/// job budget can be escrowed. Complements score-based gating (reputation >= N,
/// e.g. TrustGateHook) and content-based gating (deliverable verification,
/// e.g. ReasoningVerifierHook) with a third shape: deterministic condition checks
/// over wallet state.
///
/// FLOW
/// ----
/// 1. Off-chain: the funder obtains a signed attestation for (wallet, condition set)
///    from an IWalletStateVerifier implementer (see `examples/InsumerWalletStateVerifier.sol`).
/// 2. A relayer submits the attestation on-chain so the verifier can answer
///    `checkWalletState(wallet, conditionsHash) → (verified, validUntil)`.
/// 3. Client calls `AgenticCommerce.fund(...)` — the core contract invokes
///    `beforeAction(jobId, fundSelector, data)` on this hook (callback step).
/// 4. `_preFund` reads the funder's address, calls the verifier, reverts unless
///    the wallet is verified and the attestation has not expired.
///
/// TRUST MODEL
/// -----------
/// - The hook trusts the injected `IWalletStateVerifier` to return honest
///   (verified, validUntil) pairs. Implementations can offer zero-trust
///   verification (e.g. on-chain P-256 signature check via RIP-7212) or an
///   operator-trusted relayer fallback — the hook is indifferent.
/// - `conditionsHash` is immutable per deployment. Deploy one hook per distinct
///   condition set; this keeps the hook stateless and removes per-job config
///   attack surface (parallels the immutable `minConfidence` pattern in
///   ReasoningVerifierHook).
/// - Job-lifecycle authorization is enforced by `BaseERC8183Hook.onlyERC8183`.
///
/// KEY PROPERTY: the hook performs no token custody. Profile A — Simple Policy.
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
