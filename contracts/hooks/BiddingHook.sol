// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../BaseACPHook.sol";
import "@acp/AgenticCommerce.sol";

/**
 * @title BiddingHook
 * @notice Example ACP hook that manages off-chain signed bidding for provider
 *         selection — with zero direct calls to the hook.
 *
 * USE CASE
 * --------
 * A client wants to hire the cheapest (or best) agent for a job but does not
 * know upfront who to assign. Providers bid off-chain by signing a message
 * committing to a (jobId, bidAmount) pair. The client collects bids, selects
 * the winner, and submits the winning bid's signature via `setProvider`. The
 * hook verifies the signature on-chain — proving the provider actually
 * committed to that price.
 *
 * FLOW (all interactions through core contract -> hook callbacks)
 * ----
 *  1. createJob(provider=0, evaluator, expiredAt, description, hook=this)
 *  2. setBudget(jobId, maxBudget, optParams=abi.encode(biddingDeadline))
 *     -> _preSetBudget (mode 1): store deadline for this jobId.
 *  3. Bidding happens OFF-CHAIN:
 *     Providers sign: keccak256(abi.encode(chainId, hookAddress, jobId, bidAmount))
 *     Client collects signed bids and selects the winner.
 *  4. setProvider(jobId, winnerAddress, agentId) — no hook, just sets provider.
 *  5. setBudget(jobId, bidAmount, optParams=abi.encode(signature))
 *     -> _preSetBudget (mode 2): verify deadline passed, recover signer from
 *        signature, validate signer == provider, store committed bidAmount,
 *        enforce budget == bidAmount.
 *  6. fund(jobId, ...) — _preFund enforces budget == committedAmount (blocks
 *     funding if client skipped step 5).
 *  7. Job continues normally: submit -> complete.
 *
 * TRUST MODEL
 * -----------
 * The client is incentivised to pick the lowest bidder (they pay). The hook
 * verifies the chosen provider actually signed a commitment — preventing
 * the client from fabricating a provider commitment.
 *
 * KEY PROPERTY: Zero direct external calls to the hook. Everything flows
 * through core contract -> hook callbacks.
 */
contract BiddingHook is BaseACPHook {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct Bidding {
        uint256 deadline;
        uint256 committedAmount; // winning bid amount, set during bid verification
    }

    mapping(uint256 => Bidding) public biddings;

    error DeadlineMustBeFuture();
    error BiddingStillOpen();
    error InvalidBidSignature();
    error NoBidDeadline();
    error BudgetMismatch();
    error ProviderNotSet();

    constructor(address acpContract_) BaseACPHook(acpContract_) {}

    // --- Hook callbacks only (no direct external functions) ---

    /// @dev Three modes based on bidding state:
    ///  1. deadline == 0: initial call, decode deadline from optParams.
    ///  2. deadline > 0 && committedAmount == 0: bid verification, decode
    ///     signature from optParams, verify against provider.
    ///  3. committedAmount > 0: enforce budget == committedAmount.
    function _preSetBudget(uint256 jobId, address, uint256 amount, bytes memory optParams) internal override {
        Bidding storage b = biddings[jobId];

        // Mode 3: enforce budget matches the winning bid
        if (b.committedAmount > 0) {
            if (amount != b.committedAmount) revert BudgetMismatch();
            return;
        }

        // Mode 1: store bidding deadline
        if (b.deadline == 0) {
            if (optParams.length == 0) return;
            uint256 deadline = abi.decode(optParams, (uint256));
            if (deadline <= block.timestamp) revert DeadlineMustBeFuture();
            b.deadline = deadline;
            return;
        }

        // Mode 2: verify signed bid and store committedAmount
        if (block.timestamp < b.deadline) revert BiddingStillOpen();

        address provider = _core().getJob(jobId).provider;
        if (provider == address(0)) revert ProviderNotSet();

        bytes memory signature = abi.decode(optParams, (bytes));

        bytes32 messageHash = keccak256(abi.encode(block.chainid, address(this), jobId, amount));
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address signer = ECDSA.recover(ethSignedHash, signature);
        if (signer != provider) revert InvalidBidSignature();

        b.committedAmount = amount;
    }

    /// @dev Block funding if budget hasn't been set to the committed bid amount.
    function _preFund(uint256 jobId, address, bytes memory) internal override {
        Bidding storage b = biddings[jobId];
        if (b.committedAmount == 0) return; // no bidding for this job
        if (_core().getJob(jobId).budget != b.committedAmount) revert BudgetMismatch();
    }

    // --- Helpers --------------------------------------------------------------

    /// @dev Typed accessor for the core contract
    function _core() internal view returns (AgenticCommerce) {
        return AgenticCommerce(acpContract);
    }
}
