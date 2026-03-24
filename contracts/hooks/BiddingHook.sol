// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../BaseACPHook.sol";

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
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider=0, evaluator, expiredAt, description, hook=this)
 *  2. setBudget(jobId, maxBudget, optParams=abi.encode(biddingDeadline))
 *     → _preSetBudget: store deadline for this jobId.
 *  3. Bidding happens OFF-CHAIN:
 *     Providers sign: keccak256(abi.encode(chainId, hookAddress, jobId, bidAmount))
 *     Client collects signed bids and selects the winner.
 *  4. setProvider(jobId, winnerAddress, optParams=abi.encode(bidAmount, signature))
 *     → _preSetProvider: verify deadline passed, recover signer from signature,
 *       validate signer == provider, store committed bidAmount.
 *     → core: job.provider = winnerAddress
 *     → _postSetProvider: mark bidding finalised.
 *     Then: setBudget(jobId, bidAmount, "")
 *     → _preSetBudget: enforce budget == committedAmount.
 *  5. fund(jobId, "") — _preFund enforces budget == committedAmount (blocks
 *     funding if client skipped the second setBudget).
 *  6. Job continues normally: submit → complete.
 *
 * TRUST MODEL
 * -----------
 * The client is incentivised to pick the lowest bidder (they pay). The hook
 * verifies the chosen provider actually signed a commitment — preventing
 * the client from fabricating a provider commitment.
 *
 * KEY PROPERTY: Zero direct external calls to the hook. Everything flows
 * through core contract → hook callbacks.
 */
contract BiddingHook is BaseACPHook {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct Bidding {
        uint256 deadline;
        uint256 committedAmount; // winning bid amount, set at setProvider
        bool finalized;
    }

    mapping(uint256 => Bidding) public biddings;

    error DeadlineMustBeFuture();
    error BiddingStillOpen();
    error BiddingAlreadyFinalized();
    error InvalidBidSignature();
    error NoBidDeadline();
    error BudgetMismatch();

    constructor(address acpContract_) BaseACPHook(acpContract_) {}

    // --- Hook callbacks only (no direct external functions) ---

    /// @dev Two modes:
    ///  1. Initial call (before provider): decode deadline from optParams, store it.
    ///  2. Post-provider call (committedAmount set): enforce budget == committedAmount.
    function _preSetBudget(uint256 jobId, uint256 amount, bytes memory optParams) internal override {
        Bidding storage b = biddings[jobId];

        // After provider selected: enforce budget matches the winning bid
        if (b.committedAmount > 0) {
            if (amount != b.committedAmount) revert BudgetMismatch();
            return;
        }

        // Initial call: store bidding deadline from optParams
        if (optParams.length == 0) return;
        uint256 deadline = abi.decode(optParams, (uint256));
        if (deadline <= block.timestamp) revert DeadlineMustBeFuture();
        b.deadline = deadline;
    }

    /// @dev Verify signed bid from provider. Client passes (bidAmount, signature) in optParams.
    function _preSetProvider(uint256 jobId, address provider_, bytes memory optParams) internal override {
        Bidding storage b = biddings[jobId];
        if (b.deadline == 0) revert NoBidDeadline();
        if (block.timestamp < b.deadline) revert BiddingStillOpen();
        if (b.finalized) revert BiddingAlreadyFinalized();

        (uint256 bidAmount, bytes memory signature) = abi.decode(optParams, (uint256, bytes));

        // Verify the provider signed this bid
        bytes32 messageHash = keccak256(abi.encode(block.chainid, address(this), jobId, bidAmount));
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address signer = ECDSA.recover(ethSignedHash, signature);
        if (signer != provider_) revert InvalidBidSignature();

        b.committedAmount = bidAmount;
    }

    /// @dev Block funding if budget hasn't been set to the committed bid amount.
    function _preFund(uint256 jobId, uint256 expectedBudget, bytes memory) internal override {
        (expectedBudget); // silence unused variable warning
        Bidding storage b = biddings[jobId];
        if (b.committedAmount == 0) return; // no bidding for this job
        uint256 budget = _getJobBudget(jobId);
        if (budget != b.committedAmount) revert BudgetMismatch();
    }

    function _postSetProvider(uint256 jobId, address, bytes memory) internal override {
        biddings[jobId].finalized = true;
    }

    // --- Helper --------------------------------------------------------------

    function _getJobBudget(uint256 jobId) internal view returns (uint256 budget) {
        (bool ok, bytes memory data) = acpContract.staticcall(abi.encodeWithSignature("getJob(uint256)", jobId));
        require(ok, "getJob failed");
        // Job struct: (id, client, provider, evaluator, hook, description, budget, expiredAt, status)
        (,,,,,, budget,,) =
            abi.decode(data, (uint256, address, address, address, address, string, uint256, uint256, uint8));
    }
}
