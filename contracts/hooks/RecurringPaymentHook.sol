// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseACPHook} from "../BaseACPHook.sol";

// ---------------------------------------------------------------------------
// Minimal ERC-8191 interface
// Replace with a proper import once cadence-protocol is published on npm.
// ---------------------------------------------------------------------------

enum SubscriptionStatus { Active, Paused, Cancelled, Expired, PastDue }

interface ISubscription {
    function getStatus(bytes32 subId) external view returns (SubscriptionStatus);
    function getSubscriber(bytes32 subId) external view returns (address);
    function getMerchant(bytes32 subId) external view returns (address);
}

// ---------------------------------------------------------------------------

/**
 * @title  RecurringPaymentHook
 * @notice Bridges ERC-8183 agentic jobs with ERC-8191 recurring payment subscriptions.
 *
 * USE CASE
 * --------
 * Agents that offer tiered, subscription-based services via ERC-8183 need a way to
 * (a) price jobs differently for recurring subscribers vs. one-off clients, and
 * (b) gate job funding on an active subscription so lapsed subscriptions cannot
 *     consume agent capacity.
 *
 * This hook connects a client's ERC-8191 subscription (managed externally by
 * cadence-protocol's SubscriptionManager) to the ACP job lifecycle, enabling
 * on-chain enforcement of subscription-gated pricing and access.
 *
 * FLOW
 * ----
 * Off-chain setup (once per subscription):
 *   1. Client calls SubscriptionManager.subscribe(provider, terms) → receives subId.
 *   2. Client calls registerSubscription(provider, subId) on this hook.
 *      Hook validates ownership and merchant match; stores (client → provider → subId).
 *
 * Job lifecycle (per job):
 *   3. _preSetBudget  — if client has an active subscription to the provider,
 *                       enforce subscriberMinBudget instead of nonSubscriberMinBudget.
 *                       Reverts with BudgetBelowMinimum if the proposed budget is too low.
 *   4. _preFund       — if a subscription is registered for (client, provider),
 *                       it MUST be Active. Reverts with SubscriptionLapsed otherwise.
 *   5. _postFund      — links jobId → subId in storage; emits JobLinkedToSubscription
 *                       for off-chain indexers and the ERC-8191 keeper.
 *   6. _postComplete  — emits JobCompletedForSubscriber; off-chain services can use
 *                       this to confirm renewal, update reputation, or signal the keeper.
 *   7. _postReject    — emits JobRejectedForSubscriber; triggers off-chain dunning /
 *                       retry logic without blocking the on-chain transaction.
 *
 * TRUST MODEL
 * -----------
 * - The hook trusts the ERC-8191 SubscriptionManager at `subscriptionManager` to
 *   correctly report subscription status. Deployers should verify the address.
 * - registerSubscription validates that msg.sender is the subscriber and that the
 *   merchant matches the supplied provider — clients cannot register another user's sub.
 * - Subscription status is read live at call time; a subscription that expires between
 *   setBudget and fund will cause _preFund to revert (intentional — stale state is unsafe).
 * - This hook holds no token custody. All value flows through the ACP core contract.
 * - _postComplete and _postReject are informational only; no state-changing external
 *   calls are made, so they cannot cause unexpected reverts.
 *
 * Profile: B — Advanced Escrow
 * (Multi-phase flow; maintains job↔subscription state; integrates external ERC standard)
 *
 * Related standards:
 *   ERC-8183 — Agentic Commerce Protocol  (https://eips.ethereum.org/EIPS/eip-8183)
 *   ERC-8191 — Onchain Recurring Payments (https://github.com/ethereum/ERCs/pull/1595)
 */
contract RecurringPaymentHook is BaseACPHook {
    ISubscription public immutable subscriptionManager;

    /// @notice Minimum budget required for non-subscribers (in token's smallest unit)
    uint256 public immutable nonSubscriberMinBudget;

    /// @notice Minimum budget required for active subscribers (discount tier, may be 0)
    uint256 public immutable subscriberMinBudget;

    // ─── Storage ──────────────────────────────────────────────────────────

    /// @notice client => provider => registered subscriptionId
    mapping(address => mapping(address => bytes32)) public clientSubscriptions;

    /// @notice jobId => subscriptionId (populated at fund time)
    mapping(uint256 => bytes32) public jobSubscription;

    // ─── Events ───────────────────────────────────────────────────────────

    event SubscriptionRegistered(
        address indexed client,
        address indexed provider,
        bytes32 indexed subId
    );
    event JobLinkedToSubscription(uint256 indexed jobId, bytes32 indexed subId);
    event JobCompletedForSubscriber(uint256 indexed jobId, bytes32 indexed subId);
    event JobRejectedForSubscriber(uint256 indexed jobId, bytes32 indexed subId);

    // ─── Errors ───────────────────────────────────────────────────────────

    error SubscriptionLapsed(address client, address provider);
    error BudgetBelowMinimum(uint256 provided, uint256 minimum);
    error NotSubscriber(bytes32 subId);
    error ProviderMismatch(bytes32 subId);

    // ─── Constructor ──────────────────────────────────────────────────────

    /**
     * @param acpContract_            ERC-8183 AgenticCommerceHooked contract address
     * @param subscriptionManager_    ERC-8191 SubscriptionManager contract address
     * @param nonSubscriberMinBudget_ Minimum budget for clients without an active subscription
     * @param subscriberMinBudget_    Minimum budget for clients with an active subscription
     */
    constructor(
        address acpContract_,
        address subscriptionManager_,
        uint256 nonSubscriberMinBudget_,
        uint256 subscriberMinBudget_
    ) BaseACPHook(acpContract_) {
        subscriptionManager = ISubscription(subscriptionManager_);
        nonSubscriberMinBudget = nonSubscriberMinBudget_;
        subscriberMinBudget = subscriberMinBudget_;
    }

    // ─── Registration ─────────────────────────────────────────────────────

    /**
     * @notice Register an ERC-8191 subscription for the (caller → provider) pair.
     * @dev    Validates that msg.sender is the subscriber and the merchant matches.
     *         Called by the client after SubscriptionManager.subscribe().
     * @param provider  Address of the agent / service provider
     * @param subId     ERC-8191 subscription identifier returned by subscribe()
     */
    function registerSubscription(address provider, bytes32 subId) external {
        if (subscriptionManager.getSubscriber(subId) != msg.sender) revert NotSubscriber(subId);
        if (subscriptionManager.getMerchant(subId) != provider) revert ProviderMismatch(subId);
        clientSubscriptions[msg.sender][provider] = subId;
        emit SubscriptionRegistered(msg.sender, provider, subId);
    }

    // ─── Hook overrides ───────────────────────────────────────────────────

    /**
     * @dev Tiered pricing: active subscribers may set a lower budget (subscriberMinBudget).
     *      Non-subscribers or lapsed subscribers must meet nonSubscriberMinBudget.
     */
    function _preSetBudget(
        uint256 jobId,
        uint256 amount,
        bytes memory /*optParams*/
    ) internal override {
        address client = _getJobClient(jobId);
        address provider = _getJobProvider(jobId);
        bytes32 subId = clientSubscriptions[client][provider];

        bool hasActiveSubscription = subId != bytes32(0)
            && subscriptionManager.getStatus(subId) == SubscriptionStatus.Active;

        uint256 minimum = hasActiveSubscription ? subscriberMinBudget : nonSubscriberMinBudget;
        if (amount < minimum) revert BudgetBelowMinimum(amount, minimum);
    }

    /**
     * @dev Subscription gate: if a subscription is registered for (client, provider),
     *      it must be Active before funding is allowed. No subscription = open access.
     */
    function _preFund(uint256 jobId, bytes memory /*optParams*/) internal override {
        address client = _getJobClient(jobId);
        address provider = _getJobProvider(jobId);
        bytes32 subId = clientSubscriptions[client][provider];

        if (subId == bytes32(0)) return;

        if (subscriptionManager.getStatus(subId) != SubscriptionStatus.Active) {
            revert SubscriptionLapsed(client, provider);
        }
    }

    /**
     * @dev After funding: link jobId → subId for downstream lifecycle correlation.
     */
    function _postFund(uint256 jobId, bytes memory /*optParams*/) internal override {
        address client = _getJobClient(jobId);
        address provider = _getJobProvider(jobId);
        bytes32 subId = clientSubscriptions[client][provider];

        if (subId != bytes32(0)) {
            jobSubscription[jobId] = subId;
            emit JobLinkedToSubscription(jobId, subId);
        }
    }

    /**
     * @dev Informational: signals off-chain services that a subscription-backed job
     *      completed successfully (reputation update, keeper acknowledgment, renewal).
     */
    function _postComplete(
        uint256 jobId,
        bytes32 /*reason*/,
        bytes memory /*optParams*/
    ) internal override {
        bytes32 subId = jobSubscription[jobId];
        if (subId != bytes32(0)) emit JobCompletedForSubscriber(jobId, subId);
    }

    /**
     * @dev Informational: signals off-chain dunning logic that a subscription-backed
     *      job was rejected. The subscriber or keeper decides whether to cancel or retry.
     */
    function _postReject(
        uint256 jobId,
        bytes32 /*reason*/,
        bytes memory /*optParams*/
    ) internal override {
        bytes32 subId = jobSubscription[jobId];
        if (subId != bytes32(0)) emit JobRejectedForSubscriber(jobId, subId);
    }

    // ─── Internal helpers ─────────────────────────────────────────────────

    /**
     * @dev Read provider address from the ACP job struct.
     *      Job layout: (id, client, provider, evaluator, hook, description, budget, expiredAt, status)
     */
    function _getJobProvider(uint256 jobId) internal view returns (address provider) {
        (bool ok, bytes memory data) = acpContract.staticcall(
            abi.encodeWithSignature("getJob(uint256)", jobId)
        );
        require(ok, "getJob failed");
        (,, provider,,,,,,) = abi.decode(
            data,
            (uint256, address, address, address, address, string, uint256, uint256, uint8)
        );
    }
}
