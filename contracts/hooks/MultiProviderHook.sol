// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";
import "../interfaces/IMultiPartyCoordination.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MultiProviderHook
 * @notice Profile B — Multi-provider job management with payment distribution.
 *
 * USE CASE
 * --------
 * Jobs requiring multiple providers working together (e.g., 5 reviewers,
 * 3 validators) with automatic payment distribution upon completion.
 *
 * FLOW
 * ----
 *  1. createJob(provider, evaluator, expiry, desc, hook=this)
 *     → Job created with this hook attached
 *
 *  2. addProviders() — Client adds providers via hook
 *     → Hook registers providers with ERC-8004 registry
 *     → Emits ProviderAdded
 *
 *  3. fund() — Client funds job
 *     → Hook validates provider set is non-empty
 *     → Core contract pulls funds into escrow
 *
 *  4. submit() — Provider submits work
 *     → Job moves to Submitted state
 *
 *  5. complete() — Evaluator completes job
 *     → Core releases escrow to hook
 *     → Hook distributes payments to providers via ERC-8004
 *     → Emits PaymentDistributed
 *
 *  6. removeProvider() — Can remove providers before funding
 *
 * SECURITY CONSIDERATIONS
 * -----------------------
 * - Only client can add/remove providers
 * - Provider set must be valid before funding
 * - Cannot remove last provider (minimum 1)
 * - Payment distribution uses SafeERC20
 * - Zero-address checks on all providers
 * - Maximum provider limit (gas protection)
 *
 * TRUST MODEL
 * -----------
 * - Client trusts hook to fairly distribute payments
 * - Providers trust ERC-8004 registry to track participation
 * - Hook is immutable (no upgrades)
 * - claimRefund remains unhookable (safety mechanism)
 *
 * COMPLEMENTARY FEATURES
 * ----------------------
 * This hook can be combined with ERC8001CoordinationHook:
 * - Multi-provider for payment distribution
 * - ERC-8001 coordination for consensus on completion
 */
contract MultiProviderHook is BaseACPHook {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error MultiProviderHook_OnlyClient();
    error MultiProviderHook_OnlyBeforeFunding();
    error MultiProviderHook_ProviderSetEmpty();
    error MultiProviderHook_InvalidProviderSet();
    error MultiProviderHook_ZeroAddress();
    error MultiProviderHook_RegistryCallFailed();
    error MultiProviderHook_InvalidShares();
    error MultiProviderHook_TransferFailed();

    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    event ProviderAdded(uint256 indexed jobId, address indexed provider, address indexed adder);

    event ProviderRemoved(uint256 indexed jobId, address indexed provider, address indexed remover);

    event PaymentDistributed(uint256 indexed jobId, address[] providers, uint256[] amounts);

    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// @dev ERC-8004 provider registry
    IMultiPartyCoordination public immutable providerRegistry;

    /// @dev ERC-20 token for payments
    IERC20 public immutable paymentToken;

    /// @dev Job ID => has been funded (prevents provider modifications after funding)
    mapping(uint256 => bool) public jobFunded;

    /// @dev Job ID => budget (for payment calculation)
    mapping(uint256 => uint256) public jobBudget;

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    constructor(address acpContract_, address providerRegistry_, address paymentToken_) BaseACPHook(acpContract_) {
        if (providerRegistry_ == address(0)) revert MultiProviderHook_ZeroAddress();
        if (paymentToken_ == address(0)) revert MultiProviderHook_ZeroAddress();

        providerRegistry = IMultiPartyCoordination(providerRegistry_);
        paymentToken = IERC20(paymentToken_);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - Provider Management
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Add a provider to a job.
     * @dev Only callable by job client before funding.
     * @param jobId The job ID
     * @param provider The provider address
     */
    function addProvider(uint256 jobId, address provider) external {
        // Only client can add providers
        _onlyClient(jobId);

        // Can only add before funding
        if (jobFunded[jobId]) revert MultiProviderHook_OnlyBeforeFunding();

        if (provider == address(0)) revert MultiProviderHook_ZeroAddress();

        // Convert jobId to bytes32 for registry
        bytes32 jobIdBytes = bytes32(jobId);

        // Call registry to add provider
        (bool success,) = address(providerRegistry)
            .call(abi.encodeWithSelector(IMultiPartyCoordination.addProvider.selector, jobIdBytes, provider));

        if (!success) revert MultiProviderHook_RegistryCallFailed();

        emit ProviderAdded(jobId, provider, msg.sender);
    }

    /**
     * @notice Remove a provider from a job.
     * @dev Only callable by job client before funding.
     * @param jobId The job ID
     * @param provider The provider address
     */
    function removeProvider(uint256 jobId, address provider) external {
        // Only client can remove providers
        _onlyClient(jobId);

        // Can only remove before funding
        if (jobFunded[jobId]) revert MultiProviderHook_OnlyBeforeFunding();

        // Convert jobId to bytes32 for registry
        bytes32 jobIdBytes = bytes32(jobId);

        // Call registry to remove provider
        (bool success,) = address(providerRegistry)
            .call(abi.encodeWithSelector(IMultiPartyCoordination.removeProvider.selector, jobIdBytes, provider));

        if (!success) revert MultiProviderHook_RegistryCallFailed();

        emit ProviderRemoved(jobId, provider, msg.sender);
    }

    /**
     * @notice Get providers for a job.
     * @param jobId The job ID
     * @return providers Array of provider addresses
     */
    function getJobProviders(uint256 jobId) external view returns (address[] memory providers) {
        bytes32 jobIdBytes = bytes32(jobId);

        // Call registry to get providers
        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.getProviders.selector, jobIdBytes));

        if (!success) return new address[](0);

        return abi.decode(result, (address[]));
    }

    /**
     * @notice Check if provider set is valid.
     * @param jobId The job ID
     * @return isValid True if valid
     */
    function isValidProviderSet(uint256 jobId) external view returns (bool isValid) {
        bytes32 jobIdBytes = bytes32(jobId);

        // Call registry to validate
        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.isValidProviderSet.selector, jobIdBytes));

        if (!success) return false;

        return abi.decode(result, (bool));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HOOK CALLBACKS
    // ═══════════════════════════════════════════════════════════════════════

    // Temporary storage for budget during fund operation
    mapping(uint256 => uint256) private tempBudget;

    /**
     * @dev Called before fund(). Validates provider set and stores expected budget.
     * @param jobId The job ID
     * @param expectedBudget The expected budget amount
     * @param optParams Optional parameters
     */
    function _preFund(uint256 jobId, uint256 expectedBudget, bytes memory optParams) internal override {
        // Store budget for later distribution
        tempBudget[jobId] = expectedBudget;

        // Validate provider set
        bytes32 jobIdBytes = bytes32(jobId);

        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.isValidProviderSet.selector, jobIdBytes));

        if (!success || !abi.decode(result, (bool))) {
            revert MultiProviderHook_InvalidProviderSet();
        }
    }

    /**
     * @dev Called after fund(). Records funding and budget.
     * @param jobId The job ID
     * @param expectedBudget The expected budget amount
     * @param optParams Optional parameters
     */
    function _postFund(uint256 jobId, uint256 expectedBudget, bytes memory optParams) internal override {
        // Mark as funded
        jobFunded[jobId] = true;

        // Use the budget we saved in _preFund (or expectedBudget)
        jobBudget[jobId] = tempBudget[jobId] > 0 ? tempBudget[jobId] : expectedBudget;

        // Clear temp storage
        delete tempBudget[jobId];
    }

    /**
     * @dev Called after complete(). Distributes payment to providers.
     * @param jobId The job ID
     * @param reason Completion reason
     * @param optParams Optional parameters
     */
    function _postComplete(uint256 jobId, bytes32 reason, bytes memory optParams) internal override {
        // Get budget for this job
        uint256 budget = jobBudget[jobId];
        if (budget == 0) return; // Nothing to distribute

        bytes32 jobIdBytes = bytes32(jobId);

        // Get providers
        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.getProviders.selector, jobIdBytes));

        if (!success) return;

        address[] memory providers = abi.decode(result, (address[]));
        uint256 providerCount = providers.length;

        if (providerCount == 0) return; // No providers to pay

        // Calculate equal shares (in basis points)
        // Each provider gets equal share: 10000 / providerCount
        uint256 sharePerProvider = 10000 / providerCount;
        uint256[] memory shares = new uint256[](providerCount);

        for (uint256 i = 0; i < providerCount; i++) {
            shares[i] = sharePerProvider;
        }

        // Handle remainder (first provider gets extra)
        uint256 totalShares = sharePerProvider * providerCount;
        if (totalShares < 10000) {
            shares[0] += (10000 - totalShares);
        }

        // Pull funds from ACP contract
        // The ACP contract should have sent the budget to this hook
        uint256 hookBalance = paymentToken.balanceOf(address(this));

        if (hookBalance == 0) return; // Nothing to distribute

        // Distribute to providers
        uint256[] memory amounts = new uint256[](providerCount);

        for (uint256 i = 0; i < providerCount; i++) {
            amounts[i] = (hookBalance * shares[i]) / 10000;

            if (amounts[i] > 0) {
                paymentToken.safeTransfer(providers[i], amounts[i]);
            }
        }

        emit PaymentDistributed(jobId, providers, amounts);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Verify caller is job client.
     * @param jobId The job ID
     */
    function _onlyClient(uint256 jobId) internal view {
        (bool ok, bytes memory data) = acpContract.staticcall(abi.encodeWithSignature("getJob(uint256)", jobId));

        if (!ok) revert MultiProviderHook_RegistryCallFailed();

        // Decode client address from Job struct
        // Job struct layout: [id, client, provider, evaluator, hook, description, budget, expiredAt, status]
        // client is at slot 1
        address client;
        assembly {
            let base := add(data, 32) // skip bytes length
            client := mload(add(base, 64)) // slot 2 (0=id, 1=client, etc.)
        }

        if (msg.sender != client) revert MultiProviderHook_OnlyClient();
    }
}
