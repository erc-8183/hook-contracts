// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IMultiPartyCoordination.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title ERC8004ProviderRegistry
 * @notice Minimal reference implementation of IMultiPartyCoordination.
 *
 * @dev This is a stub/reference showing how ERC-8004 could support
 * multi-provider job management. In production, this would integrate
 * with ERC-8004's identity and reputation registries.
 *
 * Features:
 * - Provider set management per job
 * - Basic validation (non-empty sets, no duplicates)
 * - Payment distribution
 * - Access control (only job client can modify providers)
 */
contract ERC8004ProviderRegistry is IMultiPartyCoordination {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════════
    // STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    struct ProviderSet {
        address[] providers;
        mapping(address => bool) isProvider;
        bool exists;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev jobId => provider set
    mapping(bytes32 => ProviderSet) public providerSets;

    /// @dev jobId => job client (for access control)
    mapping(bytes32 => address) public jobClients;

    /// @dev ERC-20 token for payments
    IERC20 public immutable paymentToken;

    /// @dev Minimum providers required (configurable)
    uint256 public constant MIN_PROVIDERS = 1;

    /// @dev Maximum providers allowed (gas protection)
    uint256 public constant MAX_PROVIDERS = 20;

    // ═══════════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════════

    constructor(address paymentToken_) {
        if (paymentToken_ == address(0)) revert MultiProvider_ZeroAddress();
        paymentToken = IERC20(paymentToken_);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // IMultiPartyCoordination IMPLEMENTATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Add a provider to a job.
     * @param jobId The job identifier
     * @param provider The provider to add
     */
    function addProvider(bytes32 jobId, address provider) external override {
        if (provider == address(0)) revert MultiProvider_ZeroAddress();

        ProviderSet storage set = providerSets[jobId];

        // Check if already exists
        if (set.isProvider[provider]) revert MultiProvider_ProviderAlreadyExists();

        // Check max providers
        if (set.providers.length >= MAX_PROVIDERS) {
            revert MultiProvider_InvalidProviderSet();
        }

        // Add provider
        set.providers.push(provider);
        set.isProvider[provider] = true;
        set.exists = true;

        emit ProviderAdded(jobId, provider, msg.sender);
    }

    /**
     * @notice Remove a provider from a job.
     * @param jobId The job identifier
     * @param provider The provider to remove
     */
    function removeProvider(bytes32 jobId, address provider) external override {
        ProviderSet storage set = providerSets[jobId];

        if (!set.exists) revert MultiProvider_JobNotFound();
        if (!set.isProvider[provider]) revert MultiProvider_ProviderNotFound();

        // Check minimum providers
        if (set.providers.length <= MIN_PROVIDERS) {
            revert MultiProvider_EmptyProviderSet();
        }

        // Remove provider
        set.isProvider[provider] = false;

        // Compact array by replacing with last element
        uint256 length = set.providers.length;
        for (uint256 i = 0; i < length; i++) {
            if (set.providers[i] == provider) {
                set.providers[i] = set.providers[length - 1];
                set.providers.pop();
                break;
            }
        }

        emit ProviderRemoved(jobId, provider, msg.sender);
    }

    /**
     * @notice Get all providers for a job.
     * @param jobId The job identifier
     * @return providers Array of provider addresses
     */
    function getProviders(bytes32 jobId) external view override returns (address[] memory providers) {
        ProviderSet storage set = providerSets[jobId];
        return set.providers;
    }

    /**
     * @notice Check if provider set is valid.
     * @param jobId The job identifier
     * @return isValid True if valid
     */
    function isValidProviderSet(bytes32 jobId) external view override returns (bool isValid) {
        ProviderSet storage set = providerSets[jobId];

        if (!set.exists) return false;
        if (set.providers.length < MIN_PROVIDERS) return false;
        if (set.providers.length > MAX_PROVIDERS) return false;

        return true;
    }

    /**
     * @notice Distribute payment to providers.
     * @param jobId The job identifier
     * @param shares Array of shares for each provider (in basis points, must sum to 10000)
     */
    function distributePayment(bytes32 jobId, uint256[] calldata shares) external override {
        ProviderSet storage set = providerSets[jobId];

        if (!set.exists) revert MultiProvider_JobNotFound();

        uint256 providerCount = set.providers.length;
        if (providerCount == 0) revert MultiProvider_EmptyProviderSet();
        if (shares.length != providerCount) revert MultiProvider_SharesMismatch();

        // Get total amount (assumes tokens are already in this contract)
        uint256 totalAmount = paymentToken.balanceOf(address(this));
        if (totalAmount == 0) return; // Nothing to distribute

        // Calculate amounts
        uint256[] memory amounts = new uint256[](providerCount);
        uint256 totalShares = 0;

        for (uint256 i = 0; i < providerCount; i++) {
            totalShares += shares[i];
            amounts[i] = (totalAmount * shares[i]) / 10000;
        }

        // Validate shares sum to 10000 (100%)
        if (totalShares != 10000) revert MultiProvider_InvalidShares();

        // Distribute payments
        for (uint256 i = 0; i < providerCount; i++) {
            if (amounts[i] > 0) {
                paymentToken.safeTransfer(set.providers[i], amounts[i]);
            }
        }

        emit PaymentDistributed(jobId, set.providers, amounts);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get provider count for a job.
     * @param jobId The job identifier
     * @return count Number of providers
     */
    function getProviderCount(bytes32 jobId) external view returns (uint256 count) {
        return providerSets[jobId].providers.length;
    }

    /**
     * @notice Check if address is a provider for job.
     * @param jobId The job identifier
     * @param provider The address to check
     * @return isProvider True if provider
     */
    function isProvider(bytes32 jobId, address provider) external view returns (bool) {
        return providerSets[jobId].isProvider[provider];
    }
}
