// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IMultiPartyCoordination
 * @dev Generic interface for multi-provider job management.
 *
 * This interface standardizes how hooks can manage multiple providers
 * working on a single job, including provider set validation and
 * payment distribution. Designed for use with ERC-8183 hooks.
 *
 * Example use cases:
 * - 5 reviewers working on the same job
 * - 3 validators collaborating
 * - Payment distribution among multiple contributors
 *
 * Note: This is separate from multi-party consensus (ERC-8001) -
 * these are complementary features that can be combined.
 */
interface IMultiPartyCoordination {
    // ═══════════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Emitted when a provider is added to a job.
     * @param jobId The job identifier
     * @param provider The provider address
     * @param adder The address that added the provider
     */
    event ProviderAdded(bytes32 indexed jobId, address indexed provider, address indexed adder);

    /**
     * @dev Emitted when a provider is removed from a job.
     * @param jobId The job identifier
     * @param provider The provider address
     * @param remover The address that removed the provider
     */
    event ProviderRemoved(bytes32 indexed jobId, address indexed provider, address indexed remover);

    /**
     * @dev Emitted when payments are distributed to providers.
     * @param jobId The job identifier
     * @param recipients Array of provider addresses receiving payment
     * @param amounts Array of amounts distributed
     */
    event PaymentDistributed(bytes32 indexed jobId, address[] recipients, uint256[] amounts);

    // ═══════════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════════

    error MultiProvider_JobNotFound();
    error MultiProvider_ProviderAlreadyExists();
    error MultiProvider_ProviderNotFound();
    error MultiProvider_InvalidProviderSet();
    error MultiProvider_EmptyProviderSet();
    error MultiProvider_Unauthorized();
    error MultiProvider_InvalidShares();
    error MultiProvider_SharesMismatch();
    error MultiProvider_ZeroAddress();

    // ═══════════════════════════════════════════════════════════════════════════
    // CORE FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Add a provider to a job's provider set.
     * @dev MUST revert if:
     *      - jobId is not valid
     *      - provider is already in the set
     *      - provider is zero address
     *      - caller is not authorized
     * Emits {ProviderAdded}.
     * @param jobId The job identifier
     * @param provider The provider address to add
     */
    function addProvider(bytes32 jobId, address provider) external;

    /**
     * @notice Remove a provider from a job's provider set.
     * @dev MUST revert if:
     *      - jobId is not valid
     *      - provider is not in the set
     *      - removing the last provider (would create empty set)
     *      - caller is not authorized
     * Emits {ProviderRemoved}.
     * @param jobId The job identifier
     * @param provider The provider address to remove
     */
    function removeProvider(bytes32 jobId, address provider) external;

    /**
     * @notice Get all providers for a job.
     * @param jobId The job identifier
     * @return providers Array of provider addresses
     */
    function getProviders(bytes32 jobId) external view returns (address[] memory providers);

    /**
     * @notice Validate if a provider set is valid for the job.
     * @dev Returns true if:
     *      - job exists
     *      - provider set is not empty
     *      - all providers are valid addresses
     *      - provider count is within acceptable range
     * @param jobId The job identifier
     * @return isValid True if provider set is valid
     */
    function isValidProviderSet(bytes32 jobId) external view returns (bool isValid);

    /**
     * @notice Distribute payment to providers.
     * @dev MUST revert if:
     *      - jobId is not valid
     *      - shares array length doesn't match provider count
     *      - shares don't sum to expected total (optional validation)
     *      - caller is not authorized
     * Emits {PaymentDistributed}.
     * @param jobId The job identifier
     * @param shares Array of payment shares for each provider (in basis points or absolute amounts)
     */
    function distributePayment(bytes32 jobId, uint256[] calldata shares) external;
}
