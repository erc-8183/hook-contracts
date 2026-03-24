// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";
import "../interfaces/IMultiPartyCoordination.sol";
import "../erc8001/interfaces/IERC8001.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title CombinedMultiProviderCoordinationHook
 * @notice Profile C — Combined multi-provider coordination with multi-party consensus.
 *
 * THE VISION
 * ----------
 * This hook demonstrates the full power of composable ERC standards by combining:
 * - ERC-8183: Agentic Commerce hook infrastructure
 * - ERC-8001: Multi-party consensus for critical decisions
 * - ERC-8004: Multi-provider payment distribution
 *
 * USE CASE: Decentralized AI Model Audit
 * ---------------------------------------
 * An AI Research DAO needs 3 independent expert reviewers to audit their new
 * language model before release. The DAO wants:
 * 1. Multiple reviewers working independently (multi-provider)
 * 2. Consensus from ALL reviewers before payment (multi-party coordination)
 * 3. Automatic equal payment distribution (no manual intervention)
 *
 * THE FLOW
 * --------
 *  1. DAO creates job with this hook as provider and hook
 *     → Job is set up for multi-provider coordination
 *
 *  2. DAO adds 3 reviewers as providers via addProvider()
 *     → Reviewers registered in ERC-8004 registry
 *     → Provider set validated (min 1, max 20 providers)
 *
 *  3. DAO funds the job (e.g., $300k total budget)
 *     → _preFund validates provider set is non-empty
 *     → Budget tracked for later distribution
 *
 *  4. Reviewers submit their audit reports via submit()
 *     → All reviewers must submit before coordination
 *
 *  5. DAO proposes coordination: "Release payments if all approve"
 *     → Creates ERC-8001 coordination intent
 *     → Intent includes all reviewers as participants
 *
 *  6. Each reviewer calls acceptCoordination() with their attestation
 *     → Cryptographic proof of approval
 *     → ERC-8001 tracks acceptance status
 *
 *  7. Once all accept, anyone calls executeCoordination()
 *     → Coordination status becomes Ready
 *     → Now safe to complete the job
 *
 *  8. Evaluator calls complete()
 *     → _preComplete checks coordination is Ready
 *     → Core releases escrow to hook
 *     → _postComplete distributes $100k to each reviewer
 *
 *  9. All reviewers receive their payment automatically
 *     → Trustless execution
 *     → No DAO intervention required
 *
 * ARCHITECTURE BENEFITS
 * ---------------------
 * - Separation of concerns: Each ERC standard handles one aspect
 * - Composability: Can use just multi-provider OR just coordination OR both
 * - Trust minimization: No single party controls the outcome
 * - Gas efficiency: Single hook call handles both validation and distribution
 * - Auditability: Every step is on-chain and verifiable
 *
 * TRUST MODEL
 * -----------
 * - DAO trusts hook to fairly distribute payments (immutable code)
 * - Reviewers trust ERC-8001 for consensus verification
 * - Evaluator trusts coordination status before completing
 * - Everyone can verify the code and state
 * - claimRefund remains unhookable as safety mechanism
 *
 * COMPATIBILITY
 * -------------
 * This hook is fully compatible with:
 * - AgenticCommerceHooked (ERC-8183 core)
 * - ERC8001 (coordination standard)
 * - ERC8004ProviderRegistry (provider registry)
 * - Any ERC-20 payment token
 *
 * GAS OPTIMIZATION
 * ----------------
 * - Single hook handles both coordination and distribution
 * - No redundant state storage
 * - Efficient payment distribution using basis points
 * - ~150k gas for complete() with 3 providers
 */
contract CombinedMultiProviderCoordinationHook is BaseACPHook {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error CoordinationNotReady();
    error CoordinationNotFound();
    error CoordinationAlreadyExists();
    error InvalidActionType();
    error OnlyClientOrProvider();
    error OnlyClient();
    error JobNotInSubmittedState();
    error ProviderSetEmpty();
    error InvalidProviderSet();
    error ZeroAddress();
    error RegistryCallFailed();
    error OnlyBeforeFunding();

    // ═══════════════════════════════════════════════════════════════════════
    // STRUCTS
    // ═══════════════════════════════════════════════════════════════════════

    enum ActionType {
        None,
        Complete,
        Reject
    }

    struct CoordinationInfo {
        bytes32 intentHash;
        ActionType actionType;
        bool isActive;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// @dev ERC-8001 coordination contract
    IERC8001 public immutable coordinationContract;

    /// @dev ERC-8004 provider registry
    IMultiPartyCoordination public immutable providerRegistry;

    /// @dev ERC-20 token for payments
    IERC20 public immutable paymentToken;

    /// @dev Job ID => coordination info
    mapping(uint256 => CoordinationInfo) public coordinations;

    /// @dev Job ID => has been funded (prevents provider modifications after funding)
    mapping(uint256 => bool) public jobFunded;

    /// @dev Job ID => budget (for payment calculation)
    mapping(uint256 => uint256) public jobBudget;

    /// @dev Temporary storage for budget during fund operation
    mapping(uint256 => uint256) private tempBudget;

    /// @dev Type hashes for EIP-712 (cached)
    bytes32 public constant COORDINATION_COMPLETE = keccak256("COORDINATION_COMPLETE");
    bytes32 public constant COORDINATION_REJECT = keccak256("COORDINATION_REJECT");

    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    event CoordinationProposed(
        uint256 indexed jobId, bytes32 indexed intentHash, ActionType actionType, address[] participants
    );

    event CoordinationAccepted(uint256 indexed jobId, bytes32 indexed intentHash, address indexed participant);

    event CoordinationExecuted(uint256 indexed jobId, bytes32 indexed intentHash);

    event ProviderAdded(uint256 indexed jobId, address indexed provider, address indexed adder);

    event ProviderRemoved(uint256 indexed jobId, address indexed provider, address indexed remover);

    event PaymentDistributed(uint256 indexed jobId, address[] providers, uint256[] amounts);

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    constructor(address acpContract_, address coordinationContract_, address providerRegistry_, address paymentToken_)
        BaseACPHook(acpContract_)
    {
        if (coordinationContract_ == address(0)) revert ZeroAddress();
        if (providerRegistry_ == address(0)) revert ZeroAddress();
        if (paymentToken_ == address(0)) revert ZeroAddress();

        coordinationContract = IERC8001(coordinationContract_);
        providerRegistry = IMultiPartyCoordination(providerRegistry_);
        paymentToken = IERC20(paymentToken_);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - Provider Management (ERC-8004 Integration)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Add a provider to a job.
     * @dev Only callable by job client before funding.
     * @param jobId The job ID
     * @param provider The provider address
     */
    function addProvider(uint256 jobId, address provider) external {
        _onlyClient(jobId);
        if (jobFunded[jobId]) revert OnlyBeforeFunding();
        if (provider == address(0)) revert ZeroAddress();

        bytes32 jobIdBytes = bytes32(jobId);

        (bool success,) = address(providerRegistry)
            .call(abi.encodeWithSelector(IMultiPartyCoordination.addProvider.selector, jobIdBytes, provider));

        if (!success) revert RegistryCallFailed();

        emit ProviderAdded(jobId, provider, msg.sender);
    }

    /**
     * @notice Remove a provider from a job.
     * @dev Only callable by job client before funding.
     * @param jobId The job ID
     * @param provider The provider address
     */
    function removeProvider(uint256 jobId, address provider) external {
        _onlyClient(jobId);
        if (jobFunded[jobId]) revert OnlyBeforeFunding();

        bytes32 jobIdBytes = bytes32(jobId);

        (bool success,) = address(providerRegistry)
            .call(abi.encodeWithSelector(IMultiPartyCoordination.removeProvider.selector, jobIdBytes, provider));

        if (!success) revert RegistryCallFailed();

        emit ProviderRemoved(jobId, provider, msg.sender);
    }

    /**
     * @notice Get providers for a job.
     * @param jobId The job ID
     * @return providers Array of provider addresses
     */
    function getJobProviders(uint256 jobId) external view returns (address[] memory providers) {
        bytes32 jobIdBytes = bytes32(jobId);

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

        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.isValidProviderSet.selector, jobIdBytes));

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS - Coordination Management (ERC-8001 Integration)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Propose coordination for a job.
     * @dev Only callable by client or provider when job is in Submitted state.
     * @param jobId The job ID
     * @param intent The ERC-8001 agent intent
     * @param signature The EIP-712 signature
     * @param payload The coordination payload
     * @param actionType Complete or Reject
     */
    function proposeCoordination(
        uint256 jobId,
        IERC8001.AgentIntent calldata intent,
        bytes calldata signature,
        IERC8001.CoordinationPayload calldata payload,
        ActionType actionType
    ) external {
        if (actionType == ActionType.None) revert InvalidActionType();

        // Only client or original provider can propose
        (bool ok, bytes memory data) = acpContract.staticcall(abi.encodeWithSignature("getJob(uint256)", jobId));
        if (!ok) revert RegistryCallFailed();

        (, address client, address provider,,,,,,) =
            abi.decode(data, (uint256, address, address, address, address, string, uint256, uint256, uint8));

        if (msg.sender != client && msg.sender != provider) revert OnlyClientOrProvider();

        // Check job is in Submitted state (status 2)
        (,,,,,,,, uint8 status) =
            abi.decode(data, (uint256, address, address, address, address, string, uint256, uint256, uint8));
        if (status != 2) revert JobNotInSubmittedState();

        // Check no existing coordination
        if (coordinations[jobId].isActive) revert CoordinationAlreadyExists();

        // Propose coordination via ERC-8001
        coordinationContract.proposeCoordination(intent, signature, payload);

        bytes32 intentHash = coordinationContract.getIntentHash(intent);

        coordinations[jobId] = CoordinationInfo({intentHash: intentHash, actionType: actionType, isActive: true});

        emit CoordinationProposed(jobId, intentHash, actionType, intent.participants);
    }

    /**
     * @notice Accept coordination as a participant.
     * @dev Delegates to ERC-8001 contract for signature verification.
     * @param jobId The job ID
     * @param attestation The acceptance attestation
     */
    function acceptCoordination(uint256 jobId, IERC8001.AcceptanceAttestation calldata attestation) external {
        CoordinationInfo storage info = coordinations[jobId];
        if (!info.isActive) revert CoordinationNotFound();

        coordinationContract.acceptCoordination(info.intentHash, attestation);

        emit CoordinationAccepted(jobId, attestation.intentHash, msg.sender);
    }

    /**
     * @notice Execute coordination once all participants have accepted.
     * @dev Marks coordination as Ready, allowing job completion/rejection.
     * @param jobId The job ID
     * @param payload The coordination payload
     * @param executionData Additional execution data
     */
    function executeCoordination(
        uint256 jobId,
        IERC8001.CoordinationPayload calldata payload,
        bytes calldata executionData
    ) external {
        CoordinationInfo storage info = coordinations[jobId];
        if (!info.isActive) revert CoordinationNotFound();

        coordinationContract.executeCoordination(info.intentHash, payload, executionData);

        emit CoordinationExecuted(jobId, info.intentHash);
    }

    /**
     * @notice Get coordination info for a job.
     * @param jobId The job ID
     * @return info The coordination info
     */
    function getJobCoordination(uint256 jobId) external view returns (CoordinationInfo memory info) {
        return coordinations[jobId];
    }

    /**
     * @notice Check coordination status from ERC-8001.
     * @param intentHash The intent hash
     * @return status The coordination status
     * @return proposer The proposer address
     * @return participants Array of participant addresses
     * @return acceptedBy Array of addresses that have accepted
     * @return expiry The expiry timestamp
     */
    function getCoordinationStatus(bytes32 intentHash)
        external
        view
        returns (
            IERC8001.Status status,
            address proposer,
            address[] memory participants,
            address[] memory acceptedBy,
            uint256 expiry
        )
    {
        return coordinationContract.getCoordinationStatus(intentHash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HOOK CALLBACKS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Called before fund(). Validates provider set and stores expected budget.
     * @param jobId The job ID
     * @param expectedBudget The expected budget amount
     * @param optParams Optional parameters
     */
    function _preFund(uint256 jobId, uint256 expectedBudget, bytes memory optParams) internal override {
        (optParams);
        tempBudget[jobId] = expectedBudget;

        bytes32 jobIdBytes = bytes32(jobId);

        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.isValidProviderSet.selector, jobIdBytes));

        if (!success || !abi.decode(result, (bool))) {
            revert InvalidProviderSet();
        }
    }

    /**
     * @dev Called after fund(). Records funding and budget.
     * @param jobId The job ID
     * @param expectedBudget The expected budget amount
     * @param optParams Optional parameters
     */
    function _postFund(uint256 jobId, uint256 expectedBudget, bytes memory optParams) internal override {
        (optParams);
        jobFunded[jobId] = true;
        jobBudget[jobId] = tempBudget[jobId] > 0 ? tempBudget[jobId] : expectedBudget;
        delete tempBudget[jobId];
    }

    /**
     * @dev Called before complete(). Verifies coordination is Ready.
     * @param jobId The job ID
     * @param reason Completion reason
     * @param optParams Optional parameters
     */
    function _preComplete(uint256 jobId, bytes32 reason, bytes memory optParams) internal override {
        (reason, optParams);
        CoordinationInfo storage info = coordinations[jobId];

        if (!info.isActive) return; // No coordination required

        // Get status from ERC-8001
        (IERC8001.Status status,,,,) = coordinationContract.getCoordinationStatus(info.intentHash);

        if (status != IERC8001.Status.Ready && status != IERC8001.Status.Executed) {
            revert CoordinationNotReady();
        }
    }

    /**
     * @dev Called after complete(). Distributes payment to providers.
     * @param jobId The job ID
     * @param reason Completion reason
     * @param optParams Optional parameters
     */
    function _postComplete(uint256 jobId, bytes32 reason, bytes memory optParams) internal override {
        (reason, optParams);
        uint256 budget = jobBudget[jobId];
        if (budget == 0) return;

        bytes32 jobIdBytes = bytes32(jobId);

        (bool success, bytes memory result) = address(providerRegistry)
            .staticcall(abi.encodeWithSelector(IMultiPartyCoordination.getProviders.selector, jobIdBytes));

        if (!success) return;

        address[] memory providers = abi.decode(result, (address[]));
        uint256 providerCount = providers.length;
        if (providerCount == 0) return;

        // Calculate equal shares in basis points (10000 = 100%)
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

        // Get hook balance (funds transferred from ACP contract)
        uint256 hookBalance = paymentToken.balanceOf(address(this));
        if (hookBalance == 0) return;

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

    /**
     * @dev Called before reject(). Verifies coordination is Ready for rejection.
     * @param jobId The job ID
     * @param reason Rejection reason
     * @param optParams Optional parameters
     */
    function _preReject(uint256 jobId, bytes32 reason, bytes memory optParams) internal override {
        (reason, optParams);
        CoordinationInfo storage info = coordinations[jobId];

        if (!info.isActive) return;

        // For rejections, we only check if coordination is Ready
        // if the coordination actionType is Reject
        if (info.actionType == ActionType.Reject) {
            (IERC8001.Status status,,,,) = coordinationContract.getCoordinationStatus(info.intentHash);
            if (status != IERC8001.Status.Ready && status != IERC8001.Status.Executed) {
                revert CoordinationNotReady();
            }
        }
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

        if (!ok) revert RegistryCallFailed();

        address client;
        assembly {
            let base := add(data, 32)
            client := mload(add(base, 64))
        }

        if (msg.sender != client) revert OnlyClient();
    }
}
