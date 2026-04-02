// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";
import "../erc8001/interfaces/IERC8001.sol";

/**
 * @title ERC8001CoordinationHook
 * @notice Profile B — Advanced Escrow hook for multi-party coordination
 *         of job completion and rejection.
 *
 * USE CASE
 * --------
 * High-value jobs requiring multiple parties (client, provider, evaluator,
 * optional arbiters) to cryptographically agree before the job can be
 * completed or rejected. Prevents unilateral decisions by enforcing
 * multi-party consensus through attestations.
 *
 * This hook uses ERC-8001 for multi-party coordination. While designed for
 * ERC-8001, the architecture supports other coordination frameworks through
 * the standard interface pattern.
 *
 * FLOW
 * ----
 *  1. createJob(provider, evaluator, expiry, desc, hook=this)
 *     → Job created with this hook attached
 *
 *  2. Provider submits work via submit()
 *     → Job moves to Submitted state
 *
 *  3. Any party calls proposeCoordination(jobId, participants, actionType, intent, signature, payload)
 *     → Creates ERC-8001 coordination intent with participants
 *     → Stores intentHash for the job
 *     → Emits CoordinationProposed
 *
 *  4. Each participant calls acceptCoordination(jobId, attestation)
 *     → Delegates to ERC-8001 contract for signature verification
 *     → Records acceptance on-chain
 *     → Emits CoordinationAccepted
 *
 *  5. Once all participants accept, anyone calls executeCoordination(jobId, payload, executionData)
 *     → Marks coordination as Ready in ERC-8001
 *     → Emits CoordinationExecuted
 *
 *  6. Evaluator calls complete(jobId, reason, optParams) or reject(jobId, reason, optParams)
 *     → _preComplete/_preReject checks coordination is Ready
 *     → If not Ready, reverts with CoordinationNotReady
 *     → Core contract executes complete/reject
 *
 *  7. Optional: cancelCoordination(jobId, reason) if coordination needs cancellation
 *     → Proposer can cancel before expiry
 *     → Anyone can cancel after expiry
 *
 * TRUST MODEL
 * -----------
 * - The hook trusts the ERC-8001 contract for signature verification and
 *   coordination state management
 * - Participants trust that their acceptance attestation will only be used
 *   for the specific coordination intent they signed
 * - The client and provider are incentivized to participate to resolve
 *   the job and release/return funds
 * - If coordination expires or is cancelled, the job can still be completed
 *   or rejected through other means (e.g., direct evaluator action)
 * - claimRefund remains unhookable as a safety mechanism
 *
 * KEY PROPERTIES
 * --------------
 * - Multi-party coordination via ERC-8001
 * - Supports ECDSA (65-byte and 64-byte) and ERC-1271 signatures
 * - Strict participant canonicalization (sorted unique addresses)
 * - Monotonic nonce enforcement per agent
 * - Optional per-job (not all jobs require coordination)
 * - Gas-efficient: minimal state in hook, complex logic in ERC-8001 contract
 */
contract ERC8001CoordinationHook is BaseACPHook {
    // ═══════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════

    error CoordinationNotReady();
    error CoordinationNotFound();
    error CoordinationAlreadyExists();
    error InvalidActionType();
    error OnlyClientOrProvider();
    error JobNotInSubmittedState();
    error ZeroAddress();

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

    IERC8001 public immutable coordinationContract;

    /// @dev jobId => coordination info
    mapping(uint256 => CoordinationInfo) public jobCoordinations;

    /// @dev Coordination type identifiers per ERC-8001
    bytes32 public constant COORDINATION_COMPLETE = keccak256("COMPLETE_JOB");
    bytes32 public constant COORDINATION_REJECT = keccak256("REJECT_JOB");

    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    event CoordinationProposed(
        uint256 indexed jobId, bytes32 indexed intentHash, ActionType actionType, address[] participants
    );

    event CoordinationAccepted(uint256 indexed jobId, address indexed participant, bytes32 indexed intentHash);

    event CoordinationExecuted(uint256 indexed jobId, bytes32 indexed intentHash, ActionType actionType);

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    constructor(address acpContract_, address coordinationContract_) BaseACPHook(acpContract_) {
        if (coordinationContract_ == address(0)) revert ZeroAddress();
        coordinationContract = IERC8001(coordinationContract_);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HOOK CALLBACKS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Called before complete(). Verifies ERC-8001 coordination is Ready.
     * @param jobId The job ID
     */
    function _preComplete(
        uint256 jobId,
        address, /* caller */
        bytes32, /* reason */
        bytes memory /* optParams */
    )
        internal
        view
        override
    {
        CoordinationInfo memory info = jobCoordinations[jobId];

        // If no coordination exists, allow completion (coordination is optional)
        if (!info.isActive) return;

        // If coordination exists but is for reject, allow completion
        if (info.actionType == ActionType.Reject) return;

        // Must be a complete coordination
        if (info.actionType != ActionType.Complete) revert InvalidActionType();

        // Check coordination is Ready or already Executed (both mean all parties agreed)
        (IERC8001.Status status,,,,) = coordinationContract.getCoordinationStatus(info.intentHash);
        if (status != IERC8001.Status.Ready && status != IERC8001.Status.Executed) {
            revert CoordinationNotReady();
        }
    }

    /**
     * @dev Called before reject(). Verifies ERC-8001 coordination is Ready.
     * @param jobId The job ID
     */
    function _preReject(
        uint256 jobId,
        address, /* caller */
        bytes32, /* reason */
        bytes memory /* optParams */
    )
        internal
        view
        override
    {
        CoordinationInfo memory info = jobCoordinations[jobId];

        // If no coordination exists, allow rejection
        if (!info.isActive) return;

        // If coordination exists but is for complete, allow rejection
        if (info.actionType == ActionType.Complete) return;

        // Must be a reject coordination
        if (info.actionType != ActionType.Reject) revert InvalidActionType();

        // Check coordination is Ready or already Executed (both mean all parties agreed)
        (IERC8001.Status status,,,,) = coordinationContract.getCoordinationStatus(info.intentHash);
        if (status != IERC8001.Status.Ready && status != IERC8001.Status.Executed) {
            revert CoordinationNotReady();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXTERNAL FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Propose a coordination for completing or rejecting a job.
     * @param jobId The job ID
     * @param intent The ERC-8001 intent structure
     * @param signature EIP-712 signature from the proposer
     * @param payload The coordination payload
     * @param actionType Complete (1) or Reject (2)
     */
    function proposeCoordination(
        uint256 jobId,
        IERC8001.AgentIntent calldata intent,
        bytes calldata signature,
        IERC8001.CoordinationPayload calldata payload,
        ActionType actionType
    ) external returns (bytes32 intentHash) {
        if (actionType != ActionType.Complete && actionType != ActionType.Reject) {
            revert InvalidActionType();
        }

        // Check no existing active coordination for this job
        if (jobCoordinations[jobId].isActive) revert CoordinationAlreadyExists();

        // Single getJob call to read client, provider, and status
        (address client, address provider, uint8 status) = _getJobClientProviderStatus(jobId);

        if (msg.sender != client && msg.sender != provider) {
            revert OnlyClientOrProvider();
        }

        // Job must be in Submitted state (JobStatus.Submitted == 2)
        if (status != 2) revert JobNotInSubmittedState();

        // Set coordination type in intent
        IERC8001.AgentIntent memory modifiedIntent = intent;
        modifiedIntent.coordinationType =
            actionType == ActionType.Complete ? COORDINATION_COMPLETE : COORDINATION_REJECT;

        // Call ERC-8001 to propose
        intentHash = coordinationContract.proposeCoordination(modifiedIntent, signature, payload);

        // Store coordination info
        jobCoordinations[jobId] = CoordinationInfo({intentHash: intentHash, actionType: actionType, isActive: true});

        emit CoordinationProposed(jobId, intentHash, actionType, intent.participants);

        return intentHash;
    }

    /**
     * @notice Accept a coordination as a participant.
     * @param jobId The job ID
     * @param attestation The acceptance attestation
     * @return allAccepted True if all participants have accepted
     */
    function acceptCoordination(uint256 jobId, IERC8001.AcceptanceAttestation calldata attestation)
        external
        returns (bool allAccepted)
    {
        CoordinationInfo memory info = jobCoordinations[jobId];
        if (!info.isActive) revert CoordinationNotFound();

        allAccepted = coordinationContract.acceptCoordination(info.intentHash, attestation);

        if (allAccepted) {
            emit CoordinationAccepted(jobId, attestation.participant, info.intentHash);
        }

        return allAccepted;
    }

    /**
     * @notice Execute a ready coordination.
     * @param jobId The job ID
     * @param payload The coordination payload
     * @param executionData Optional execution data
     */
    function executeCoordination(
        uint256 jobId,
        IERC8001.CoordinationPayload calldata payload,
        bytes calldata executionData
    ) external returns (bool success, bytes memory result) {
        CoordinationInfo memory info = jobCoordinations[jobId];
        if (!info.isActive) revert CoordinationNotFound();

        (success, result) = coordinationContract.executeCoordination(info.intentHash, payload, executionData);

        emit CoordinationExecuted(jobId, info.intentHash, info.actionType);

        return (success, result);
    }

    /**
     * @notice Cancel a coordination.
     * @param jobId The job ID
     * @param reason Cancellation reason
     */
    function cancelCoordination(uint256 jobId, string calldata reason) external {
        CoordinationInfo memory info = jobCoordinations[jobId];
        if (!info.isActive) revert CoordinationNotFound();

        coordinationContract.cancelCoordination(info.intentHash, reason);

        // Note: We keep the state for audit trail (as per decision)
        // The coordination is marked as Cancelled in ERC-8001 contract
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Get coordination status for a job.
     * @param jobId The job ID
     * @return status The ERC-8001 status
     * @return actionType Complete or Reject
     * @return intentHash The coordination intent hash
     */
    function getJobCoordination(uint256 jobId)
        external
        view
        returns (IERC8001.Status status, ActionType actionType, bytes32 intentHash)
    {
        CoordinationInfo memory info = jobCoordinations[jobId];
        if (!info.isActive) {
            return (IERC8001.Status.None, ActionType.None, bytes32(0));
        }

        (status,,,,) = coordinationContract.getCoordinationStatus(info.intentHash);
        return (status, info.actionType, info.intentHash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Reads client, provider, and status from the ACP contract in a single
     *      staticcall. The Job struct contains a dynamic `string description` field
     *      so we decode positionally using fixed-size slots rather than relying on
     *      abi.decode with a string type (which requires a valid offset pointer).
     *
     *      ABI-encoded Job memory layout (each slot = 32 bytes):
     *        [0]  id          (uint256)
     *        [1]  client      (address, right-aligned)
     *        [2]  provider    (address, right-aligned)
     *        [3]  evaluator   (address, right-aligned)
     *        [4]  hook        (address, right-aligned)
     *        [5]  description (offset pointer to dynamic data)
     *        [6]  budget      (uint256)
     *        [7]  expiredAt   (uint256)
     *        [8]  status      (uint8, right-aligned in 32-byte slot)
     *
     *      The return value from getJob is the ABI encoding of a memory struct,
     *      which starts with a single offset word (0x20) before the tuple data.
     *      Total prefix before the first field: 32 bytes (the outer offset word).
     */
    function _getJobClientProviderStatus(uint256 jobId)
        internal
        view
        returns (address client, address provider, uint8 status)
    {
        (bool ok, bytes memory data) = acpContract.staticcall(abi.encodeWithSignature("getJob(uint256)", jobId));
        require(ok, "getJob failed");

        // data layout: [outer-offset(32)] [id(32)] [client(32)] [provider(32)] ... [status(32)]
        // Slot indices into data (each 32 bytes):
        //   slot 0 → outer offset (0x20)
        //   slot 1 → id
        //   slot 2 → client
        //   slot 3 → provider
        //   slot 9 → status  (slots 4-8: evaluator, hook, description-offset, budget, expiredAt)
        assembly {
            let base := add(data, 32) // skip the `bytes` length prefix
            client := mload(add(base, 64)) // slot 2 (1*32 outer-offset + 1*32 id + 0 = 64)
            provider := mload(add(base, 96)) // slot 3
            status := mload(add(base, 288)) // slot 9 (9*32 = 288)
        }
    }
}
