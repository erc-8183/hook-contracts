// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC8001 -- IAgentCoordination
 * @dev Interface for the ERC-8001 Agent Coordination Framework.
 *
 * ERC-8001 defines a minimal, single-chain primitive for multi-party agent coordination.
 * An initiator posts an intent and each participant provides a verifiable acceptance
 * attestation. Once the required set of acceptances is present and fresh, the intent
 * is executable.
 *
 * See https://eips.ethereum.org/EIPS/eip-8001
 */
interface IERC8001 {
    // ═══════════════════════════════════════════════════════════════════════════
    // ENUMS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Coordination lifecycle status.
     *
     * - None      = default zero state (intent not found)
     * - Proposed  = intent proposed, not all acceptances yet
     * - Ready     = all participants have accepted, intent executable
     * - Executed  = intent successfully executed
     * - Cancelled = intent explicitly cancelled
     * - Expired   = intent expired before execution
     */
    enum Status {
        None,
        Proposed,
        Ready,
        Executed,
        Cancelled,
        Expired
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // STRUCTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev The core intent structure signed by the proposer.
     * @param payloadHash       keccak256(CoordinationPayload)
     * @param expiry            Unix seconds; MUST be > block.timestamp at propose
     * @param nonce             Per-agent nonce; MUST be > agentNonces[agentId]
     * @param agentId           Initiator and signer of the intent
     * @param coordinationType  Domain-specific type id
     * @param coordinationValue Informational in Core; modules MAY bind value
     * @param participants      Unique, ascending; MUST include agentId
     */
    struct AgentIntent {
        bytes32 payloadHash;
        uint64 expiry;
        uint64 nonce;
        address agentId;
        bytes32 coordinationType;
        uint256 coordinationValue;
        address[] participants;
    }

    /**
     * @dev Coordination payload -- application-specific data.
     * @param version          Payload format id
     * @param coordinationType MUST equal AgentIntent.coordinationType
     * @param coordinationData Opaque to Core
     * @param conditionsHash   Domain-specific
     * @param timestamp        Creation time (informational)
     * @param metadata         Optional
     */
    struct CoordinationPayload {
        bytes32 version;
        bytes32 coordinationType;
        bytes coordinationData;
        bytes32 conditionsHash;
        uint256 timestamp;
        bytes metadata;
    }

    /**
     * @dev Acceptance attestation signed by each participant.
     * @param intentHash    getIntentHash(intent) -- the struct hash, not the digest
     * @param participant   Signer
     * @param nonce         Optional in Core; if used, MUST be strictly monotonic per participant
     * @param expiry        Acceptance validity; MUST be > now at accept and execute
     * @param conditionsHash Participant constraints
     * @param signature     ECDSA (65 or 64 bytes) or ERC-1271
     */
    struct AcceptanceAttestation {
        bytes32 intentHash;
        address participant;
        uint64 nonce;
        uint64 expiry;
        bytes32 conditionsHash;
        bytes signature;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Emitted when a new coordination is proposed.
     */
    event CoordinationProposed(
        bytes32 indexed intentHash,
        address indexed proposer,
        bytes32 coordinationType,
        uint256 participantCount,
        uint256 coordinationValue
    );

    /**
     * @dev Emitted when a participant accepts a coordination.
     */
    event CoordinationAccepted(
        bytes32 indexed intentHash,
        address indexed participant,
        bytes32 acceptanceHash,
        uint256 acceptedCount,
        uint256 requiredCount
    );

    /**
     * @dev Emitted when a coordination is executed.
     */
    event CoordinationExecuted(
        bytes32 indexed intentHash,
        address indexed executor,
        bool success,
        uint256 gasUsed,
        bytes result
    );

    /**
     * @dev Emitted when a coordination is cancelled.
     */
    event CoordinationCancelled(
        bytes32 indexed intentHash,
        address indexed canceller,
        string reason,
        uint8 finalStatus
    );

    // ═══════════════════════════════════════════════════════════════════════════
    // ERRORS
    // ═══════════════════════════════════════════════════════════════════════════

    error ERC8001_NotProposer();
    error ERC8001_ExpiredIntent();
    error ERC8001_ExpiredAcceptance(address participant);
    error ERC8001_BadSignature();
    error ERC8001_NotParticipant();
    error ERC8001_DuplicateAcceptance();
    error ERC8001_ParticipantsNotCanonical();
    error ERC8001_NonceTooLow();
    error ERC8001_PayloadHashMismatch();
    error ERC8001_NotReady();

    // ═══════════════════════════════════════════════════════════════════════════
    // CORE FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Propose a new multi-party coordination.
     * @dev The proposer MUST sign the intent using EIP-712.
     *      MUST revert if:
     *        - signature does not validate the AgentIntent under the ERC-8001 EIP-712 domain
     *        - intent.expiry <= block.timestamp
     *        - intent.nonce is not strictly greater than getAgentNonce(intent.agentId)
     *        - participants is not strictly ascending and unique
     *        - intent.agentId is not included in the participants list
     *      If valid:
     *        - CoordinationProposed MUST be emitted
     *        - getCoordinationStatus MUST report Proposed
     *        - getAgentNonce(intent.agentId) MUST equal the supplied nonce
     *        - getRequiredAcceptances(intentHash) MUST equal the number of participants
     *      Emits {CoordinationProposed}.
     * @param intent    The agent intent structure
     * @param signature EIP-712 signature from the proposer
     * @param payload   The coordination payload (hashed to verify against intent)
     * @return intentHash Unique identifier for this coordination
     */
    function proposeCoordination(
        AgentIntent calldata intent,
        bytes calldata signature,
        CoordinationPayload calldata payload
    ) external returns (bytes32 intentHash);

    /**
     * @notice Accept a proposed coordination.
     * @dev MUST revert if:
     *        - the intent does not exist or has expired
     *        - the caller is not listed as a participant
     *        - the participant has already accepted
     *        - the attestation signature does not validate under the ERC-8001 domain
     *        - attestation.expiry <= block.timestamp
     *      If valid:
     *        - CoordinationAccepted MUST be emitted
     *        - the participant MUST appear in the acceptedBy list
     *        - if all participants have accepted, return true and status MUST be Ready
     *        - otherwise return false
     *      Emits {CoordinationAccepted}.
     * @param intentHash  The coordination to accept
     * @param attestation The acceptance attestation (includes signature)
     * @return allAccepted True if all participants have now accepted
     */
    function acceptCoordination(bytes32 intentHash, AcceptanceAttestation calldata attestation)
    external
    returns (bool allAccepted);

    /**
     * @notice Execute a ready coordination.
     * @dev MUST revert if:
     *        - the intent is not in Ready state
     *        - intent.expiry <= block.timestamp
     *        - any acceptance has expired
     *        - the supplied payload does not hash to payloadHash
     *      If valid:
     *        - the implementation MUST attempt execution
     *        - MUST return (success, result)
     *        - CoordinationExecuted MUST be emitted
     *        - getCoordinationStatus MUST report Executed
     *      Emits {CoordinationExecuted}.
     * @param intentHash    The coordination to execute
     * @param payload       The coordination payload for execution logic
     * @param executionData Optional execution-specific data
     * @return success Whether execution succeeded
     * @return result  Return data from execution
     */
    function executeCoordination(
        bytes32 intentHash,
        CoordinationPayload calldata payload,
        bytes calldata executionData
    ) external returns (bool success, bytes memory result);

    /**
     * @notice Cancel a coordination.
     * @dev - If the intent has not expired, only the proposer MUST be permitted to cancel.
     *      - After expiry, any caller MUST be permitted to cancel.
     *      On success:
     *        - CoordinationCancelled MUST be emitted
     *        - status MUST be Cancelled
     *      Emits {CoordinationCancelled}.
     * @param intentHash The coordination to cancel
     * @param reason     Human-readable cancellation reason
     */
    function cancelCoordination(bytes32 intentHash, string calldata reason) external;

    // ═══════════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Get the current status of a coordination.
     * @dev MUST return:
     *      - None if the intent does not exist
     *      - Proposed if not all participants have accepted and the intent has not expired
     *      - Ready if all participants have accepted and expiries have not elapsed
     *      - Executed if execution has occurred
     *      - Cancelled if cancellation has occurred
     *      - Expired if the intent has expired and was not executed or cancelled
     * @param intentHash The coordination to query
     * @return status     Current lifecycle status
     * @return proposer   Address of the proposer
     * @return participants Required participants
     * @return acceptedBy  Participants who have accepted
     * @return expiry     Intent expiration timestamp
     */
    function getCoordinationStatus(bytes32 intentHash)
    external
    view
    returns (
        Status status,
        address proposer,
        address[] memory participants,
        address[] memory acceptedBy,
        uint256 expiry
    );

    /**
     * @notice Get the number of required acceptances.
     * @param intentHash The coordination to query
     * @return count Number of required acceptances (equals participant count)
     */
    function getRequiredAcceptances(bytes32 intentHash) external view returns (uint256 count);

    /**
     * @notice Get the current nonce for an agent.
     * @dev MUST increase for every valid new intent.
     * @param agent The agent address
     * @return nonce Current nonce value
     */
    function getAgentNonce(address agent) external view returns (uint64 nonce);

    /**
     * @notice Check if a participant has accepted a coordination.
     * @param intentHash  The coordination to check
     * @param participant The participant to check
     * @return hasAccepted True if the participant has accepted
     */
    function hasAccepted(bytes32 intentHash, address participant) external view returns (bool hasAccepted);

    /**
     * @notice Get the EIP-712 domain separator.
     * @return domainSeparator The domain separator hash
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32 domainSeparator);

    /**
     * @notice Get the EIP-712 struct hash for an AgentIntent.
     * @dev This returns the struct hash (not the full digest) as defined in the spec.
     *      Used for acceptance attestations and off-chain verification.
     * @param intent The agent intent structure
     * @return intentHash The EIP-712 struct hash of the intent
     */
    function getIntentHash(AgentIntent calldata intent) external pure returns (bytes32 intentHash);
}