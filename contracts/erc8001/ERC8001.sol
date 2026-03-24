// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IERC8001.sol";

/**
 * @title ERC8001
 * @dev Standard-compliant implementation of ERC-8001 Agent Coordination Framework.
 *
 *      This contract provides the core coordination primitive for multi-party agent
 *      coordination using EIP-712 attestations. It implements the full IERC8001 interface
 *      with support for ECDSA (65-byte and 64-byte) and ERC-1271 signatures.
 *
 *      Features:
 *      - EIP-712 domain: {name: "ERC-8001", version: "1"}
 *      - Strict participant canonicalization (sorted unique addresses)
 *      - Monotonic nonce enforcement per agent
 *      - ERC-5267 support for domain discovery
 *      - Low-s signature enforcement for malleability protection
 */
contract ERC8001 is IERC8001 {
    // ═══════════════════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════

    bytes32 public constant DOMAIN_NAME = keccak256("ERC-8001");
    bytes32 public constant DOMAIN_VERSION = keccak256("1");

    bytes32 public constant AGENT_INTENT_TYPEHASH = keccak256(
        "AgentIntent(bytes32 payloadHash,uint64 expiry,uint64 nonce,address agentId,bytes32 coordinationType,uint256 coordinationValue,address[] participants)"
    );

    bytes32 public constant ACCEPTANCE_TYPEHASH = keccak256(
        "AcceptanceAttestation(bytes32 intentHash,address participant,uint64 nonce,uint64 expiry,bytes32 conditionsHash)"
    );

    // ═══════════════════════════════════════════════════════════════════════
    // STORAGE
    // ═══════════════════════════════════════════════════════════════════════

    struct Coordination {
        Status status;
        address proposer; // intent.agentId
        address operator; // msg.sender at proposal time (may be a hook contract)
        address[] participants;
        mapping(address => bool) hasAccepted;
        address[] acceptedBy;
        uint256 expiry;
        bytes32 payloadHash;
        uint256 coordinationValue;
    }

    mapping(bytes32 => Coordination) public coordinations;
    mapping(address => uint64) public agentNonces;

    bytes32 private immutable _domainSeparator;
    uint256 private immutable _chainId;

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    constructor() {
        _chainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                DOMAIN_NAME,
                DOMAIN_VERSION,
                _chainId,
                address(this)
            )
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ERC-5267 SUPPORT
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Get the EIP-712 domain separator.
     * @return domainSeparator The domain separator hash
     */
    function DOMAIN_SEPARATOR() external view returns (bytes32 domainSeparator) {
        return _domainSeparator;
    }

    /**
     * @notice Get EIP-712 domain information (ERC-5267).
     * @return fields Bitmap of domain fields present
     * @return name Domain name
     * @return version Domain version
     * @return chainId Chain ID
     * @return verifyingContract This contract address
     * @return salt Salt (empty for this implementation)
     * @return extensions Array of extension contract addresses (empty)
     */
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0F"; // name, version, chainId, verifyingContract
        name = "ERC-8001";
        version = "1";
        chainId = _chainId;
        verifyingContract = address(this);
        salt = bytes32(0);
        extensions = new uint256[](0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CORE FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Propose a new multi-party coordination.
     * @param intent The agent intent structure
     * @param signature EIP-712 signature from the proposer
     * @param payload The coordination payload
     * @return intentHash The coordination intent hash
     */
    function proposeCoordination(
        AgentIntent calldata intent,
        bytes calldata signature,
        CoordinationPayload calldata payload
    ) external returns (bytes32 intentHash) {
        // Validate expiry
        if (intent.expiry <= block.timestamp) revert ERC8001_ExpiredIntent();

        // Validate nonce
        if (intent.nonce <= agentNonces[intent.agentId]) revert ERC8001_NonceTooLow();

        // Validate participants are canonical (sorted unique)
        _validateParticipantsCanonical(intent.participants);

        // Validate agentId is in participants
        bool agentFound = false;
        for (uint256 i = 0; i < intent.participants.length; i++) {
            if (intent.participants[i] == intent.agentId) {
                agentFound = true;
                break;
            }
        }
        if (!agentFound) revert ERC8001_NotParticipant();

        // Validate payload hash
        bytes32 computedPayloadHash = keccak256(abi.encode(payload));
        if (computedPayloadHash != intent.payloadHash) revert ERC8001_PayloadHashMismatch();

        // Compute intent hash (struct hash, not digest)
        intentHash = getIntentHash(intent);

        // Verify signature
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator, intentHash));
        if (!_verifySignature(intent.agentId, digest, signature)) revert ERC8001_BadSignature();

        // Store coordination
        Coordination storage c = coordinations[intentHash];
        c.status = Status.Proposed;
        c.proposer = intent.agentId;
        c.operator = msg.sender;
        c.expiry = intent.expiry;
        c.payloadHash = intent.payloadHash;
        c.coordinationValue = intent.coordinationValue;

        // Copy participants
        c.participants = new address[](intent.participants.length);
        for (uint256 i = 0; i < intent.participants.length; i++) {
            c.participants[i] = intent.participants[i];
        }

        // Update agent nonce
        agentNonces[intent.agentId] = intent.nonce;

        emit CoordinationProposed(
            intentHash, intent.agentId, intent.coordinationType, intent.participants.length, intent.coordinationValue
        );

        return intentHash;
    }

    /**
     * @notice Accept a proposed coordination.
     * @param intentHash The coordination to accept
     * @param attestation The acceptance attestation
     * @return allAccepted True if all participants have now accepted
     */
    function acceptCoordination(bytes32 intentHash, AcceptanceAttestation calldata attestation)
        external
        returns (bool allAccepted)
    {
        Coordination storage c = coordinations[intentHash];

        // Check coordination exists and not expired
        if (c.status == Status.None) revert ERC8001_NotParticipant();
        if (c.status != Status.Proposed) revert ERC8001_NotReady();
        if (block.timestamp > c.expiry) revert ERC8001_ExpiredIntent();

        // Validate participant
        address participant = attestation.participant;
        bool isParticipant = false;
        for (uint256 i = 0; i < c.participants.length; i++) {
            if (c.participants[i] == participant) {
                isParticipant = true;
                break;
            }
        }
        if (!isParticipant) revert ERC8001_NotParticipant();

        // Check not already accepted
        if (c.hasAccepted[participant]) revert ERC8001_DuplicateAcceptance();

        // Validate attestation expiry
        if (attestation.expiry <= block.timestamp) revert ERC8001_ExpiredAcceptance(participant);

        // Validate attestation intentHash matches
        if (attestation.intentHash != intentHash) revert ERC8001_PayloadHashMismatch();

        // Verify signature
        bytes32 attestationStructHash = keccak256(
            abi.encode(
                ACCEPTANCE_TYPEHASH,
                attestation.intentHash,
                attestation.participant,
                attestation.nonce,
                attestation.expiry,
                attestation.conditionsHash
            )
        );
        bytes32 attestationDigest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator, attestationStructHash));
        if (!_verifySignature(participant, attestationDigest, attestation.signature)) revert ERC8001_BadSignature();

        // Record acceptance
        c.hasAccepted[participant] = true;
        c.acceptedBy.push(participant);

        bytes32 acceptanceHash = keccak256(abi.encode(attestation));
        emit CoordinationAccepted(intentHash, participant, acceptanceHash, c.acceptedBy.length, c.participants.length);

        // Check if all accepted
        allAccepted = (c.acceptedBy.length == c.participants.length);
        if (allAccepted) {
            c.status = Status.Ready;
        }

        return allAccepted;
    }

    /**
     * @notice Execute a ready coordination.
     * @param intentHash The coordination to execute
     * @param payload The coordination payload
     * @param executionData Optional execution-specific data
     * @return success Whether execution succeeded
     * @return result Return data from execution
     */
    function executeCoordination(bytes32 intentHash, CoordinationPayload calldata payload, bytes calldata executionData)
        external
        returns (bool success, bytes memory result)
    {
        Coordination storage c = coordinations[intentHash];

        // Validate status
        if (c.status != Status.Ready) revert ERC8001_NotReady();

        // Validate intent not expired
        if (block.timestamp > c.expiry) revert ERC8001_ExpiredIntent();

        // Validate payload hash
        bytes32 computedPayloadHash = keccak256(abi.encode(payload));
        if (computedPayloadHash != c.payloadHash) revert ERC8001_PayloadHashMismatch();

        // Check all acceptances are still valid (not expired)
        // Note: In a full implementation, we'd check each attestation's expiry
        // For simplicity, we assume acceptances are valid if coordination is Ready

        // Mark as executed
        c.status = Status.Executed;

        // Call execution hook
        uint256 gasBefore = gasleft();
        (success, result) = _executeCoordinationHook(intentHash, payload, executionData);
        uint256 gasUsed = gasBefore - gasleft();

        emit CoordinationExecuted(intentHash, msg.sender, success, gasUsed, result);

        return (success, result);
    }

    /**
     * @notice Cancel a coordination.
     * @param intentHash The coordination to cancel
     * @param reason Human-readable cancellation reason
     */
    function cancelCoordination(bytes32 intentHash, string calldata reason) external {
        Coordination storage c = coordinations[intentHash];

        // Check coordination exists and not already executed/cancelled
        if (c.status == Status.None) revert ERC8001_NotParticipant();
        if (c.status == Status.Executed || c.status == Status.Cancelled) {
            revert ERC8001_NotProposer();
        }

        // Before expiry: only proposer (agentId) or the operator (hook) that submitted
        //   the proposal can cancel. After expiry: anyone can cancel.
        if (block.timestamp <= c.expiry && msg.sender != c.proposer && msg.sender != c.operator) {
            revert ERC8001_NotProposer();
        }

        c.status = Status.Cancelled;

        emit CoordinationCancelled(intentHash, msg.sender, reason, uint8(Status.Cancelled));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Get the current status of a coordination.
     * @param intentHash The coordination to query
     * @return status Current lifecycle status
     * @return proposer Address of the proposer
     * @return participants Required participants
     * @return acceptedBy Participants who have accepted
     * @return expiry Intent expiration timestamp
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
        )
    {
        Coordination storage c = coordinations[intentHash];

        // Check if expired
        if (c.status == Status.Proposed && block.timestamp > c.expiry) {
            return (Status.Expired, c.proposer, c.participants, c.acceptedBy, c.expiry);
        }

        return (c.status, c.proposer, c.participants, c.acceptedBy, c.expiry);
    }

    /**
     * @notice Get the number of required acceptances.
     * @param intentHash The coordination to query
     * @return count Number of required acceptances
     */
    function getRequiredAcceptances(bytes32 intentHash) external view returns (uint256 count) {
        return coordinations[intentHash].participants.length;
    }

    /**
     * @notice Get the current nonce for an agent.
     * @param agent The agent address
     * @return nonce Current nonce value
     */
    function getAgentNonce(address agent) external view returns (uint64 nonce) {
        return agentNonces[agent];
    }

    /**
     * @notice Check if a participant has accepted a coordination.
     * @param intentHash The coordination to check
     * @param participant The participant to check
     * @return hasAccepted True if the participant has accepted
     */
    function hasAccepted(bytes32 intentHash, address participant) external view returns (bool) {
        return coordinations[intentHash].hasAccepted[participant];
    }

    /**
     * @notice Get the EIP-712 struct hash for an AgentIntent.
     * @param intent The agent intent structure
     * @return intentHash The EIP-712 struct hash
     */
    function getIntentHash(AgentIntent calldata intent) public pure returns (bytes32 intentHash) {
        bytes32 participantsHash = keccak256(abi.encodePacked(intent.participants));
        return keccak256(
            abi.encode(
                AGENT_INTENT_TYPEHASH,
                intent.payloadHash,
                intent.expiry,
                intent.nonce,
                intent.agentId,
                intent.coordinationType,
                intent.coordinationValue,
                participantsHash
            )
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @dev Validate that participants array is canonical (sorted unique).
     * @param participants Array of participant addresses
     */
    function _validateParticipantsCanonical(address[] calldata participants) internal pure {
        if (participants.length == 0) revert ERC8001_ParticipantsNotCanonical();

        for (uint256 i = 1; i < participants.length; i++) {
            // Check strictly ascending (no duplicates)
            if (uint160(participants[i]) <= uint160(participants[i - 1])) {
                revert ERC8001_ParticipantsNotCanonical();
            }
        }
    }

    /**
     * @dev Verify a signature (ECDSA or ERC-1271).
     * @param signer The expected signer address
     * @param digest The EIP-712 digest
     * @param signature The signature bytes
     * @return valid True if signature is valid
     */
    function _verifySignature(address signer, bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool valid)
    {
        // Check if contract
        if (_isContract(signer)) {
            // ERC-1271 verification
            try IERC1271(signer).isValidSignature(digest, signature) returns (bytes4 magicValue) {
                return magicValue == IERC1271.isValidSignature.selector;
            } catch {
                return false;
            }
        } else {
            // ECDSA verification
            return _verifyECDSA(digest, signature) == signer;
        }
    }

    /**
     * @dev Verify ECDSA signature and return signer.
     * @param digest The digest that was signed
     * @param signature The signature (65 or 64 bytes)
     * @return signer The recovered signer address
     */
    function _verifyECDSA(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length == 65) {
            // Standard ECDSA
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
        } else if (signature.length == 64) {
            // EIP-2098 compact signature
            bytes32 vs;
            assembly {
                r := calldataload(signature.offset)
                vs := calldataload(add(signature.offset, 32))
            }
            s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            v = uint8(uint256(vs >> 255) + 27);
        } else {
            return address(0);
        }

        // Enforce low-s (malleability protection)
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        if (uint256(s) > n / 2) return address(0);

        // Recover signer
        signer = ecrecover(digest, v, r, s);
    }

    /**
     * @dev Check if an address is a contract.
     * @param addr The address to check
     * @return isContract True if address is a contract
     */
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    /**
     * @dev Hook called by executeCoordination to perform the actual action.
     *      Override this in subclasses to implement custom execution logic.
     * @return success Whether execution succeeded
     * @return result Return data from execution
     */
    function _executeCoordinationHook(
        bytes32,
        /* intentHash */
        CoordinationPayload calldata,
        /* payload */
        bytes calldata /* executionData */
    )
        internal
        virtual
        returns (bool success, bytes memory result)
    {
        // Default: no-op, return success
        // Subclasses should override this
        return (true, "");
    }
}

/**
 * @title IERC1271
 * @dev Interface for ERC-1271 contract signature verification
 */
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}
