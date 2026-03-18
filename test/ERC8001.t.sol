// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/erc8001/ERC8001.sol";
import "../contracts/erc8001/interfaces/IERC8001.sol";

/**
 * @title ERC8001Test
 * @dev Comprehensive test suite for ERC8001 base contract
 */
contract ERC8001Test is Test {
    ERC8001 public coordination;
    
    // Test accounts
    address public agent;
    address public participant1;
    address public participant2;
    address public participant3;
    uint256 public agentKey;
    uint256 public participant1Key;
    uint256 public participant2Key;
    uint256 public participant3Key;
    
    // Domain separator
    bytes32 public domainSeparator;
    
    // Type hashes
    bytes32 public constant AGENT_INTENT_TYPEHASH = keccak256(
        "AgentIntent(bytes32 payloadHash,uint64 expiry,uint64 nonce,address agentId,bytes32 coordinationType,uint256 coordinationValue,address[] participants)"
    );
    
    bytes32 public constant ACCEPTANCE_TYPEHASH = keccak256(
        "AcceptanceAttestation(bytes32 intentHash,address participant,uint64 nonce,uint64 expiry,bytes32 conditionsHash)"
    );

    function setUp() public {
        coordination = new ERC8001();
        
        // Create test accounts with private keys
        (agent, agentKey) = makeAddrAndKey("agent");
        (participant1, participant1Key) = makeAddrAndKey("participant1");
        (participant2, participant2Key) = makeAddrAndKey("participant2");
        (participant3, participant3Key) = makeAddrAndKey("participant3");
        
        // Fund accounts
        vm.deal(agent, 100 ether);
        vm.deal(participant1, 100 ether);
        vm.deal(participant2, 100 ether);
        vm.deal(participant3, 100 ether);
        
        // Get domain separator
        domainSeparator = coordination.DOMAIN_SEPARATOR();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    function _createParticipants() internal view returns (address[] memory) {
        address[] memory participants = new address[](3);
        // Must be sorted by uint160
        if (uint160(agent) < uint160(participant1)) {
            if (uint160(participant1) < uint160(participant2)) {
                participants[0] = agent;
                participants[1] = participant1;
                participants[2] = participant2;
            } else {
                participants[0] = agent;
                participants[1] = participant2;
                participants[2] = participant1;
            }
        } else {
            if (uint160(agent) < uint160(participant2)) {
                participants[0] = participant1;
                participants[1] = agent;
                participants[2] = participant2;
            } else {
                participants[0] = participant1;
                participants[1] = participant2;
                participants[2] = agent;
            }
        }
        return participants;
    }

    function _createAgentIntent(
        bytes32 payloadHash,
        uint64 expiry,
        uint64 nonce,
        bytes32 coordinationType,
        uint256 coordinationValue
    ) internal view returns (IERC8001.AgentIntent memory) {
        address[] memory participants = _createParticipants();
        
        return IERC8001.AgentIntent({
            payloadHash: payloadHash,
            expiry: expiry,
            nonce: nonce,
            agentId: agent,
            coordinationType: coordinationType,
            coordinationValue: coordinationValue,
            participants: participants
        });
    }

    function _hashAgentIntent(IERC8001.AgentIntent memory intent) internal pure returns (bytes32) {
        bytes32 participantsHash = keccak256(abi.encodePacked(intent.participants));
        return keccak256(abi.encode(
            AGENT_INTENT_TYPEHASH,
            intent.payloadHash,
            intent.expiry,
            intent.nonce,
            intent.agentId,
            intent.coordinationType,
            intent.coordinationValue,
            participantsHash
        ));
    }

    function _signIntent(
        uint256 privateKey,
        IERC8001.AgentIntent memory intent
    ) internal view returns (bytes memory) {
        bytes32 structHash = _hashAgentIntent(intent);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createAcceptanceAttestation(
        bytes32 intentHash,
        address participant,
        uint64 nonce,
        uint64 expiry,
        bytes32 conditionsHash
    ) internal pure returns (IERC8001.AcceptanceAttestation memory) {
        return IERC8001.AcceptanceAttestation({
            intentHash: intentHash,
            participant: participant,
            nonce: nonce,
            expiry: expiry,
            conditionsHash: conditionsHash,
            signature: "" // Will be filled later
        });
    }

    function _hashAcceptance(IERC8001.AcceptanceAttestation memory attestation) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            ACCEPTANCE_TYPEHASH,
            attestation.intentHash,
            attestation.participant,
            attestation.nonce,
            attestation.expiry,
            attestation.conditionsHash
        ));
    }

    function _signAcceptance(
        uint256 privateKey,
        IERC8001.AcceptanceAttestation memory attestation
    ) internal view returns (bytes memory) {
        bytes32 structHash = _hashAcceptance(attestation);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hashPayload(IERC8001.CoordinationPayload memory payload) internal pure returns (bytes32) {
        return keccak256(abi.encode(payload));
    }

    function _createPayload(
        bytes32 coordinationType,
        bytes memory coordinationData
    ) internal view returns (IERC8001.CoordinationPayload memory) {
        return IERC8001.CoordinationPayload({
            version: keccak256("1"),
            coordinationType: coordinationType,
            coordinationData: coordinationData,
            conditionsHash: bytes32(0),
            timestamp: block.timestamp,
            metadata: ""
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PROPOSE COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_ProposeCoordination_Success() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        uint256 coordinationValue = 1000;
        
        // Create payload first, then compute its hash
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "test data");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            coordinationValue
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Verify coordination was created
        (
            IERC8001.Status status,
            address proposer,
            address[] memory participants,
            address[] memory acceptedBy,
            uint256 storedExpiry
        ) = coordination.getCoordinationStatus(intentHash);
        
        assertEq(uint256(status), uint256(IERC8001.Status.Proposed));
        assertEq(proposer, agent);
        assertEq(storedExpiry, expiry);
        assertEq(participants.length, 3);
        assertEq(acceptedBy.length, 0);
        
        // Verify nonce was updated
        assertEq(coordination.getAgentNonce(agent), nonce);
    }

    function test_ProposeCoordination_Revert_ExpiredIntent() public {
        uint64 expiry = uint64(block.timestamp - 1); // Already expired
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        vm.expectRevert(IERC8001.ERC8001_ExpiredIntent.selector);
        coordination.proposeCoordination(intent, signature, payload);
    }

    function test_ProposeCoordination_Revert_NonceTooLow() public {
        // First proposal with nonce 1
        test_ProposeCoordination_Success();
        
        // Try to propose with nonce 1 again
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1; // Same nonce
        bytes32 coordinationType = keccak256("TEST_COORDINATION_2");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        vm.expectRevert(IERC8001.ERC8001_NonceTooLow.selector);
        coordination.proposeCoordination(intent, signature, payload);
    }

    function test_ProposeCoordination_Revert_ParticipantsNotCanonical() public {
        // Create non-canonical participants (not sorted)
        address[] memory participants = new address[](3);
        participants[0] = participant2; // Not sorted
        participants[1] = agent;
        participants[2] = participant1;
        
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = IERC8001.AgentIntent({
            payloadHash: payloadHash,
            expiry: expiry,
            nonce: nonce,
            agentId: agent,
            coordinationType: coordinationType,
            coordinationValue: 0,
            participants: participants
        });
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        vm.expectRevert(IERC8001.ERC8001_ParticipantsNotCanonical.selector);
        coordination.proposeCoordination(intent, signature, payload);
    }

    function test_ProposeCoordination_Revert_AgentNotInParticipants() public {
        // Create participants without agent
        address[] memory participants = new address[](2);
        participants[0] = participant1;
        participants[1] = participant2;
        
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = IERC8001.AgentIntent({
            payloadHash: payloadHash,
            expiry: expiry,
            nonce: nonce,
            agentId: agent,
            coordinationType: coordinationType,
            coordinationValue: 0,
            participants: participants
        });
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        vm.expectRevert(IERC8001.ERC8001_NotParticipant.selector);
        coordination.proposeCoordination(intent, signature, payload);
    }

    function test_ProposeCoordination_Revert_PayloadHashMismatch() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        
        // Create payload with one set of data for hashing
        IERC8001.CoordinationPayload memory payloadForHash = _createPayload(coordinationType, "original data");
        bytes32 payloadHash = _hashPayload(payloadForHash);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        // Create payload with different data for submission
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "different data");
        
        vm.prank(agent);
        vm.expectRevert(IERC8001.ERC8001_PayloadHashMismatch.selector);
        coordination.proposeCoordination(intent, signature, payload);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACCEPT COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_AcceptCoordination_Success() public {
        // First propose
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Now accept as participant1
        IERC8001.AcceptanceAttestation memory attestation = _createAcceptanceAttestation(
            intentHash,
            participant1,
            1,
            uint64(block.timestamp + 30 minutes),
            bytes32(0)
        );
        
        bytes memory attestationSig = _signAcceptance(participant1Key, attestation);
        attestation.signature = attestationSig;
        
        vm.prank(participant1);
        bool allAccepted = coordination.acceptCoordination(intentHash, attestation);
        
        assertFalse(allAccepted); // Not all accepted yet
        
        // Verify acceptance was recorded
        assertTrue(coordination.hasAccepted(intentHash, participant1));
    }

    function test_AcceptCoordination_AllAccepted() public {
        // Propose coordination
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 1;
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Get participants
        (,, address[] memory participants,,) = coordination.getCoordinationStatus(intentHash);
        
        // Accept as all participants
        for (uint i = 0; i < participants.length; i++) {
            address participant = participants[i];
            uint256 key;
            
            if (participant == agent) key = agentKey;
            else if (participant == participant1) key = participant1Key;
            else if (participant == participant2) key = participant2Key;
            else continue;
            
            IERC8001.AcceptanceAttestation memory attestation = _createAcceptanceAttestation(
                intentHash,
                participant,
                1,
                uint64(block.timestamp + 30 minutes),
                bytes32(0)
            );
            
            bytes memory attestationSig = _signAcceptance(key, attestation);
            attestation.signature = attestationSig;
            
            vm.prank(participant);
            bool allAccepted = coordination.acceptCoordination(intentHash, attestation);
            
            if (i == participants.length - 1) {
                assertTrue(allAccepted);
                
                // Verify status is Ready
                (IERC8001.Status status,,,,) = coordination.getCoordinationStatus(intentHash);
                assertEq(uint256(status), uint256(IERC8001.Status.Ready));
            } else {
                assertFalse(allAccepted);
            }
        }
    }

    function test_AcceptCoordination_Revert_NotParticipant() public {
        // Propose coordination
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Try to accept as non-participant (participant3)
        address nonParticipant = makeAddr("nonParticipant");
        IERC8001.AcceptanceAttestation memory attestation = _createAcceptanceAttestation(
            intentHash,
            nonParticipant,
            1,
            uint64(block.timestamp + 30 minutes),
            bytes32(0)
        );
        
        // Sign with a random key
        (, uint256 randomKey) = makeAddrAndKey("random");
        bytes memory attestationSig = _signAcceptance(randomKey, attestation);
        attestation.signature = attestationSig;
        
        vm.prank(nonParticipant);
        vm.expectRevert(IERC8001.ERC8001_NotParticipant.selector);
        coordination.acceptCoordination(intentHash, attestation);
    }

    function test_AcceptCoordination_Revert_DuplicateAcceptance() public {
        // Propose and accept once
        test_AcceptCoordination_Success();
        
        // Get the intentHash from previous test
        // We need to re-propose to get a fresh intentHash
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 nonce = 2;
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            nonce,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Accept once
        IERC8001.AcceptanceAttestation memory attestation = _createAcceptanceAttestation(
            intentHash,
            participant1,
            1,
            uint64(block.timestamp + 30 minutes),
            bytes32(0)
        );
        
        bytes memory attestationSig = _signAcceptance(participant1Key, attestation);
        attestation.signature = attestationSig;
        
        vm.prank(participant1);
        coordination.acceptCoordination(intentHash, attestation);
        
        // Try to accept again
        vm.prank(participant1);
        vm.expectRevert(IERC8001.ERC8001_DuplicateAcceptance.selector);
        coordination.acceptCoordination(intentHash, attestation);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXECUTE COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_ExecuteCoordination_Success() public {
        // Propose and accept all
        test_AcceptCoordination_AllAccepted();
        
        // Get the intentHash using the same parameters as the proposal
        bytes32 coordinationType = keccak256("TEST_COORDINATION");
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            uint64(block.timestamp + 1 hours),
            1,
            coordinationType,
            0
        );
        bytes32 intentHash = coordination.getIntentHash(intent);
        
        // Execute
        vm.prank(agent);
        (bool success, bytes memory result) = coordination.executeCoordination(
            intentHash,
            payload,
            ""
        );
        
        assertTrue(success);
        
        // Verify status is Executed
        (IERC8001.Status status,,,,) = coordination.getCoordinationStatus(intentHash);
        assertEq(uint256(status), uint256(IERC8001.Status.Executed));
    }

    function test_ExecuteCoordination_Revert_NotReady() public {
        // Propose but don't accept
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Try to execute without all acceptances
        vm.prank(agent);
        vm.expectRevert(IERC8001.ERC8001_NotReady.selector);
        coordination.executeCoordination(intentHash, payload, "");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CANCEL COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_CancelCoordination_BeforeExpiry_ProposerOnly() public {
        // Propose
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Cancel as proposer
        vm.prank(agent);
        coordination.cancelCoordination(intentHash, "Test cancellation");
        
        // Verify status is Cancelled
        (IERC8001.Status status,,,,) = coordination.getCoordinationStatus(intentHash);
        assertEq(uint256(status), uint256(IERC8001.Status.Cancelled));
    }

    function test_CancelCoordination_BeforeExpiry_NonProposerReverts() public {
        // Propose
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Try to cancel as non-proposer
        vm.prank(participant1);
        vm.expectRevert(IERC8001.ERC8001_NotProposer.selector);
        coordination.cancelCoordination(intentHash, "Test cancellation");
    }

    function test_CancelCoordination_AfterExpiry_AnyoneCanCancel() public {
        // Propose
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Warp past expiry
        vm.warp(block.timestamp + 2 hours);
        
        // Cancel as non-proposer (should work after expiry)
        vm.prank(participant1);
        coordination.cancelCoordination(intentHash, "Test cancellation after expiry");
        
        // Verify status is Cancelled
        (IERC8001.Status status,,,,) = coordination.getCoordinationStatus(intentHash);
        assertEq(uint256(status), uint256(IERC8001.Status.Cancelled));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_GetIntentHash() public {
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            keccak256("payload"),
            uint64(block.timestamp + 1 hours),
            1,
            keccak256("TEST"),
            1000
        );
        
        bytes32 hashFromContract = coordination.getIntentHash(intent);
        bytes32 hashFromTest = _hashAgentIntent(intent);
        
        assertEq(hashFromContract, hashFromTest);
    }

    function test_GetRequiredAcceptances() public {
        // Propose
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        uint256 required = coordination.getRequiredAcceptances(intentHash);
        assertEq(required, 3); // agent, participant1, participant2
    }

    function test_ExpiredStatus() public {
        // Propose with short expiry
        uint64 expiry = uint64(block.timestamp + 10 minutes);
        bytes32 coordinationType = keccak256("TEST");
        
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);
        
        IERC8001.AgentIntent memory intent = _createAgentIntent(
            payloadHash,
            expiry,
            1,
            coordinationType,
            0
        );
        
        bytes memory signature = _signIntent(agentKey, intent);
        
        vm.prank(agent);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);
        
        // Warp past expiry
        vm.warp(block.timestamp + 11 minutes);
        
        // Check status shows Expired
        (IERC8001.Status status,,,,) = coordination.getCoordinationStatus(intentHash);
        assertEq(uint256(status), uint256(IERC8001.Status.Expired));
    }
}
