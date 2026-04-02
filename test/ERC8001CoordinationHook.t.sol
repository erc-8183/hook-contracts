// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/AgenticCommerceHooked.sol";
import "../contracts/hooks/ERC8001CoordinationHook.sol";
import "../contracts/erc8001/ERC8001.sol";
import "../contracts/erc8001/interfaces/IERC8001.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockERC20
 * @dev Simple ERC20 token for testing
 */
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title ERC8001CoordinationHookTest
 * @dev Comprehensive test suite for ERC8001CoordinationHook
 */
contract ERC8001CoordinationHookTest is Test {
    AgenticCommerceHooked public acp;
    ERC8001CoordinationHook public hook;
    ERC8001 public coordination;
    MockERC20 public token;

    // Test accounts
    address public client;
    address public provider;
    address public evaluator;
    address public arbiter;
    address public treasury;
    uint256 public clientKey;
    uint256 public providerKey;
    uint256 public evaluatorKey;
    uint256 public arbiterKey;

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
        // Deploy contracts
        token = new MockERC20("Test Token", "TEST");
        treasury = makeAddr("treasury");
        acp = new AgenticCommerceHooked(address(token), treasury);
        coordination = new ERC8001();
        hook = new ERC8001CoordinationHook(address(acp), address(coordination));

        // Create test accounts
        (client, clientKey) = makeAddrAndKey("client");
        (provider, providerKey) = makeAddrAndKey("provider");
        (evaluator, evaluatorKey) = makeAddrAndKey("evaluator");
        (arbiter, arbiterKey) = makeAddrAndKey("arbiter");

        // Fund accounts
        vm.deal(client, 100 ether);
        vm.deal(provider, 100 ether);
        vm.deal(evaluator, 100 ether);
        vm.deal(arbiter, 100 ether);

        // Mint tokens
        token.mint(client, 100000 * 10 ** 18);
        token.mint(provider, 100000 * 10 ** 18);

        // Approve tokens
        vm.prank(client);
        token.approve(address(acp), type(uint256).max);
        vm.prank(provider);
        token.approve(address(acp), type(uint256).max);

        // Get domain separator
        domainSeparator = coordination.DOMAIN_SEPARATOR();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    function _createParticipants() internal view returns (address[] memory) {
        address[] memory participants = new address[](4);
        address[4] memory addrs = [client, provider, evaluator, arbiter];

        // Sort by uint160
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = i + 1; j < 4; j++) {
                if (uint160(addrs[j]) < uint160(addrs[i])) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                }
            }
        }

        for (uint256 i = 0; i < 4; i++) {
            participants[i] = addrs[i];
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
            agentId: client,
            coordinationType: coordinationType,
            coordinationValue: coordinationValue,
            participants: participants
        });
    }

    function _hashAgentIntent(IERC8001.AgentIntent memory intent) internal pure returns (bytes32) {
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

    function _signIntent(uint256 privateKey, IERC8001.AgentIntent memory intent) internal view returns (bytes memory) {
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
            signature: ""
        });
    }

    function _hashAcceptance(IERC8001.AcceptanceAttestation memory attestation) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ACCEPTANCE_TYPEHASH,
                attestation.intentHash,
                attestation.participant,
                attestation.nonce,
                attestation.expiry,
                attestation.conditionsHash
            )
        );
    }

    function _signAcceptance(uint256 privateKey, IERC8001.AcceptanceAttestation memory attestation)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = _hashAcceptance(attestation);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hashPayload(IERC8001.CoordinationPayload memory payload) internal pure returns (bytes32) {
        return keccak256(abi.encode(payload));
    }

    function _createPayload(bytes32 coordinationType, bytes memory coordinationData)
        internal
        view
        returns (IERC8001.CoordinationPayload memory)
    {
        return IERC8001.CoordinationPayload({
            version: keccak256("1"),
            coordinationType: coordinationType,
            coordinationData: coordinationData,
            conditionsHash: bytes32(0),
            timestamp: block.timestamp,
            metadata: ""
        });
    }

    function _createJobWithHook() internal returns (uint256 jobId) {
        uint256 budget = 1000 * 10 ** 18;
        uint256 expiry = block.timestamp + 1 days;

        vm.prank(client);
        jobId = acp.createJob(provider, evaluator, expiry, "Test job", address(hook));

        // Set budget
        vm.prank(client);
        acp.setBudget(jobId, budget, "");

        // Fund job
        vm.prank(client);
        acp.fund(jobId, budget, "");

        return jobId;
    }

    function _getParticipantKey(address participant) internal view returns (uint256) {
        if (participant == client) return clientKey;
        if (participant == provider) return providerKey;
        if (participant == evaluator) return evaluatorKey;
        if (participant == arbiter) return arbiterKey;
        return 0;
    }

    function _acceptAsParticipant(uint256 jobId, address participant, bytes32 intentHash) internal {
        uint256 key = _getParticipantKey(participant);
        if (key == 0) return;

        IERC8001.AcceptanceAttestation memory attestation =
            _createAcceptanceAttestation(intentHash, participant, 1, uint64(block.timestamp + 30 minutes), bytes32(0));

        bytes memory attestationSig = _signAcceptance(key, attestation);
        attestation.signature = attestationSig;

        vm.prank(participant);
        hook.acceptCoordination(jobId, attestation);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PROPOSE COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_ProposeCoordination_Success() public {
        uint256 jobId = _createJobWithHook();

        // Submit work
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // Propose coordination
        bytes32 coordinationType = hook.COORDINATION_COMPLETE();
        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent =
            _createAgentIntent(payloadHash, uint64(block.timestamp + 1 hours), 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        bytes32 intentHash =
            hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Complete);

        // Verify coordination was created
        (IERC8001.Status status, ERC8001CoordinationHook.ActionType actionType, bytes32 storedIntentHash) =
            hook.getJobCoordination(jobId);

        assertEq(uint256(status), uint256(IERC8001.Status.Proposed));
        assertEq(uint256(actionType), uint256(ERC8001CoordinationHook.ActionType.Complete));
        assertEq(storedIntentHash, intentHash);
    }

    function test_ProposeCoordination_Revert_NotClientOrProvider() public {
        uint256 jobId = _createJobWithHook();

        // Submit work
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // Try to propose as evaluator (not allowed)
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_COMPLETE();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(evaluator);
        vm.expectRevert(ERC8001CoordinationHook.OnlyClientOrProvider.selector);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Complete);
    }

    function test_ProposeCoordination_Revert_JobNotSubmitted() public {
        // Create job but don't submit
        uint256 jobId = _createJobWithHook();

        // Try to propose before submit
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_COMPLETE();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        vm.expectRevert(ERC8001CoordinationHook.JobNotInSubmittedState.selector);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Complete);
    }

    function test_ProposeCoordination_Revert_AlreadyExists() public {
        // Propose once
        test_ProposeCoordination_Success();

        uint256 jobId = 1;

        // Try to propose again
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_COMPLETE();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 2, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        vm.expectRevert(ERC8001CoordinationHook.CoordinationAlreadyExists.selector);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Complete);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACCEPT COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_AcceptCoordination_Success() public {
        // Propose coordination
        test_ProposeCoordination_Success();

        uint256 jobId = 1;
        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        // Accept as participant1 (client)
        IERC8001.AcceptanceAttestation memory attestation =
            _createAcceptanceAttestation(intentHash, client, 1, uint64(block.timestamp + 30 minutes), bytes32(0));

        bytes memory attestationSig = _signAcceptance(clientKey, attestation);
        attestation.signature = attestationSig;

        vm.prank(client);
        bool allAccepted = hook.acceptCoordination(jobId, attestation);

        assertFalse(allAccepted);
    }

    function test_AcceptCoordination_AllAccepted() public {
        // Propose coordination
        test_ProposeCoordination_Success();

        uint256 jobId = 1;
        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        // Get participants
        (,, address[] memory participants,,) = coordination.getCoordinationStatus(intentHash);

        // Accept as all participants
        for (uint256 i = 0; i < participants.length; i++) {
            _acceptAsParticipant(jobId, participants[i], intentHash);
        }

        // Verify status is Ready
        (IERC8001.Status status,,) = hook.getJobCoordination(jobId);
        assertEq(uint256(status), uint256(IERC8001.Status.Ready));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EXECUTE COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_ExecuteCoordination_Success() public {
        // Accept all
        test_AcceptCoordination_AllAccepted();

        uint256 jobId = 1;
        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        // Get the coordination type from the stored action
        bytes32 coordinationType = actionType == ERC8001CoordinationHook.ActionType.Complete
            ? hook.COORDINATION_COMPLETE()
            : hook.COORDINATION_REJECT();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");

        vm.prank(client);
        (bool success,) = hook.executeCoordination(jobId, payload, "");

        assertTrue(success);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HOOK CALLBACK TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_PreComplete_AllowsWhenCoordinationReady() public {
        // Execute coordination (marks as Ready)
        test_ExecuteCoordination_Success();

        uint256 jobId = 1;

        // Complete should succeed
        vm.prank(evaluator);
        acp.complete(jobId, keccak256("reason"), "");

        // Verify job is completed
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint256(job.status), uint256(AgenticCommerceHooked.JobStatus.Completed));
    }

    function test_PreComplete_RevertsWhenCoordinationNotReady() public {
        // Propose but don't execute
        test_ProposeCoordination_Success();

        uint256 jobId = 1;

        // Complete should revert
        vm.prank(evaluator);
        vm.expectRevert(ERC8001CoordinationHook.CoordinationNotReady.selector);
        acp.complete(jobId, keccak256("reason"), "");
    }

    function test_PreComplete_AllowsWithoutCoordination() public {
        // Create job without hook
        uint256 budget = 1000 * 10 ** 18;
        uint256 expiry = block.timestamp + 1 days;

        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, expiry, "Test job", address(0));

        // Set budget and fund
        vm.prank(client);
        acp.setBudget(jobId, budget, "");
        vm.prank(client);
        acp.fund(jobId, budget, "");

        // Submit
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // Complete should succeed (no coordination required)
        vm.prank(evaluator);
        acp.complete(jobId, keccak256("reason"), "");

        // Verify job is completed
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint256(job.status), uint256(AgenticCommerceHooked.JobStatus.Completed));
    }

    function test_PreReject_AllowsWhenCoordinationReady() public {
        // Propose reject coordination
        uint256 jobId = _createJobWithHook();

        // Submit work
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // Propose reject coordination
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_REJECT();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Reject);

        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        // Accept all
        (,, address[] memory participants,,) = coordination.getCoordinationStatus(intentHash);

        for (uint256 i = 0; i < participants.length; i++) {
            _acceptAsParticipant(jobId, participants[i], intentHash);
        }

        // Execute
        vm.prank(client);
        hook.executeCoordination(jobId, payload, "");

        // Reject should succeed
        vm.prank(evaluator);
        acp.reject(jobId, keccak256("reason"), "");

        // Verify job is rejected
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint256(job.status), uint256(AgenticCommerceHooked.JobStatus.Rejected));
    }

    function test_PreComplete_AllowsWhenCoordinationIsForReject() public {
        // Propose reject coordination
        uint256 jobId = _createJobWithHook();

        // Submit work
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // Propose reject coordination
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_REJECT();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Reject);

        // Complete should succeed (coordination is for reject, not complete)
        vm.prank(evaluator);
        acp.complete(jobId, keccak256("reason"), "");

        // Verify job is completed
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint256(job.status), uint256(AgenticCommerceHooked.JobStatus.Completed));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CANCEL COORDINATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_CancelCoordination_Success() public {
        // Propose coordination
        test_ProposeCoordination_Success();

        uint256 jobId = 1;

        // Cancel
        vm.prank(client);
        hook.cancelCoordination(jobId, "Test cancellation");

        // Verify coordination is cancelled in ERC-8001
        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        (IERC8001.Status status,,,,) = coordination.getCoordinationStatus(intentHash);
        assertEq(uint256(status), uint256(IERC8001.Status.Cancelled));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTEGRATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    function test_FullFlow_CompleteWithCoordination() public {
        // 1. Create job with hook
        uint256 jobId = _createJobWithHook();

        // 2. Submit work
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // 3. Propose coordination
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_COMPLETE();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Complete);

        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        // 4. All participants accept
        (,, address[] memory participants,,) = coordination.getCoordinationStatus(intentHash);

        for (uint256 i = 0; i < participants.length; i++) {
            _acceptAsParticipant(jobId, participants[i], intentHash);
        }

        // 5. Execute coordination
        vm.prank(client);
        hook.executeCoordination(jobId, payload, "");

        // 6. Complete job
        uint256 providerBalanceBefore = token.balanceOf(provider);
        uint256 treasuryBalanceBefore = token.balanceOf(treasury);

        vm.prank(evaluator);
        acp.complete(jobId, keccak256("reason"), "");

        // 7. Verify completion
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint256(job.status), uint256(AgenticCommerceHooked.JobStatus.Completed));

        // Verify payment was released to provider
        assertGt(token.balanceOf(provider), providerBalanceBefore);
        // Treasury fee may be 0 if platformFeeBP is 0 (valid configuration)
        assertGe(token.balanceOf(treasury), treasuryBalanceBefore);
    }

    function test_FullFlow_RejectWithCoordination() public {
        // 1. Create job with hook
        uint256 jobId = _createJobWithHook();

        // 2. Submit work
        vm.prank(provider);
        acp.submit(jobId, keccak256("deliverable"), "");

        // 3. Propose reject coordination
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 coordinationType = hook.COORDINATION_REJECT();

        IERC8001.CoordinationPayload memory payload = _createPayload(coordinationType, "");
        bytes32 payloadHash = _hashPayload(payload);

        IERC8001.AgentIntent memory intent = _createAgentIntent(payloadHash, expiry, 1, coordinationType, 0);

        bytes memory signature = _signIntent(clientKey, intent);

        vm.prank(client);
        hook.proposeCoordination(jobId, intent, signature, payload, ERC8001CoordinationHook.ActionType.Reject);

        (, ERC8001CoordinationHook.ActionType actionType, bytes32 intentHash) = hook.getJobCoordination(jobId);

        // 4. All participants accept
        (,, address[] memory participants,,) = coordination.getCoordinationStatus(intentHash);

        for (uint256 i = 0; i < participants.length; i++) {
            _acceptAsParticipant(jobId, participants[i], intentHash);
        }

        // 5. Execute coordination
        vm.prank(client);
        hook.executeCoordination(jobId, payload, "");

        // 6. Reject job
        uint256 clientBalanceBefore = token.balanceOf(client);

        vm.prank(evaluator);
        acp.reject(jobId, keccak256("reason"), "");

        // 7. Verify rejection
        AgenticCommerceHooked.Job memory job = acp.getJob(jobId);
        assertEq(uint256(job.status), uint256(AgenticCommerceHooked.JobStatus.Rejected));

        // Verify refund
        assertGt(token.balanceOf(client), clientBalanceBefore);
    }
}
