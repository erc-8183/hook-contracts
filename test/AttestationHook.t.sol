// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC8183HookMetadata} from "../contracts/interfaces/IERC8183HookMetadata.sol";
import {AttestationHook, IEAS} from "../contracts/hooks/AttestationHook.sol";
import {ERC8183} from "@erc8183/ERC8183.sol";

contract MockERC8183 {
    mapping(uint256 => ERC8183.Job) internal jobs;

    function setJob(uint256 jobId, address client, address provider, address evaluator, uint256 budget, address hook)
        external
    {
        jobs[jobId] = ERC8183.Job({
            client: client,
            status: ERC8183.JobStatus.Completed,
            provider: provider,
            expiredAt: uint48(block.timestamp + 1 days),
            evaluator: evaluator,
            submittedAt: uint48(block.timestamp),
            budget: budget,
            hook: hook,
            paymentToken: address(0),
            providerAgentId: 0,
            description: "test job"
        });
    }

    function getJob(uint256 jobId) external view returns (ERC8183.Job memory) {
        return jobs[jobId];
    }
}

contract MockEAS is IEAS {
    bool public shouldRevert;
    uint256 public calls;
    bytes32 public lastSchema;
    address public lastRecipient;
    bytes public lastData;

    function setShouldRevert(bool shouldRevert_) external {
        shouldRevert = shouldRevert_;
    }

    function attest(AttestationRequest calldata request) external payable returns (bytes32) {
        if (shouldRevert) revert("EAS down");

        calls++;
        lastSchema = request.schema;
        lastRecipient = request.data.recipient;
        lastData = request.data.data;

        return keccak256(abi.encode(calls, request.schema, request.data.recipient));
    }
}

contract AttestationHookTest is Test {
    bytes4 internal constant SEL_COMPLETE = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 internal constant SEL_REJECT = bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    MockERC8183 internal core;
    MockEAS internal eas;
    AttestationHook internal hook;

    address internal client = address(0xA11CE);
    address internal provider = address(0xB0B);
    address internal evaluator = address(0xE0A1);
    bytes32 internal schemaUID = bytes32(uint256(0x8183));

    function setUp() public {
        core = new MockERC8183();
        eas = new MockEAS();
        hook = new AttestationHook(address(core), address(eas), schemaUID);
        core.setJob(1, client, provider, evaluator, 1 ether, address(hook));
    }

    function testRequiredSelectors() public view {
        bytes4[] memory selectors = hook.requiredSelectors();

        assertEq(selectors.length, 2);
        assertEq(selectors[0], SEL_COMPLETE);
        assertEq(selectors[1], SEL_REJECT);
    }

    function testPostCompleteWritesProviderAttestation() public {
        bytes32 reason = keccak256("accepted");

        _afterActionFromCore(1, SEL_COMPLETE, reason);

        bytes32 uid = hook.getAttestation(1);
        assertNotEq(uid, bytes32(0));
        assertEq(hook.jobAttestations(1), uid);
        assertEq(hook.totalAttestations(), 1);
        assertEq(eas.calls(), 1);
        assertEq(eas.lastSchema(), schemaUID);
        assertEq(eas.lastRecipient(), provider);

        (
            uint256 jobId,
            address attestedClient,
            address attestedProvider,
            address attestedEvaluator,
            uint256 budget,
            bytes32 attestedReason,
            bool completed
        ) = abi.decode(eas.lastData(), (uint256, address, address, address, uint256, bytes32, bool));

        assertEq(jobId, 1);
        assertEq(attestedClient, client);
        assertEq(attestedProvider, provider);
        assertEq(attestedEvaluator, evaluator);
        assertEq(budget, 1 ether);
        assertEq(attestedReason, reason);
        assertTrue(completed);
    }

    function testPostRejectWritesNegativeAttestation() public {
        bytes32 reason = keccak256("rejected");

        _afterActionFromCore(1, SEL_REJECT, reason);

        (,,,,, bytes32 attestedReason, bool completed) =
            abi.decode(eas.lastData(), (uint256, address, address, address, uint256, bytes32, bool));

        assertEq(hook.totalAttestations(), 1);
        assertEq(attestedReason, reason);
        assertFalse(completed);
    }

    function testEASFailureDoesNotRevertAndClearsSentinel() public {
        eas.setShouldRevert(true);

        _afterActionFromCore(1, SEL_COMPLETE, keccak256("accepted"));

        assertEq(hook.getAttestation(1), bytes32(0));
        assertEq(hook.jobAttestations(1), bytes32(0));
        assertEq(hook.totalAttestations(), 0);
    }

    function testAttestationIsIdempotentPerJob() public {
        _afterActionFromCore(1, SEL_COMPLETE, keccak256("first"));
        bytes32 uid = hook.getAttestation(1);

        _afterActionFromCore(1, SEL_REJECT, keccak256("second"));

        assertEq(hook.getAttestation(1), uid);
        assertEq(hook.totalAttestations(), 1);
        assertEq(eas.calls(), 1);
    }

    function testOnlyCoreOrRegisteredHookCanCallAfterAction() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        hook.afterAction(1, SEL_COMPLETE, abi.encode(client, keccak256("accepted"), ""));
    }

    function testOwnerCanUpdateEAS() public {
        MockEAS newEAS = new MockEAS();

        hook.setEAS(address(newEAS));

        assertEq(address(hook.eas()), address(newEAS));
    }

    function testSupportsHookMetadataInterface() public view {
        assertTrue(hook.supportsInterface(type(IERC8183HookMetadata).interfaceId));
    }

    function _afterActionFromCore(uint256 jobId, bytes4 selector, bytes32 reason) internal {
        vm.prank(address(core));
        hook.afterAction(jobId, selector, abi.encode(client, reason, ""));
    }
}
