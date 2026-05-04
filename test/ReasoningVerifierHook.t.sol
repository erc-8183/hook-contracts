// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC8183Hook} from "@erc8183/IERC8183Hook.sol";
import {IERC8183HookMetadata} from "../contracts/interfaces/IERC8183HookMetadata.sol";
import {IReasoningVerifier, ReasoningVerifierHook} from "../contracts/hooks/ReasoningVerifierHook.sol";

contract MockReasoningVerifier is IReasoningVerifier {
    mapping(bytes32 => bool) private _verified;
    mapping(bytes32 => uint256) private _confidence;

    function setResult(bytes32 canonicalHash, bool verified, uint256 confidence) external {
        _verified[canonicalHash] = verified;
        _confidence[canonicalHash] = confidence;
    }

    function verifyReasoning(bytes32 canonicalHash)
        external
        view
        override
        returns (bool verified, uint256 confidence)
    {
        return (_verified[canonicalHash], _confidence[canonicalHash]);
    }
}

contract MockERC8183Caller {
    function callBeforeAction(IERC8183Hook hook, uint256 jobId, bytes4 selector, bytes memory data) external {
        hook.beforeAction(jobId, selector, data);
    }

    function callAfterAction(IERC8183Hook hook, uint256 jobId, bytes4 selector, bytes memory data) external {
        hook.afterAction(jobId, selector, data);
    }
}

contract ReasoningVerifierHookTest is Test {
    MockReasoningVerifier mockVerifier;
    MockERC8183Caller mockCore;
    ReasoningVerifierHook hook;

    uint256 constant JOB_ID = 1;
    uint256 constant MIN_CONFIDENCE = 700;
    bytes4 constant SUBMIT_SELECTOR = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 constant COMPLETE_SELECTOR = bytes4(keccak256("complete(uint256,bytes32,bytes)"));

    function setUp() public {
        mockVerifier = new MockReasoningVerifier();
        mockCore = new MockERC8183Caller();
        hook = new ReasoningVerifierHook(address(mockCore), IReasoningVerifier(address(mockVerifier)), MIN_CONFIDENCE);
    }

    function _submitData(bytes32 deliverable, bytes memory optParams) internal pure returns (bytes memory) {
        return abi.encode(address(0xBEEF), deliverable, optParams);
    }

    function _callBeforeSubmit(bytes32 deliverable) internal {
        mockCore.callBeforeAction(hook, JOB_ID, SUBMIT_SELECTOR, _submitData(deliverable, bytes("")));
    }

    function test_Deployment() public view {
        assertEq(address(hook.verifier()), address(mockVerifier));
        assertEq(hook.minConfidence(), MIN_CONFIDENCE);
        assertEq(hook.erc8183Contract(), address(mockCore));
    }

    function test_Deployment_RevertZeroCore() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(address(0), IReasoningVerifier(address(mockVerifier)), MIN_CONFIDENCE);
    }

    function test_Deployment_RevertZeroVerifier() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(address(mockCore), IReasoningVerifier(address(0)), MIN_CONFIDENCE);
    }

    function test_Deployment_RevertConfidenceTooLow() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(address(mockCore), IReasoningVerifier(address(mockVerifier)), 50);
    }

    function test_Deployment_RevertConfidenceTooHigh() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(address(mockCore), IReasoningVerifier(address(mockVerifier)), 1001);
    }

    function test_BeforeSubmit_AllowsWhenVerifiedAboveThreshold() public {
        bytes32 deliverable = keccak256("claim-allow");
        mockVerifier.setResult(deliverable, true, 850);
        _callBeforeSubmit(deliverable);
    }

    function test_BeforeSubmit_AllowsAtExactThreshold() public {
        bytes32 deliverable = keccak256("claim-exact");
        mockVerifier.setResult(deliverable, true, MIN_CONFIDENCE);
        _callBeforeSubmit(deliverable);
    }

    function test_BeforeSubmit_RevertsWhenNotVerified() public {
        bytes32 deliverable = keccak256("claim-unverified");
        vm.expectRevert(abi.encodeWithSelector(ReasoningVerifierHook.NotVerified.selector, deliverable));
        _callBeforeSubmit(deliverable);
    }

    function test_BeforeSubmit_RevertsWhenConfidenceTooLow() public {
        bytes32 deliverable = keccak256("claim-lowconf");
        mockVerifier.setResult(deliverable, true, 600);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.ConfidenceTooLow.selector,
                deliverable,
                uint256(600),
                uint256(MIN_CONFIDENCE)
            )
        );
        _callBeforeSubmit(deliverable);
    }

    function test_BeforeAction_NonSubmitSelectorDoesNotRevert() public {
        mockCore.callBeforeAction(hook, JOB_ID, COMPLETE_SELECTOR, abi.encode(address(0xBEEF), bytes32("ok"), bytes("")));
    }

    function test_AfterAction_DoesNotRevert() public {
        mockCore.callAfterAction(hook, JOB_ID, COMPLETE_SELECTOR, abi.encode(address(0xBEEF), bytes32("ok"), bytes("")));
    }

    function test_ExposesHookMetadataInterface() public view {
        assertTrue(hook.supportsInterface(type(IERC8183Hook).interfaceId));
        assertTrue(hook.supportsInterface(type(IERC8183HookMetadata).interfaceId));
    }

    function test_RequiredSelectors_IsEmpty() public view {
        bytes4[] memory selectors = hook.requiredSelectors();
        assertEq(selectors.length, 0);
    }
}
