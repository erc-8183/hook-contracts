// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC8183Hook} from "@erc8183/IERC8183Hook.sol";
import {IERC8183HookMetadata} from "../contracts/interfaces/IERC8183HookMetadata.sol";
import {IReasoningVerifier, ReasoningVerifierHook} from "../contracts/hooks/ReasoningVerifierHook.sol";

/// @notice Mock verifier that binds verification to (jobId, caller, deliverable).
///         Consumes records on read to enforce single-use.
contract MockReasoningVerifier is IReasoningVerifier {
    struct VerificationRecord {
        bool verified;
        uint256 confidence;
        bool consumed;
    }

    // key = keccak256(abi.encode(jobId, caller, deliverable))
    mapping(bytes32 => VerificationRecord) private _records;

    function setResult(
        uint256 jobId,
        address caller,
        bytes32 deliverable,
        bool verified,
        uint256 confidence
    ) external {
        bytes32 key = keccak256(abi.encode(jobId, caller, deliverable));
        _records[key] = VerificationRecord(verified, confidence, false);
    }

    function verifyReasoning(uint256 jobId, address caller, bytes32 deliverable)
        external
        override
        returns (bool verified, uint256 confidence)
    {
        bytes32 key = keccak256(abi.encode(jobId, caller, deliverable));
        VerificationRecord storage rec = _records[key];
        if (rec.consumed) return (false, 0);
        verified = rec.verified;
        confidence = rec.confidence;
        // Consume on read (single-use at verifier level)
        rec.consumed = true;
    }
}

/// @notice Simulates AgenticCommerce calling beforeAction/afterAction on the hook.
///         In production, AgenticCommerce encodes: abi.encode(caller, deliverable, optParams)
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

    // In ERC-8183, "caller" = msg.sender of submit() on AgenticCommerce.
    // This is the worker or an operator acting on their behalf.
    address constant CALLER = address(0xBEEF);
    address constant OPERATOR = address(0xCAFE);
    address constant ATTACKER = address(0xDEAD);

    bytes4 constant SUBMIT_SELECTOR = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 constant COMPLETE_SELECTOR = bytes4(keccak256("complete(uint256,bytes32,bytes)"));

    function setUp() public {
        mockVerifier = new MockReasoningVerifier();
        mockCore = new MockERC8183Caller();
        hook = new ReasoningVerifierHook(address(mockCore), IReasoningVerifier(address(mockVerifier)), MIN_CONFIDENCE);
    }

    /// @dev Encodes data the same way AgenticCommerce does for submit():
    ///      abi.encode(caller, deliverable, optParams)
    function _submitData(address caller, bytes32 deliverable, bytes memory optParams) internal pure returns (bytes memory) {
        return abi.encode(caller, deliverable, optParams);
    }

    function _callBeforeSubmit(uint256 jobId, address caller, bytes32 deliverable) internal {
        mockCore.callBeforeAction(hook, jobId, SUBMIT_SELECTOR, _submitData(caller, deliverable, bytes("")));
    }

    // ================================================================
    // Deployment tests
    // ================================================================

    function test_Deployment() public view {
        assertEq(address(hook.verifier()), address(mockVerifier));
        assertEq(hook.minConfidence(), MIN_CONFIDENCE);
        assertEq(hook.erc8183Contract(), address(mockCore));
        assertEq(hook.MAX_CONFIDENCE(), 1000);
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

    // ================================================================
    // Happy path
    // ================================================================

    function test_BeforeSubmit_AllowsWhenVerifiedAboveThreshold() public {
        bytes32 deliverable = keccak256("claim-allow");
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, 850);
        _callBeforeSubmit(JOB_ID, CALLER, deliverable);
    }

    function test_BeforeSubmit_EmitsEvent() public {
        bytes32 deliverable = keccak256("claim-event");
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, 900);

        vm.expectEmit(true, true, false, true);
        emit ReasoningVerifierHook.ReasoningVerified(JOB_ID, CALLER, deliverable, 900);

        _callBeforeSubmit(JOB_ID, CALLER, deliverable);
    }

    // ================================================================
    // Rejection tests
    // ================================================================

    function test_BeforeSubmit_RevertsWhenNotVerified() public {
        bytes32 deliverable = keccak256("claim-unverified");
        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.NotVerified.selector,
                JOB_ID, CALLER, deliverable
            )
        );
        _callBeforeSubmit(JOB_ID, CALLER, deliverable);
    }

    function test_BeforeSubmit_RevertsWhenConfidenceTooLow() public {
        bytes32 deliverable = keccak256("claim-low");
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, 500);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.ConfidenceTooLow.selector,
                deliverable, 500, MIN_CONFIDENCE
            )
        );
        _callBeforeSubmit(JOB_ID, CALLER, deliverable);
    }

    // ================================================================
    // Security: Cross-job replay prevention
    // ================================================================

    function test_CrossJobReplay_DifferentJobIdReverts() public {
        bytes32 deliverable = keccak256("shared-hash");
        // Only verified for JOB_ID=1
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, 850);

        // Job 1 succeeds
        _callBeforeSubmit(JOB_ID, CALLER, deliverable);

        // Job 2 with same hash fails — not verified for job 2
        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.NotVerified.selector,
                2, CALLER, deliverable
            )
        );
        _callBeforeSubmit(2, CALLER, deliverable);
    }

    // ================================================================
    // Security: Cross-caller replay prevention
    // ================================================================

    function test_CrossCallerReplay_DifferentCallerReverts() public {
        bytes32 deliverable = keccak256("caller-replay");

        // Verified for CALLER on JOB_ID
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, 850);

        // Attacker tries same job + deliverable but as different caller
        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.NotVerified.selector,
                JOB_ID, ATTACKER, deliverable
            )
        );
        _callBeforeSubmit(JOB_ID, ATTACKER, deliverable);
    }

    // ================================================================
    // Multi-caller: same job, independently verified callers both pass
    // ================================================================

    function test_MultiCaller_IndependentlyVerifiedCallersSucceed() public {
        bytes32 deliverable1 = keccak256("worker-submission");
        bytes32 deliverable2 = keccak256("operator-submission");

        // Both CALLER and OPERATOR independently verified for same job
        mockVerifier.setResult(JOB_ID, CALLER, deliverable1, true, 850);
        mockVerifier.setResult(JOB_ID, OPERATOR, deliverable2, true, 900);

        // Both succeed
        _callBeforeSubmit(JOB_ID, CALLER, deliverable1);
        _callBeforeSubmit(JOB_ID, OPERATOR, deliverable2);
    }

    // ================================================================
    // Security: Single-use (replay prevention on same job+caller)
    // ================================================================

    function test_SingleUse_SecondSubmitSameJobCallerReverts() public {
        bytes32 deliverable = keccak256("single-use");
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, 850);

        // First submit succeeds
        _callBeforeSubmit(JOB_ID, CALLER, deliverable);

        // Second submit on same (jobId, caller) reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.AlreadyConsumed.selector,
                JOB_ID, CALLER
            )
        );
        _callBeforeSubmit(JOB_ID, CALLER, deliverable);
    }

    // ================================================================
    // Confidence cap
    // ================================================================

    function test_ConfidenceCap_CapsAtMax() public {
        bytes32 deliverable = keccak256("overcap");
        // Malicious verifier returns type(uint256).max
        mockVerifier.setResult(JOB_ID, CALLER, deliverable, true, type(uint256).max);

        vm.expectEmit(true, true, false, true);
        // Should be capped at 1000
        emit ReasoningVerifierHook.ReasoningVerified(JOB_ID, CALLER, deliverable, 1000);

        _callBeforeSubmit(JOB_ID, CALLER, deliverable);
    }

    // ================================================================
    // requiredSelectors
    // ================================================================

    function test_RequiredSelectors_ReturnsSubmitSelector() public view {
        bytes4[] memory selectors = hook.requiredSelectors();
        assertEq(selectors.length, 1);
        assertEq(selectors[0], SUBMIT_SELECTOR);
    }

    // ================================================================
    // Non-submit selectors pass through
    // ================================================================

    function test_BeforeComplete_PassesThrough() public {
        bytes32 reason = keccak256("complete-ok");
        // No verification needed for non-submit selectors
        // complete encoding: abi.encode(caller, reason, optParams)
        mockCore.callBeforeAction(hook, JOB_ID, COMPLETE_SELECTOR, abi.encode(CALLER, reason, bytes("")));
    }
}
