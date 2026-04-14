// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/BaseACPHook.sol";

contract MockACPCaller {
    function callBeforeAction(
        BaseACPHook hook,
        uint256 jobId,
        bytes4 selector,
        bytes memory data
    ) external {
        hook.beforeAction(jobId, selector, data);
    }

    function callAfterAction(
        BaseACPHook hook,
        uint256 jobId,
        bytes4 selector,
        bytes memory data
    ) external {
        hook.afterAction(jobId, selector, data);
    }
}

contract BaseACPHookProbe is BaseACPHook {
    bool public beforeCalled;
    bool public afterCalled;

    address public beforeCaller;
    address public beforeToken;
    uint256 public beforeAmount;
    bytes32 public beforeOptParamsHash;

    address public afterCaller;
    address public afterToken;
    uint256 public afterAmount;
    bytes32 public afterOptParamsHash;

    constructor(address acpContract_) BaseACPHook(acpContract_) {}

    function _preSetBudget(
        uint256,
        address caller,
        address token,
        uint256 amount,
        bytes memory optParams
    ) internal override {
        beforeCalled = true;
        beforeCaller = caller;
        beforeToken = token;
        beforeAmount = amount;
        beforeOptParamsHash = keccak256(optParams);
    }

    function _postSetBudget(
        uint256,
        address caller,
        address token,
        uint256 amount,
        bytes memory optParams
    ) internal override {
        afterCalled = true;
        afterCaller = caller;
        afterToken = token;
        afterAmount = amount;
        afterOptParamsHash = keccak256(optParams);
    }
}

contract BaseACPHookSetBudgetRoutingTest is Test {
    uint256 internal constant JOB_ID = 1;
    uint256 internal constant AMOUNT = 1 ether;

    address internal constant CALLER = address(0xCA11);
    address internal constant TOKEN = address(0xC0FFEE);

    MockACPCaller internal acp;
    BaseACPHookProbe internal hook;

    function setUp() public {
        acp = new MockACPCaller();
        hook = new BaseACPHookProbe(address(acp));
    }

    function test_beforeAction_routes_token_aware_setBudget_payload() public {
        bytes memory optParams = abi.encode(uint256(1234));

        acp.callBeforeAction(
            hook,
            JOB_ID,
            bytes4(keccak256("setBudget(uint256,address,uint256,bytes)")),
            abi.encode(CALLER, TOKEN, AMOUNT, optParams)
        );

        assertTrue(hook.beforeCalled());
        assertEq(hook.beforeCaller(), CALLER);
        assertEq(hook.beforeToken(), TOKEN);
        assertEq(hook.beforeAmount(), AMOUNT);
        assertEq(hook.beforeOptParamsHash(), keccak256(optParams));
    }

    function test_afterAction_routes_token_aware_setBudget_payload() public {
        bytes memory optParams = abi.encode("terms");

        acp.callAfterAction(
            hook,
            JOB_ID,
            bytes4(keccak256("setBudget(uint256,address,uint256,bytes)")),
            abi.encode(CALLER, TOKEN, AMOUNT, optParams)
        );

        assertTrue(hook.afterCalled());
        assertEq(hook.afterCaller(), CALLER);
        assertEq(hook.afterToken(), TOKEN);
        assertEq(hook.afterAmount(), AMOUNT);
        assertEq(hook.afterOptParamsHash(), keccak256(optParams));
    }
}
