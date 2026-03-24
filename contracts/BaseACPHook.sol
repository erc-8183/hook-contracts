// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IACPHook.sol";

/**
 * @title BaseACPHook
 * @dev Abstract convenience base for ACP hooks. Routes the generic
 *      beforeAction/afterAction calls to named virtual functions so hook
 *      developers only override what they need.
 *
 *      NOT part of the ERC standard — this is a helper contract that can be
 *      updated independently without changing the IACPHook interface.
 *
 *      Data encoding per selector (as produced by AgenticCommerceHooked):
 *        setProvider  : abi.encode(address provider, bytes optParams)
 *        setBudget    : abi.encode(uint256 amount, bytes optParams)
 *        fund         : optParams (raw bytes)
 *        submit       : abi.encode(bytes32 deliverable, bytes optParams)
 *        complete     : abi.encode(bytes32 reason, bytes optParams)
 *        reject       : abi.encode(bytes32 reason, bytes optParams)
 *
 *      Example:
 *          contract MyHook is BaseACPHook {
 *              constructor(address acp) BaseACPHook(acp) {}
 *              function _postFund(uint256 jobId, bytes memory optParams) internal override {
 *                  // custom logic after fund
 *              }
 *          }
 */
abstract contract BaseACPHook is IACPHook {
    address public immutable acpContract;

    error OnlyACPContract();

    modifier onlyACP() {
        if (msg.sender != acpContract) revert OnlyACPContract();
        _;
    }

    constructor(address acpContract_) {
        acpContract = acpContract_;
    }

    // --- Selector constants (avoid repeated keccak at runtime) ----------------
    // These match AgenticCommerceHooked function selectors.
    bytes4 private constant SEL_SET_PROVIDER = bytes4(keccak256("setProvider(uint256,address,bytes)"));
    bytes4 private constant SEL_SET_BUDGET = bytes4(keccak256("setBudget(uint256,uint256,bytes)"));
    bytes4 private constant SEL_FUND = bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 private constant SEL_SUBMIT = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_COMPLETE = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_REJECT = bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    // --- IACPHook implementation (router) ------------------------------------

    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override onlyACP {
        if (selector == SEL_SET_PROVIDER) {
            (address provider_, bytes memory optParams) = abi.decode(data, (address, bytes));
            _preSetProvider(jobId, provider_, optParams);
        } else if (selector == SEL_SET_BUDGET) {
            (uint256 amount, bytes memory optParams) = abi.decode(data, (uint256, bytes));
            _preSetBudget(jobId, amount, optParams);
        } else if (selector == SEL_FUND) {
            if (data.length >= 64) {
                (uint256 expectedBudget, bytes memory optParams) = abi.decode(data, (uint256, bytes));
                _preFund(jobId, expectedBudget, optParams);
            }
        } else if (selector == SEL_SUBMIT) {
            (bytes32 deliverable, bytes memory optParams) = abi.decode(data, (bytes32, bytes));
            _preSubmit(jobId, deliverable, optParams);
        } else if (selector == SEL_COMPLETE) {
            (bytes32 reason, bytes memory optParams) = abi.decode(data, (bytes32, bytes));
            _preComplete(jobId, reason, optParams);
        } else if (selector == SEL_REJECT) {
            (bytes32 reason, bytes memory optParams) = abi.decode(data, (bytes32, bytes));
            _preReject(jobId, reason, optParams);
        }
    }

    function afterAction(uint256 jobId, bytes4 selector, bytes calldata data) external override onlyACP {
        if (selector == SEL_SET_PROVIDER) {
            (address provider_, bytes memory optParams) = abi.decode(data, (address, bytes));
            _postSetProvider(jobId, provider_, optParams);
        } else if (selector == SEL_SET_BUDGET) {
            (uint256 amount, bytes memory optParams) = abi.decode(data, (uint256, bytes));
            _postSetBudget(jobId, amount, optParams);
        } else if (selector == SEL_FUND) {
            if (data.length >= 64) {
                (uint256 expectedBudget, bytes memory optParams) = abi.decode(data, (uint256, bytes));
                _postFund(jobId, expectedBudget, optParams);
            }
        } else if (selector == SEL_SUBMIT) {
            (bytes32 deliverable, bytes memory optParams) = abi.decode(data, (bytes32, bytes));
            _postSubmit(jobId, deliverable, optParams);
        } else if (selector == SEL_COMPLETE) {
            (bytes32 reason, bytes memory optParams) = abi.decode(data, (bytes32, bytes));
            _postComplete(jobId, reason, optParams);
        } else if (selector == SEL_REJECT) {
            (bytes32 reason, bytes memory optParams) = abi.decode(data, (bytes32, bytes));
            _postReject(jobId, reason, optParams);
        }
    }

    // --- Virtual functions (override what you need) --------------------------

    function _preSetProvider(uint256 jobId, address provider_, bytes memory optParams) internal virtual {}
    function _postSetProvider(uint256 jobId, address provider_, bytes memory optParams) internal virtual {}

    function _preSetBudget(uint256 jobId, uint256 amount, bytes memory optParams) internal virtual {}
    function _postSetBudget(uint256 jobId, uint256 amount, bytes memory optParams) internal virtual {}

    function _preFund(uint256 jobId, uint256 expectedBudget, bytes memory optParams) internal virtual {}
    function _postFund(uint256 jobId, uint256 expectedBudget, bytes memory optParams) internal virtual {}

    function _preSubmit(uint256 jobId, bytes32 deliverable, bytes memory optParams) internal virtual {}
    function _postSubmit(uint256 jobId, bytes32 deliverable, bytes memory optParams) internal virtual {}

    function _preComplete(uint256 jobId, bytes32 reason, bytes memory optParams) internal virtual {}
    function _postComplete(uint256 jobId, bytes32 reason, bytes memory optParams) internal virtual {}

    function _preReject(uint256 jobId, bytes32 reason, bytes memory optParams) internal virtual {}
    function _postReject(uint256 jobId, bytes32 reason, bytes memory optParams) internal virtual {}

    // --- Helper: read job from ACP contract ----------------------------------

    function _getJobClient(uint256 jobId) internal view returns (address client) {
        (bool ok, bytes memory data) = acpContract.staticcall(abi.encodeWithSignature("getJob(uint256)", jobId));
        require(ok, "getJob failed");
        // Job struct: (id, client, provider, evaluator, hook, description, budget, expiredAt, status)
        (, client,,,,,,,) =
            abi.decode(data, (uint256, address, address, address, address, string, uint256, uint256, uint8));
    }
}
