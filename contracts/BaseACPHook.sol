// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@acp/IACPHook.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @title BaseACPHook
 * @dev Abstract convenience base for ACP hooks. Routes the generic
 *      beforeAction/afterAction calls to named virtual functions so hook
 *      developers only override what they need.
 *
 *      NOT part of the ERC standard — this is a helper contract that can be
 *      updated independently without changing the IACPHook interface.
 *
 *      All virtual functions include an `address caller` parameter because
 *      AgenticCommerce supports operators, so the actual caller matters.
 *
 *      Data encoding per selector (as produced by AgenticCommerce):
 *        setBudget   : abi.encode(caller, token, amount, optParams)
 *        fund        : abi.encode(caller, optParams)
 *        submit      : abi.encode(caller, deliverable, optParams)
 *        complete    : abi.encode(caller, reason, optParams)
 *        reject      : abi.encode(caller, reason, optParams)
 *
 *      Example:
 *          contract MyHook is BaseACPHook {
 *              constructor(address acp) BaseACPHook(acp) {}
 *              function _postFund(uint256 jobId, address caller, bytes memory optParams) internal override {
 *                  // custom logic after fund
 *              }
 *          }
 */
abstract contract BaseACPHook is ERC165, IACPHook {
    address public immutable acpContract;

    error OnlyACPContract();

    modifier onlyACP() {
        if (msg.sender != acpContract) revert OnlyACPContract();
        _;
    }

    constructor(address acpContract_) {
        acpContract = acpContract_;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IACPHook).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // --- Selector constants (avoid repeated keccak at runtime) ----------------
    // These match AgenticCommerce function selectors.
    bytes4 private constant SEL_SET_BUDGET =
        bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
    bytes4 private constant SEL_FUND =
        bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 private constant SEL_SUBMIT =
        bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_COMPLETE =
        bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_REJECT =
        bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    // --- IACPHook implementation (router) ------------------------------------

    function beforeAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyACP {
        if (selector == SEL_SET_BUDGET) {
            (address caller, address token, uint256 amount, bytes memory optParams) = abi
                .decode(data, (address, address, uint256, bytes));
            _preSetBudget(jobId, caller, token, amount, optParams);
        } else if (selector == SEL_FUND) {
            (address caller, bytes memory optParams) = abi.decode(
                data,
                (address, bytes)
            );
            _preFund(jobId, caller, optParams);
        } else if (selector == SEL_SUBMIT) {
            (address caller, bytes32 deliverable, bytes memory optParams) = abi
                .decode(data, (address, bytes32, bytes));
            _preSubmit(jobId, caller, deliverable, optParams);
        } else if (selector == SEL_COMPLETE) {
            (address caller, bytes32 reason, bytes memory optParams) = abi
                .decode(data, (address, bytes32, bytes));
            _preComplete(jobId, caller, reason, optParams);
        } else if (selector == SEL_REJECT) {
            (address caller, bytes32 reason, bytes memory optParams) = abi
                .decode(data, (address, bytes32, bytes));
            _preReject(jobId, caller, reason, optParams);
        }
    }

    function afterAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyACP {
        if (selector == SEL_SET_BUDGET) {
            (address caller, address token, uint256 amount, bytes memory optParams) = abi
                .decode(data, (address, address, uint256, bytes));
            _postSetBudget(jobId, caller, token, amount, optParams);
        } else if (selector == SEL_FUND) {
            (address caller, bytes memory optParams) = abi.decode(
                data,
                (address, bytes)
            );
            _postFund(jobId, caller, optParams);
        } else if (selector == SEL_SUBMIT) {
            (address caller, bytes32 deliverable, bytes memory optParams) = abi
                .decode(data, (address, bytes32, bytes));
            _postSubmit(jobId, caller, deliverable, optParams);
        } else if (selector == SEL_COMPLETE) {
            (address caller, bytes32 reason, bytes memory optParams) = abi
                .decode(data, (address, bytes32, bytes));
            _postComplete(jobId, caller, reason, optParams);
        } else if (selector == SEL_REJECT) {
            (address caller, bytes32 reason, bytes memory optParams) = abi
                .decode(data, (address, bytes32, bytes));
            _postReject(jobId, caller, reason, optParams);
        }
    }

    // --- Virtual functions (override what you need) --------------------------

    function _preSetBudget(
        uint256 jobId,
        address caller,
        address token,
        uint256 amount,
        bytes memory optParams
    ) internal virtual {}
    function _postSetBudget(
        uint256 jobId,
        address caller,
        address token,
        uint256 amount,
        bytes memory optParams
    ) internal virtual {}

    function _preFund(
        uint256 jobId,
        address caller,
        bytes memory optParams
    ) internal virtual {}
    function _postFund(
        uint256 jobId,
        address caller,
        bytes memory optParams
    ) internal virtual {}

    function _preSubmit(
        uint256 jobId,
        address caller,
        bytes32 deliverable,
        bytes memory optParams
    ) internal virtual {}
    function _postSubmit(
        uint256 jobId,
        address caller,
        bytes32 deliverable,
        bytes memory optParams
    ) internal virtual {}

    function _preComplete(
        uint256 jobId,
        address caller,
        bytes32 reason,
        bytes memory optParams
    ) internal virtual {}
    function _postComplete(
        uint256 jobId,
        address caller,
        bytes32 reason,
        bytes memory optParams
    ) internal virtual {}

    function _preReject(
        uint256 jobId,
        address caller,
        bytes32 reason,
        bytes memory optParams
    ) internal virtual {}
    function _postReject(
        uint256 jobId,
        address caller,
        bytes32 reason,
        bytes memory optParams
    ) internal virtual {}
}
