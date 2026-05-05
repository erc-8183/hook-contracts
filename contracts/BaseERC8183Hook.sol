// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@erc8183/IERC8183Hook.sol";
import "@erc8183/AgenticCommerce.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @title BaseERC8183Hook
 * @dev Abstract convenience base for ERC-8183 hooks. Routes the generic
 *      beforeAction/afterAction calls to named virtual functions so hook
 *      developers only override what they need.
 *
 *      NOT part of the ERC standard — this is a helper contract that can be
 *      updated independently without changing the IERC8183Hook interface.
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
 *          contract MyHook is BaseERC8183Hook {
 *              constructor(address erc8183) BaseERC8183Hook(erc8183) {}
 *              function _postFund(uint256 jobId, address caller, bytes memory optParams) internal override {
 *                  // custom logic after fund
 *              }
 *          }
 */
abstract contract BaseERC8183Hook is ERC165, IERC8183Hook {
    /// @notice The ERC-8183 core contract (or MultiHookRouter) that is authorized to call this hook
    address public immutable erc8183Contract;

    /// @notice Thrown when the caller is not the ERC-8183 contract
    error OnlyERC8183Contract();
    /// @notice Thrown when the ERC-8183 contract is set to zero address
    error InvalidERC8183Contract();

    /// @dev Restricts access to the ERC-8183 core contract or the hook registered for the job.
    ///      Standalone: msg.sender must be erc8183Contract (core).
    ///      Behind router: msg.sender must be the hook registered on core for this jobId.
    modifier onlyERC8183(uint256 jobId) {
        if (msg.sender != erc8183Contract) {
            AgenticCommerce.Job memory job = AgenticCommerce(erc8183Contract).getJob(jobId);
            if (msg.sender != job.hook) revert OnlyERC8183Contract();
        }
        _;
    }

    /// @param erc8183Contract_ The ERC-8183 core contract address
    constructor(address erc8183Contract_) {
        if (erc8183Contract_ == address(0)) revert InvalidERC8183Contract();
        erc8183Contract = erc8183Contract_;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC8183Hook).interfaceId ||
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

    // --- IERC8183Hook implementation (router) ------------------------------------

    function beforeAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyERC8183(jobId) {
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
    ) external override onlyERC8183(jobId) {
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
