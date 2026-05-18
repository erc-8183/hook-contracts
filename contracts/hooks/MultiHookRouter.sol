// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC8183Hook} from "@erc8183/IERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";
import {ERC8183} from "@erc8183/ERC8183.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// @title MultiHookRouter
/// @notice Routes hook callbacks to per-selector ordered lists of sub-hooks per job.
/// @dev Each hookable function (setBudget, fund, submit, complete, reject) has
///      its own ordered hook array per job. Hooks irrelevant to a given function are
///      never called.
///
///      Per-hook data dispatch: callers encode optParams as abi.encode(bytes[]) where
///      bytes[i] is the optParams for hook at position i. The router decodes and
///      re-encodes data with each hook's individual slice before calling it.
///      When optParams is empty (<64 bytes), raw data is broadcast to all hooks.
///
///      Sub-hooks must be whitelisted on the core contract.
///      Exposes passthrough view functions so sub-hooks deployed with
///      erc8183Contract = routerAddress can call _core().getJob() etc.
contract MultiHookRouter is ERC165, IERC8183Hook, ReentrancyGuardTransient, Ownable {
    // ──────────────────── Immutables ────────────────────

    /// @notice The ERC-8183 core contract
    address public immutable erc8183Contract;

    // ──────────────────── Constants ────────────────────

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

    // ──────────────────── Storage ────────────────────

    /// @notice Maximum sub-hooks per selector per job (admin-configurable gas safety cap)
    uint256 public maxHooksPerJob;

    /// @notice Per-job, per-selector ordered list of sub-hooks
    mapping(uint256 jobId => mapping(bytes4 selector => address[])) private _jobHooks;

    // ──────────────────── Errors ────────────────────

    error OnlyERC8183Contract();
    error OnlyJobClient();
    error HooksLocked();
    error TooManyHooks();
    error InvalidHook();
    error InvalidSelector();
    error DuplicateHook();
    error HookNotFound();
    error ZeroAddress();
    error EmptyArray();
    error HookSetMismatch();
    error HookDataLengthMismatch();
    error SubHookNotWhitelisted();
    error ArrayLengthMismatch();
    error HookMissingRequiredSelector();

    // ──────────────────── Events ────────────────────

    event HooksConfigured(uint256 indexed jobId, bytes4 indexed selector, address[] hooks);
    event HookAdded(uint256 indexed jobId, bytes4 indexed selector, address indexed hook, uint256 position);
    event HookRemoved(uint256 indexed jobId, bytes4 indexed selector, address indexed hook);
    event HooksReordered(uint256 indexed jobId, bytes4 indexed selector, address[] hooks);
    event MaxHooksPerJobUpdated(uint256 oldMax, uint256 newMax);
    event DewhitelistedHookSkipped(uint256 indexed jobId, bytes4 indexed selector, address indexed hook);

    // ──────────────────── Modifiers ────────────────────

    modifier onlyERC8183() {
        if (msg.sender != erc8183Contract) revert OnlyERC8183Contract();
        _;
    }

    modifier onlyJobClient(uint256 jobId) {
        ERC8183.Job memory job = ERC8183(erc8183Contract).getJob(jobId);
        if (msg.sender != job.client) revert OnlyJobClient();
        _;
    }

    modifier hooksNotLocked(uint256 jobId) {
        ERC8183.Job memory job = ERC8183(erc8183Contract).getJob(jobId);
        if (job.status != ERC8183.JobStatus.Open) revert HooksLocked();
        _;
    }

    modifier validSelector(bytes4 selector) {
        if (!_isKnownSelector(selector)) revert InvalidSelector();
        _;
    }

    // ──────────────────── Constructor ────────────────────

    constructor(address erc8183Contract_, address owner_, uint256 maxHooksPerJob_) Ownable(owner_) {
        if (erc8183Contract_ == address(0)) revert ZeroAddress();
        erc8183Contract = erc8183Contract_;
        maxHooksPerJob = maxHooksPerJob_;
    }

    // ──────────────────── Admin ────────────────────

    /// @notice Update the maximum sub-hooks allowed per selector per job
    /// @param newMax New maximum
    function setMaxHooksPerJob(uint256 newMax) external onlyOwner {
        uint256 oldMax = maxHooksPerJob;
        maxHooksPerJob = newMax;
        emit MaxHooksPerJobUpdated(oldMax, newMax);
    }

    // ──────────────────── Configuration ────────────────────

    /// @notice Replace the entire hook list for a job's selector
    /// @param jobId The job ID
    /// @param selector The hookable function selector
    /// @param hooks Ordered array of sub-hook addresses
    function configureHooks(
        uint256 jobId,
        bytes4 selector,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        if (hooks.length > maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            _validateSubHook(hooks[i]);
            for (uint256 j; j < i; ) {
                if (hooks[j] == hooks[i]) revert DuplicateHook();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }

        _jobHooks[jobId][selector] = hooks;
        emit HooksConfigured(jobId, selector, hooks);
    }

    /// @notice Replace hook lists for multiple selectors in a single call
    /// @param jobId The job ID
    /// @param selectors Array of hookable function selectors
    /// @param hooksPerSelector Array of ordered sub-hook arrays, one per selector
    function batchConfigureHooks(
        uint256 jobId,
        bytes4[] calldata selectors,
        address[][] calldata hooksPerSelector
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        if (selectors.length != hooksPerSelector.length) revert ArrayLengthMismatch();
        if (selectors.length == 0) revert EmptyArray();

        for (uint256 s; s < selectors.length; ) {
            _setHooksForSelector(jobId, selectors[s], hooksPerSelector[s]);
            unchecked { ++s; }
        }

        _validateSelectorCompleteness(jobId);
    }

    /// @notice Append a hook to the end of the list for a selector
    /// @param jobId The job ID
    /// @param selector The hookable function selector
    /// @param hook The sub-hook address to add
    function addHook(
        uint256 jobId,
        bytes4 selector,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        _validateSubHook(hook);

        address[] storage hooks = _jobHooks[jobId][selector];
        if (hooks.length >= maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            if (hooks[i] == hook) revert DuplicateHook();
            unchecked { ++i; }
        }

        hooks.push(hook);
        emit HookAdded(jobId, selector, hook, hooks.length - 1);
    }

    /// @notice Remove a hook from the list for a selector
    /// @param jobId The job ID
    /// @param selector The hookable function selector
    /// @param hook The sub-hook address to remove
    /// @dev Preserves the relative order of the remaining hooks. Order matters
    ///      because beforeAction/afterAction iterate _jobHooks in storage order
    ///      and _splitHookData binds per-hook optParams to hooks by index.
    function removeHook(
        uint256 jobId,
        bytes4 selector,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        address[] storage hooks = _jobHooks[jobId][selector];
        uint256 len = hooks.length;

        for (uint256 i; i < len; ) {
            if (hooks[i] == hook) {
                // Shift remaining elements left so removal is order-preserving.
                for (uint256 j = i; j + 1 < len; ) {
                    hooks[j] = hooks[j + 1];
                    unchecked { ++j; }
                }
                hooks.pop();
                emit HookRemoved(jobId, selector, hook);
                return;
            }
            unchecked { ++i; }
        }

        revert HookNotFound();
    }

    /// @notice Replace the hook list with a reordered version (must be a permutation)
    /// @param jobId The job ID
    /// @param selector The hookable function selector
    /// @param hooks New ordering (must contain the same hooks)
    function reorderHooks(
        uint256 jobId,
        bytes4 selector,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        address[] storage current = _jobHooks[jobId][selector];
        if (hooks.length != current.length) revert HookSetMismatch();
        if (hooks.length == 0) revert EmptyArray();

        for (uint256 i; i < hooks.length; ) {
            for (uint256 k; k < i; ) {
                if (hooks[k] == hooks[i]) revert DuplicateHook();
                unchecked { ++k; }
            }
            bool found;
            for (uint256 j; j < current.length; ) {
                if (hooks[i] == current[j]) {
                    found = true;
                    break;
                }
                unchecked { ++j; }
            }
            if (!found) revert HookNotFound();
            unchecked { ++i; }
        }

        _jobHooks[jobId][selector] = hooks;
        emit HooksReordered(jobId, selector, hooks);
    }

    // ──────────────────── IERC8183Hook Implementation ────────────────────

    /// @inheritdoc IERC8183Hook
    function beforeAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyERC8183 nonReentrant {
        address[] storage hooks = _jobHooks[jobId][selector];
        uint256 len = hooks.length;
        if (len == 0) return;

        // Validate selector completeness at fund time (first non-config lifecycle call)
        if (selector == SEL_FUND) {
            _validateSelectorCompleteness(jobId);
        }

        (bool dispatched, bytes[] memory perHookData) = _splitHookData(selector, data, len);

        for (uint256 i; i < len; ) {
            if (!ERC8183(erc8183Contract).whitelistedHooks(hooks[i])) {
                emit DewhitelistedHookSkipped(jobId, selector, hooks[i]);
                unchecked { ++i; }
                continue;
            }
            if (dispatched) {
                IERC8183Hook(hooks[i]).beforeAction(jobId, selector, perHookData[i]);
            } else {
                IERC8183Hook(hooks[i]).beforeAction(jobId, selector, data);
            }
            unchecked { ++i; }
        }
    }

    /// @inheritdoc IERC8183Hook
    function afterAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyERC8183 nonReentrant {
        address[] storage hooks = _jobHooks[jobId][selector];
        uint256 len = hooks.length;
        if (len == 0) return;

        (bool dispatched, bytes[] memory perHookData) = _splitHookData(selector, data, len);

        for (uint256 i; i < len; ) {
            if (!ERC8183(erc8183Contract).whitelistedHooks(hooks[i])) {
                emit DewhitelistedHookSkipped(jobId, selector, hooks[i]);
                unchecked { ++i; }
                continue;
            }
            if (dispatched) {
                IERC8183Hook(hooks[i]).afterAction(jobId, selector, perHookData[i]);
            } else {
                IERC8183Hook(hooks[i]).afterAction(jobId, selector, data);
            }
            unchecked { ++i; }
        }
    }

    // ──────────────────── Passthrough Views ────────────────────

    /// @notice Passthrough to core getJob -- allows sub-hooks to call _core().getJob()
    function getJob(uint256 jobId) external view returns (ERC8183.Job memory) {
        return ERC8183(erc8183Contract).getJob(jobId);
    }

    // ──────────────────── Views ────────────────────

    /// @notice Get the ordered hook list for a job's selector
    function getHooks(uint256 jobId, bytes4 selector) external view returns (address[] memory) {
        return _jobHooks[jobId][selector];
    }

    /// @notice Get the number of hooks configured for a job's selector
    function hookCount(uint256 jobId, bytes4 selector) external view returns (uint256) {
        return _jobHooks[jobId][selector].length;
    }

    // ──────────────────── ERC165 ────────────────────

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC8183Hook).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ──────────────────── Internal ────────────────────

    /// @dev Check if a selector is one of the 5 hookable functions
    function _isKnownSelector(bytes4 selector) private pure returns (bool) {
        return selector == SEL_SET_BUDGET
            || selector == SEL_FUND
            || selector == SEL_SUBMIT
            || selector == SEL_COMPLETE
            || selector == SEL_REJECT;
    }

    /// @dev Validate and store hooks for a single selector (used by batchConfigureHooks)
    function _setHooksForSelector(
        uint256 jobId,
        bytes4 selector,
        address[] calldata hooks
    ) private {
        if (!_isKnownSelector(selector)) revert InvalidSelector();
        if (hooks.length > maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            _validateSubHook(hooks[i]);
            for (uint256 j; j < i; ) {
                if (hooks[j] == hooks[i]) revert DuplicateHook();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }

        _jobHooks[jobId][selector] = hooks;
        emit HooksConfigured(jobId, selector, hooks);
    }

    /// @dev Validate a sub-hook: non-zero, whitelisted on core, supports IERC8183Hook and IERC8183HookMetadata
    function _validateSubHook(address hook) private view {
        if (hook == address(0)) revert ZeroAddress();
        if (!ERC8183(erc8183Contract).whitelistedHooks(hook))
            revert SubHookNotWhitelisted();
        if (!ERC165Checker.supportsInterface(hook, type(IERC8183Hook).interfaceId))
            revert InvalidHook();
        if (!ERC165Checker.supportsInterface(hook, type(IERC8183HookMetadata).interfaceId))
            revert InvalidHook();
    }

    /// @dev Extract optParams from data, decode as bytes[], re-encode per hook.
    ///      Returns (false, empty) if optParams is empty/short (broadcast mode).
    ///      Returns (true, perHookData) if dispatch succeeded.
    function _splitHookData(
        bytes4 selector,
        bytes calldata data,
        uint256 hookCount_
    ) private pure returns (bool dispatched, bytes[] memory perHookData) {
        bytes memory optParams = _extractOptParams(selector, data);

        // Empty or too short to be a valid abi.encode(bytes[]) -- broadcast mode
        if (optParams.length < 64) return (false, perHookData);

        // Decode as bytes[]
        bytes[] memory hookDataArray = abi.decode(optParams, (bytes[]));

        // Length must match hook count
        if (hookDataArray.length != hookCount_) revert HookDataLengthMismatch();

        // Re-encode data for each hook with its own optParams slice
        perHookData = new bytes[](hookCount_);
        for (uint256 i; i < hookCount_; ) {
            perHookData[i] = _reEncodeData(selector, data, hookDataArray[i]);
            unchecked { ++i; }
        }
        return (true, perHookData);
    }

    /// @dev Extract optParams bytes from the ABI-encoded data based on selector.
    ///      Encoding matches ERC8183's data layout.
    function _extractOptParams(
        bytes4 selector,
        bytes calldata data
    ) private pure returns (bytes memory) {
        if (selector == SEL_SET_BUDGET) {
            // (address caller, address token, uint256 amount, bytes optParams)
            (, , , bytes memory optParams) = abi.decode(data, (address, address, uint256, bytes));
            return optParams;
        } else if (selector == SEL_FUND) {
            // (address caller, bytes optParams)
            (, bytes memory optParams) = abi.decode(data, (address, bytes));
            return optParams;
        } else {
            // submit, complete, reject: (address caller, bytes32 field2, bytes optParams)
            (, , bytes memory optParams) = abi.decode(data, (address, bytes32, bytes));
            return optParams;
        }
    }

    /// @dev Re-encode data with a hook-specific optParams replacing the original.
    function _reEncodeData(
        bytes4 selector,
        bytes calldata data,
        bytes memory hookOptParams
    ) private pure returns (bytes memory) {
        if (selector == SEL_SET_BUDGET) {
            (address caller, address token, uint256 amount, ) = abi.decode(data, (address, address, uint256, bytes));
            return abi.encode(caller, token, amount, hookOptParams);
        } else if (selector == SEL_FUND) {
            (address caller, ) = abi.decode(data, (address, bytes));
            return abi.encode(caller, hookOptParams);
        } else {
            // submit, complete, reject: (address caller, bytes32 field2, bytes optParams)
            (address caller, bytes32 field2, ) = abi.decode(data, (address, bytes32, bytes));
            return abi.encode(caller, field2, hookOptParams);
        }
    }

    /// @dev Validates that every hook configured for this job is present on ALL selectors
    ///      it declares as required via IERC8183HookMetadata.requiredSelectors().
    ///      Reverts with HookMissingRequiredSelector if any required selector is missing.
    function _validateSelectorCompleteness(uint256 jobId) private view {
        bytes4[5] memory sels = [SEL_SET_BUDGET, SEL_FUND, SEL_SUBMIT, SEL_COMPLETE, SEL_REJECT];

        // Collect unique hooks across all selectors
        uint256 maxUnique;
        for (uint256 s; s < 5; ) {
            maxUnique += _jobHooks[jobId][sels[s]].length;
            unchecked { ++s; }
        }
        address[] memory uniqueHooks = new address[](maxUnique);
        uint256 uniqueCount;

        for (uint256 s; s < 5; ) {
            address[] storage hooksForSel = _jobHooks[jobId][sels[s]];
            uint256 len = hooksForSel.length;
            for (uint256 i; i < len; ) {
                address hook = hooksForSel[i];
                bool found;
                for (uint256 u; u < uniqueCount; ) {
                    if (uniqueHooks[u] == hook) {
                        found = true;
                        break;
                    }
                    unchecked { ++u; }
                }
                if (!found) {
                    uniqueHooks[uniqueCount] = hook;
                    unchecked { ++uniqueCount; }
                }
                unchecked { ++i; }
            }
            unchecked { ++s; }
        }

        // For each unique hook, check its required selectors are all configured
        for (uint256 h; h < uniqueCount; ) {
            bytes4[] memory required = IERC8183HookMetadata(uniqueHooks[h]).requiredSelectors();
            uint256 reqLen = required.length;
            for (uint256 r; r < reqLen; ) {
                bool present;
                address[] storage hooksForReqSel = _jobHooks[jobId][required[r]];
                uint256 hLen = hooksForReqSel.length;
                for (uint256 k; k < hLen; ) {
                    if (hooksForReqSel[k] == uniqueHooks[h]) {
                        present = true;
                        break;
                    }
                    unchecked { ++k; }
                }
                if (!present) revert HookMissingRequiredSelector();
                unchecked { ++r; }
            }
            unchecked { ++h; }
        }
    }
}
