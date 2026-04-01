// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IACPHook} from "@acp/IACPHook.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

/// @dev Minimal interface to AgenticCommerce for whitelisting and job lookups
interface IAgenticCommerce {
    enum JobStatus {
        Open,
        Funded,
        Submitted,
        Completed,
        Rejected,
        Expired
    }

    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        string description;
        uint256 budget;
        uint256 expiredAt;
        JobStatus status;
        address hook;
        address paymentToken;
        uint256 providerAgentId;
    }

    function whitelistedHooks(address hook) external view returns (bool);
    function getJob(uint256 jobId) external view returns (Job memory);
}

/**
 * @title CompositeRouterHook
 * @notice Advanced composite hook router with three-tier hook resolution:
 *         1. Per-job hooks (highest priority)
 *         2. Template-based hooks (medium priority)
 *         3. Global plugins (fallback)
 *
 * USE CASE
 * --------
 * A single ACP job often needs multiple orthogonal safety checks — e.g.
 * token safety screening before funding, trust-score gating before
 * submission, and attestation writing after completion. CompositeRouterHook
 * provides flexible composition at three levels:
 *   - Global plugins: Default hooks for all jobs (set by owner)
 *   - Templates: Reusable hook configurations (set by owner, applied by clients)
 *   - Per-job hooks: Fine-grained control per job (set by job client)
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *  2. Any ACP lifecycle call (fund, submit, complete, reject, …)
 *     → beforeAction: call _beforeRoute(), then iterate resolved hooks;
 *       call hook.beforeAction(jobId, selector, data) for each.
 *       If any hook reverts, the entire beforeAction reverts.
 *     → afterAction: call _afterRoute(), then iterate resolved hooks;
 *       try/catch per hook, emit PluginAfterActionFailed on failure
 *       (does NOT block the job state transition).
 *  3. Owner manages global plugins and templates.
 *  4. Job clients configure per-job hooks or apply templates.
 *
 * TRUST MODEL
 * -----------
 * Only AgenticCommerce can invoke beforeAction/afterAction on this router.
 * Only the owner can modify global plugins and templates.
 * Job clients can configure per-job hooks only while job is Open.
 * beforeAction failures are surfaced as reverts (hard safety).
 * afterAction failures are swallowed and logged (soft observability).
 *
 * EXTENSION POINTS
 * ----------------
 * Inherit from this contract and override:
 *   - _beforeRoute: Custom logic before iterating hooks
 *   - _afterRoute: Custom logic after iterating hooks
 * Example: MaiatReputationRouter extends this to add reputation scoring.
 *
 * @custom:security-contact security@erc-8183.org
 */
contract CompositeRouterHook is IACPHook, OwnableUpgradeable, ReentrancyGuardTransient {
    /*//////////////////////////////////////////////////////////////
                            TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Plugin configuration for global hooks
    struct Plugin {
        IACPHook hook;
        bool enabled;
        uint256 priority;
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum number of global plugins (gas safety)
    uint256 public constant MAX_PLUGINS = 10;

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice AgenticCommerce contract — used for access control and job lookups
    address public s_agenticCommerce;

    /// @notice Array of registered global plugins
    Plugin[] private s_plugins;

    /// @notice Mapping to check if a hook address is registered as global plugin
    mapping(address => bool) public s_registered;

    /// @notice Maximum hooks per job (configurable via initialize)
    uint256 public maxHooksPerJob;

    /// @notice Per-job hook lists
    mapping(uint256 jobId => address[]) private s_jobHooks;

    /// @notice Template definitions: name => hook addresses
    mapping(bytes32 name => address[]) private s_templates;

    /// @notice Which template is applied to each job (if any)
    mapping(uint256 jobId => bytes32) private s_jobTemplate;

    /// @dev Reserved storage gap for future upgrades
    uint256[40] private __gap;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event PluginAdded(address indexed hook, uint256 priority);
    event PluginRemoved(address indexed hook);
    event PluginEnabled(address indexed hook);
    event PluginDisabled(address indexed hook);
    event PluginPriorityUpdated(address indexed hook, uint256 oldPriority, uint256 newPriority);
    event AgenticCommerceUpdated(address indexed oldAC, address indexed newAC);
    event PluginBeforeActionFailed(address indexed hook, uint256 indexed jobId, bytes reason);
    event PluginAfterActionFailed(address indexed hook, uint256 indexed jobId, bytes reason);

    // Template events
    event TemplateCreated(bytes32 indexed name, address[] hooks);
    event TemplateRemoved(bytes32 indexed name);
    event TemplateApplied(uint256 indexed jobId, bytes32 indexed name);

    // Per-job hook events
    event JobHooksConfigured(uint256 indexed jobId, address[] hooks);
    event JobHookAdded(uint256 indexed jobId, address indexed hook);
    event JobHookRemoved(uint256 indexed jobId, address indexed hook);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error CompositeRouterHook__ZeroAddress();
    error CompositeRouterHook__OnlyAgenticCommerce();
    error CompositeRouterHook__MaxPluginsReached();
    error CompositeRouterHook__PluginAlreadyRegistered(address hook);
    error CompositeRouterHook__PluginNotFound(address hook);
    error CompositeRouterHook__HooksLocked();
    error CompositeRouterHook__NotJobClient();
    error CompositeRouterHook__TemplateNotFound(bytes32 name);
    error CompositeRouterHook__SubHookNotWhitelisted(address hook);
    error CompositeRouterHook__InvalidHook(address hook);
    error CompositeRouterHook__DuplicateHook(address hook);
    error CompositeRouterHook__MaxJobHooksReached();
    error CompositeRouterHook__JobHookNotFound(address hook);

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Ensures job hooks can only be configured while job is Open
    modifier hooksNotLocked(uint256 jobId) {
        IAgenticCommerce.Job memory job = IAgenticCommerce(s_agenticCommerce).getJob(jobId);
        if (job.status != IAgenticCommerce.JobStatus.Open) {
            revert CompositeRouterHook__HooksLocked();
        }
        _;
    }

    /// @notice Ensures only the job's client can configure per-job hooks
    modifier onlyJobClient(uint256 jobId) {
        IAgenticCommerce.Job memory job = IAgenticCommerce(s_agenticCommerce).getJob(jobId);
        if (msg.sender != job.client) {
            revert CompositeRouterHook__NotJobClient();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the CompositeRouterHook
     * @param agenticCommerce_ AgenticCommerce contract address
     * @param owner_ Contract owner address
     * @param maxHooksPerJob_ Maximum hooks allowed per job
     */
    function initialize(
        address agenticCommerce_,
        address owner_,
        uint256 maxHooksPerJob_
    ) external initializer {
        if (agenticCommerce_ == address(0)) revert CompositeRouterHook__ZeroAddress();
        if (owner_ == address(0)) revert CompositeRouterHook__ZeroAddress();

        __Ownable_init(owner_);
        s_agenticCommerce = agenticCommerce_;
        maxHooksPerJob = maxHooksPerJob_ > 0 ? maxHooksPerJob_ : 10;
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: beforeAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called before state transitions. Executes resolved hooks in order.
     * @dev Only callable by AgenticCommerce. If any hook reverts, entire call reverts.
     * @param jobId The job ID
     * @param selector The function selector being called
     * @param data Encoded function parameters
     */
    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override nonReentrant {
        if (msg.sender != s_agenticCommerce) revert CompositeRouterHook__OnlyAgenticCommerce();

        // Virtual extension point
        _beforeRoute(jobId, selector, data);

        // Resolve hooks for this job
        address[] memory hooks = _resolveHooks(jobId);
        uint256 len = hooks.length;

        // Execute hooks in order (no try/catch — revert propagates)
        for (uint256 i = 0; i < len; i++) {
            IACPHook(hooks[i]).beforeAction(jobId, selector, data);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: afterAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after state transitions. Executes resolved hooks in order.
     * @dev Only callable by AgenticCommerce. Uses try/catch so failures don't revert.
     * @param jobId The job ID
     * @param selector The function selector being called
     * @param data Encoded function parameters
     */
    function afterAction(uint256 jobId, bytes4 selector, bytes calldata data) external override nonReentrant {
        if (msg.sender != s_agenticCommerce) revert CompositeRouterHook__OnlyAgenticCommerce();

        // Virtual extension point
        _afterRoute(jobId, selector, data);

        // Resolve hooks for this job
        address[] memory hooks = _resolveHooks(jobId);
        uint256 len = hooks.length;

        // Execute hooks in order (try/catch — failures don't block job)
        for (uint256 i = 0; i < len; i++) {
            try IACPHook(hooks[i]).afterAction(jobId, selector, data) {
                // Success — continue to next hook
            } catch (bytes memory reason) {
                emit PluginAfterActionFailed(hooks[i], jobId, reason);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-165
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice ERC-165 interface support
     * @param interfaceId The interface identifier
     * @return True if supported
     */
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IACPHook).interfaceId
            || interfaceId == 0x01ffc9a7; // IERC165
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN: Global Plugin Management
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new global plugin hook
     * @param hook The hook contract address
     * @param priority Execution priority (lower = earlier)
     */
    function addPlugin(address hook, uint256 priority) external onlyOwner {
        if (hook == address(0)) revert CompositeRouterHook__ZeroAddress();
        if (s_registered[hook]) revert CompositeRouterHook__PluginAlreadyRegistered(hook);
        if (s_plugins.length >= MAX_PLUGINS) revert CompositeRouterHook__MaxPluginsReached();

        s_plugins.push(Plugin({
            hook: IACPHook(hook),
            enabled: true,
            priority: priority
        }));
        s_registered[hook] = true;

        emit PluginAdded(hook, priority);
    }

    /**
     * @notice Remove a global plugin hook
     * @param hook The hook contract address to remove
     */
    function removePlugin(address hook) external onlyOwner {
        if (!s_registered[hook]) revert CompositeRouterHook__PluginNotFound(hook);

        uint256 len = s_plugins.length;
        for (uint256 i = 0; i < len; i++) {
            if (address(s_plugins[i].hook) == hook) {
                // Swap with last and pop
                if (i != len - 1) {
                    s_plugins[i] = s_plugins[len - 1];
                }
                s_plugins.pop();
                s_registered[hook] = false;

                emit PluginRemoved(hook);
                return;
            }
        }

        // Should not reach here due to s_registered check
        revert CompositeRouterHook__PluginNotFound(hook);
    }

    /**
     * @notice Enable a global plugin
     * @param hook The hook contract address to enable
     */
    function enablePlugin(address hook) external onlyOwner {
        if (!s_registered[hook]) revert CompositeRouterHook__PluginNotFound(hook);

        uint256 len = s_plugins.length;
        for (uint256 i = 0; i < len; i++) {
            if (address(s_plugins[i].hook) == hook) {
                s_plugins[i].enabled = true;
                emit PluginEnabled(hook);
                return;
            }
        }
    }

    /**
     * @notice Disable a global plugin
     * @param hook The hook contract address to disable
     */
    function disablePlugin(address hook) external onlyOwner {
        if (!s_registered[hook]) revert CompositeRouterHook__PluginNotFound(hook);

        uint256 len = s_plugins.length;
        for (uint256 i = 0; i < len; i++) {
            if (address(s_plugins[i].hook) == hook) {
                s_plugins[i].enabled = false;
                emit PluginDisabled(hook);
                return;
            }
        }
    }

    /**
     * @notice Update a global plugin's priority
     * @param hook The hook contract address
     * @param newPriority The new priority value
     */
    function setPluginPriority(address hook, uint256 newPriority) external onlyOwner {
        if (!s_registered[hook]) revert CompositeRouterHook__PluginNotFound(hook);

        uint256 len = s_plugins.length;
        for (uint256 i = 0; i < len; i++) {
            if (address(s_plugins[i].hook) == hook) {
                uint256 oldPriority = s_plugins[i].priority;
                s_plugins[i].priority = newPriority;
                emit PluginPriorityUpdated(hook, oldPriority, newPriority);
                return;
            }
        }
    }

    /**
     * @notice Update the AgenticCommerce contract reference
     * @param agenticCommerce_ New AgenticCommerce address
     */
    function setAgenticCommerce(address agenticCommerce_) external onlyOwner {
        if (agenticCommerce_ == address(0)) revert CompositeRouterHook__ZeroAddress();
        address old = s_agenticCommerce;
        s_agenticCommerce = agenticCommerce_;
        emit AgenticCommerceUpdated(old, agenticCommerce_);
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN: Template Management
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a reusable hook template
     * @param name Template identifier (bytes32)
     * @param hooks Array of hook addresses in execution order
     */
    function createTemplate(bytes32 name, address[] calldata hooks) external onlyOwner {
        uint256 len = hooks.length;
        if (len > maxHooksPerJob) revert CompositeRouterHook__MaxJobHooksReached();

        // Validate all hooks
        for (uint256 i = 0; i < len; i++) {
            _validateSubHook(hooks[i]);
            // Check for duplicates
            for (uint256 j = i + 1; j < len; j++) {
                if (hooks[i] == hooks[j]) {
                    revert CompositeRouterHook__DuplicateHook(hooks[i]);
                }
            }
        }

        s_templates[name] = hooks;
        emit TemplateCreated(name, hooks);
    }

    /**
     * @notice Remove a template
     * @param name Template identifier
     */
    function removeTemplate(bytes32 name) external onlyOwner {
        delete s_templates[name];
        emit TemplateRemoved(name);
        // Note: existing jobs with s_jobTemplate[jobId] == name will silently
        // fall through to global plugins on next _resolveHooks() call.
        // This is intentional — jobs are not invalidated, they degrade gracefully.
    }

    /*//////////////////////////////////////////////////////////////
                    JOB CLIENT: Per-Job Hook Management
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Apply a template to a job
     * @param jobId The job ID
     * @param templateName The template to apply
     */
    function applyTemplate(
        uint256 jobId,
        bytes32 templateName
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        address[] storage tmpl = s_templates[templateName];
        if (tmpl.length == 0) {
            revert CompositeRouterHook__TemplateNotFound(templateName);
        }
        // Validate template hook count against current maxHooksPerJob
        if (tmpl.length > maxHooksPerJob) revert CompositeRouterHook__MaxJobHooksReached();

        // Clear any per-job hooks when applying template
        delete s_jobHooks[jobId];
        s_jobTemplate[jobId] = templateName;

        emit TemplateApplied(jobId, templateName);
    }

    /**
     * @notice Configure per-job hooks (replaces any existing configuration)
     * @param jobId The job ID
     * @param hooks Array of hook addresses in execution order
     */
    function configureJobHooks(
        uint256 jobId,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        uint256 len = hooks.length;
        if (len > maxHooksPerJob) revert CompositeRouterHook__MaxJobHooksReached();

        // Validate all hooks
        for (uint256 i = 0; i < len; i++) {
            _validateSubHook(hooks[i]);
            // Check for duplicates
            for (uint256 j = i + 1; j < len; j++) {
                if (hooks[i] == hooks[j]) {
                    revert CompositeRouterHook__DuplicateHook(hooks[i]);
                }
            }
        }

        // Clear any applied template when setting per-job hooks
        delete s_jobTemplate[jobId];
        s_jobHooks[jobId] = hooks;

        emit JobHooksConfigured(jobId, hooks);
    }

    /**
     * @notice Add a single hook to a job's hook list
     * @param jobId The job ID
     * @param hook The hook address to add
     */
    function addJobHook(
        uint256 jobId,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        _validateSubHook(hook);

        address[] storage jobHooks = s_jobHooks[jobId];

        // Check for duplicate
        uint256 len = jobHooks.length;
        for (uint256 i = 0; i < len; i++) {
            if (jobHooks[i] == hook) {
                revert CompositeRouterHook__DuplicateHook(hook);
            }
        }

        if (len >= maxHooksPerJob) revert CompositeRouterHook__MaxJobHooksReached();

        // Clear any applied template when modifying per-job hooks
        delete s_jobTemplate[jobId];
        jobHooks.push(hook);

        emit JobHookAdded(jobId, hook);
    }

    /**
     * @notice Remove a hook from a job's hook list
     * @param jobId The job ID
     * @param hook The hook address to remove
     */
    function removeJobHook(
        uint256 jobId,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        address[] storage jobHooks = s_jobHooks[jobId];
        uint256 len = jobHooks.length;
        bool found = false;

        for (uint256 i = 0; i < len; i++) {
            if (jobHooks[i] == hook) {
                // Swap with last and pop
                if (i != len - 1) {
                    jobHooks[i] = jobHooks[len - 1];
                }
                jobHooks.pop();
                found = true;
                break;
            }
        }

        if (!found) revert CompositeRouterHook__JobHookNotFound(hook);

        // Clear any applied template when modifying per-job hooks
        delete s_jobTemplate[jobId];

        emit JobHookRemoved(jobId, hook);
    }

    /*//////////////////////////////////////////////////////////////
                    VIEW: Global Plugins
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get all registered global plugins
     * @return Array of plugin configurations
     */
    function getPlugins() external view returns (Plugin[] memory) {
        return s_plugins;
    }

    /**
     * @notice Get the number of registered global plugins
     * @return Plugin count
     */
    function getPluginCount() external view returns (uint256) {
        return s_plugins.length;
    }

    /**
     * @notice Check if a hook is registered as global plugin
     * @param hook The hook address to check
     * @return True if registered
     */
    function isPluginRegistered(address hook) external view returns (bool) {
        return s_registered[hook];
    }

    /**
     * @notice Get global plugin info by address
     * @param hook The hook address
     * @return enabled Whether the plugin is enabled
     * @return priority The plugin's priority
     */
    function getPluginInfo(address hook) external view returns (bool enabled, uint256 priority) {
        if (!s_registered[hook]) revert CompositeRouterHook__PluginNotFound(hook);

        uint256 len = s_plugins.length;
        for (uint256 i = 0; i < len; i++) {
            if (address(s_plugins[i].hook) == hook) {
                return (s_plugins[i].enabled, s_plugins[i].priority);
            }
        }

        // Should not reach here
        revert CompositeRouterHook__PluginNotFound(hook);
    }

    /*//////////////////////////////////////////////////////////////
                    VIEW: Per-Job & Templates
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the hooks configured for a specific job
     * @param jobId The job ID
     * @return Array of hook addresses
     */
    function getJobHooks(uint256 jobId) external view returns (address[] memory) {
        return s_jobHooks[jobId];
    }

    /**
     * @notice Get hooks defined in a template
     * @param name The template identifier
     * @return Array of hook addresses
     */
    function getTemplate(bytes32 name) external view returns (address[] memory) {
        return s_templates[name];
    }

    /**
     * @notice Get which template is applied to a job
     * @param jobId The job ID
     * @return Template name (bytes32(0) if none)
     */
    function getJobTemplate(uint256 jobId) external view returns (bytes32) {
        return s_jobTemplate[jobId];
    }

    /**
     * @notice Passthrough to get job info from AgenticCommerce
     * @param jobId The job ID
     * @return The job struct
     */
    function getJob(uint256 jobId) external view returns (IAgenticCommerce.Job memory) {
        return IAgenticCommerce(s_agenticCommerce).getJob(jobId);
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL: Hook Resolution
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Resolve which hooks to execute for a job
     * @dev Priority order: per-job hooks > template > global plugins
     * @param jobId The job ID
     * @return hooks Array of hook addresses to execute
     */
    function _resolveHooks(uint256 jobId) internal view returns (address[] memory hooks) {
        // 1. Per-job hooks have highest priority
        address[] storage jobHooks = s_jobHooks[jobId];
        if (jobHooks.length > 0) {
            return jobHooks;
        }

        // 2. Template-based hooks
        bytes32 templateName = s_jobTemplate[jobId];
        if (templateName != bytes32(0)) {
            address[] storage templateHooks = s_templates[templateName];
            if (templateHooks.length > 0) {
                return templateHooks;
            }
        }

        // 3. Fall back to global plugins (sorted by priority)
        return _getEnabledGlobalHooks();
    }

    /**
     * @notice Get enabled global plugins sorted by priority
     * @return hooks Array of enabled plugin addresses
     */
    function _getEnabledGlobalHooks() internal view returns (address[] memory hooks) {
        uint256 len = s_plugins.length;
        if (len == 0) return new address[](0);

        // Count enabled plugins
        uint256 enabledCount = 0;
        for (uint256 i = 0; i < len; i++) {
            if (s_plugins[i].enabled) {
                enabledCount++;
            }
        }

        if (enabledCount == 0) return new address[](0);

        // Get sorted indices
        uint256[] memory sortedIndices = _getSortedIndices();

        // Build result array with only enabled plugins
        hooks = new address[](enabledCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < len; i++) {
            Plugin storage plugin = s_plugins[sortedIndices[i]];
            if (plugin.enabled) {
                hooks[idx++] = address(plugin.hook);
            }
        }

        return hooks;
    }

    /**
     * @dev Get indices sorted by priority (ascending)
     *      Uses simple insertion sort since MAX_PLUGINS = 10
     * @return sortedIndices Array of indices into s_plugins sorted by priority
     */
    function _getSortedIndices() internal view returns (uint256[] memory sortedIndices) {
        uint256 len = s_plugins.length;
        sortedIndices = new uint256[](len);

        // Initialize indices
        for (uint256 i = 0; i < len; i++) {
            sortedIndices[i] = i;
        }

        // Insertion sort by priority (ascending)
        for (uint256 i = 1; i < len; i++) {
            uint256 key = sortedIndices[i];
            uint256 keyPriority = s_plugins[key].priority;
            uint256 j = i;

            while (j > 0 && s_plugins[sortedIndices[j - 1]].priority > keyPriority) {
                sortedIndices[j] = sortedIndices[j - 1];
                j--;
            }
            sortedIndices[j] = key;
        }

        return sortedIndices;
    }

    /**
     * @notice Validate a sub-hook before registration
     * @dev Checks non-zero, whitelisted on AgenticCommerce, and ERC165 support
     * @param hook The hook address to validate
     */
    function _validateSubHook(address hook) internal view {
        if (hook == address(0)) {
            revert CompositeRouterHook__ZeroAddress();
        }

        // Check whitelisted on AgenticCommerce
        if (!IAgenticCommerce(s_agenticCommerce).whitelistedHooks(hook)) {
            revert CompositeRouterHook__SubHookNotWhitelisted(hook);
        }

        // Check ERC165 support for IACPHook
        if (!ERC165Checker.supportsInterface(hook, type(IACPHook).interfaceId)) {
            revert CompositeRouterHook__InvalidHook(hook);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    VIRTUAL EXTENSION POINTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Virtual hook called before iterating hooks in beforeAction
     * @dev Override in derived contracts for custom pre-processing
     * @param jobId The job ID
     * @param selector The function selector being called
     * @param data Encoded function parameters
     */
    function _beforeRoute(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) internal virtual {
        // Default: no-op. Override in derived contracts.
    }

    /**
     * @notice Virtual hook called before iterating hooks in afterAction
     * @dev Override in derived contracts for custom post-processing
     * @param jobId The job ID
     * @param selector The function selector being called
     * @param data Encoded function parameters
     */
    function _afterRoute(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) internal virtual {
        // Default: no-op. Override in derived contracts.
    }
}
