# CompositeRouterHook v2

Advanced composite hook router for ERC-8183 Agentic Commerce Protocol jobs with three-tier hook resolution, template system, and extension points for inheritance.

## Overview

CompositeRouterHook acts as a single hook address that fans out to multiple sub-hooks, enabling flexible composition of hook behaviors without deploying a new hook address for each job. Version 2 introduces:

- **Per-job hooks**: Fine-grained control per job (set by job client)
- **Template system**: Reusable hook configurations (set by owner, applied by clients)
- **Global plugins**: Default hooks for all jobs (set by owner)
- **Extension points**: Virtual functions for derived contracts (e.g., MaiatReputationRouter)

## Use Cases

1. **Token Safety Screening**: Before funding, verify token safety
2. **Trust Score Gating**: Before submission, check provider reputation
3. **Attestation Writing**: After completion, write on-chain attestations
4. **Multi-signature Approval**: Before high-value job completion
5. **Audit Logging**: After any action, log to external systems

## Three-Tier Hook Resolution

```
┌──────────────────────────────────────────────────────────────────┐
│                    Hook Resolution Flow                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  beforeAction(jobId, selector, data) called by AgenticCommerce  │
│                            │                                     │
│                            ▼                                     │
│              ┌─────────────────────────┐                        │
│              │   _beforeRoute()        │  ← Extension point     │
│              │   (virtual, override)   │                        │
│              └────────────┬────────────┘                        │
│                           │                                      │
│                           ▼                                      │
│              ┌─────────────────────────┐                        │
│              │   _resolveHooks(jobId)  │                        │
│              └────────────┬────────────┘                        │
│                           │                                      │
│         ┌─────────────────┼─────────────────┐                   │
│         │                 │                 │                   │
│         ▼                 ▼                 ▼                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Per-Job     │  │ Template    │  │ Global      │             │
│  │ Hooks       │  │ Hooks       │  │ Plugins     │             │
│  │ (Priority 1)│  │ (Priority 2)│  │ (Priority 3)│             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         │    if empty    │    if empty    │                     │
│         └───────────────►└───────────────►│                     │
│                                           │                     │
│                                           ▼                     │
│                            ┌─────────────────────────┐          │
│                            │ Execute hooks in order  │          │
│                            │ (sorted by priority for │          │
│                            │  global plugins)        │          │
│                            └─────────────────────────┘          │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Priority Order

1. **Per-job hooks** (highest priority): If set via `configureJobHooks()` or `addJobHook()`
2. **Template hooks** (medium priority): If template applied via `applyTemplate()`
3. **Global plugins** (fallback): Enabled plugins sorted by priority (ascending)

## Template System

Templates allow the owner to define reusable hook configurations that job clients can apply with a single call.

### Creating Templates (Owner)

```solidity
// Create a "standard-escrow" template
address[] memory hooks = new address[](3);
hooks[0] = address(tokenSafetyHook);
hooks[1] = address(trustScoreHook);
hooks[2] = address(attestationHook);

router.createTemplate(keccak256("standard-escrow"), hooks);
```

### Applying Templates (Job Client)

```solidity
// Client applies template to their job
router.applyTemplate(jobId, keccak256("standard-escrow"));
```

### Template Lifecycle

- Templates are created/deleted by the contract owner
- Hooks in templates must be whitelisted on AgenticCommerce
- Applying a template clears any per-job hooks
- If a template is deleted, jobs using it fall back to global plugins

## Extension Points for Inheritance

CompositeRouterHook provides virtual functions that derived contracts can override:

```solidity
contract MaiatReputationRouter is CompositeRouterHook {
    mapping(address => uint256) public reputationScores;

    function _beforeRoute(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) internal override {
        // Custom logic before hook iteration
        // Example: Check reputation threshold
        IAgenticCommerce.Job memory job = getJob(jobId);
        if (selector == SUBMIT_SELECTOR) {
            require(reputationScores[job.provider] >= MIN_REPUTATION, "Low reputation");
        }
    }

    function _afterRoute(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) internal override {
        // Custom logic before hook iteration in afterAction
        // Example: Update reputation after completion
        if (selector == COMPLETE_SELECTOR) {
            IAgenticCommerce.Job memory job = getJob(jobId);
            reputationScores[job.provider] += REPUTATION_BONUS;
        }
    }
}
```

### Extension Point Behavior

| Function | Called In | Reverts Block Action? | Use Case |
|----------|-----------|----------------------|----------|
| `_beforeRoute()` | `beforeAction()` | Yes | Pre-validation, gating |
| `_afterRoute()` | `afterAction()` | No (try/catch) | Side effects, logging |

## Public Functions

### Initialization

#### `initialize(address agenticCommerce_, address owner_, uint256 maxHooksPerJob_)`
Initialize the upgradeable contract.

| Parameter | Type | Description |
|-----------|------|-------------|
| `agenticCommerce_` | `address` | AgenticCommerce contract address |
| `owner_` | `address` | Contract owner address |
| `maxHooksPerJob_` | `uint256` | Maximum hooks allowed per job (default: 10) |

### IACPHook Interface

#### `beforeAction(uint256 jobId, bytes4 selector, bytes calldata data)`
Called by AgenticCommerce before state transitions. Executes `_beforeRoute()`, then resolved hooks. Reverts propagate.

#### `afterAction(uint256 jobId, bytes4 selector, bytes calldata data)`
Called by AgenticCommerce after state transitions. Executes `_afterRoute()`, then resolved hooks with try/catch.

### Global Plugin Management (Owner Only)

#### `addPlugin(address hook, uint256 priority)`
Add a global plugin. Lower priority = executes first.

#### `removePlugin(address hook)`
Remove a global plugin.

#### `enablePlugin(address hook)`
Enable a disabled global plugin.

#### `disablePlugin(address hook)`
Disable a global plugin without removing it.

#### `setPluginPriority(address hook, uint256 newPriority)`
Update a plugin's execution priority.

### Template Management (Owner Only)

#### `createTemplate(bytes32 name, address[] calldata hooks)`
Create a reusable hook template. Hooks are validated for whitelist and ERC165.

#### `removeTemplate(bytes32 name)`
Remove a template. Jobs using it will fall back to global plugins.

### Per-Job Hook Management (Job Client Only)

#### `applyTemplate(uint256 jobId, bytes32 templateName)`
Apply a template to a job. Only while job status is `Open`.

#### `configureJobHooks(uint256 jobId, address[] calldata hooks)`
Set per-job hooks (replaces any existing). Only while job status is `Open`.

#### `addJobHook(uint256 jobId, address hook)`
Add a single hook to job's hook list. Only while job status is `Open`.

#### `removeJobHook(uint256 jobId, address hook)`
Remove a hook from job's hook list. Only while job status is `Open`.

### View Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `getPlugins()` | `Plugin[] memory` | All registered global plugins |
| `getPluginCount()` | `uint256` | Number of global plugins |
| `isPluginRegistered(address)` | `bool` | Check if hook is global plugin |
| `getPluginInfo(address)` | `(bool, uint256)` | Plugin enabled status and priority |
| `getJobHooks(uint256)` | `address[] memory` | Per-job hooks for a job |
| `getTemplate(bytes32)` | `address[] memory` | Hooks in a template |
| `getJobTemplate(uint256)` | `bytes32` | Template applied to a job |
| `getJob(uint256)` | `Job memory` | Passthrough to AgenticCommerce |

### Admin Functions

#### `setAgenticCommerce(address agenticCommerce_)`
Update the AgenticCommerce contract reference.

## Events

### Global Plugin Events

```solidity
event PluginAdded(address indexed hook, uint256 priority);
event PluginRemoved(address indexed hook);
event PluginEnabled(address indexed hook);
event PluginDisabled(address indexed hook);
event PluginPriorityUpdated(address indexed hook, uint256 oldPriority, uint256 newPriority);
event AgenticCommerceUpdated(address indexed oldAC, address indexed newAC);
```

### Hook Execution Events

```solidity
event PluginBeforeActionFailed(address indexed hook, uint256 indexed jobId, bytes reason);
event PluginAfterActionFailed(address indexed hook, uint256 indexed jobId, bytes reason);
```

### Template Events

```solidity
event TemplateCreated(bytes32 indexed name, address[] hooks);
event TemplateRemoved(bytes32 indexed name);
event TemplateApplied(uint256 indexed jobId, bytes32 indexed name);
```

### Per-Job Hook Events

```solidity
event JobHooksConfigured(uint256 indexed jobId, address[] hooks);
event JobHookAdded(uint256 indexed jobId, address indexed hook);
event JobHookRemoved(uint256 indexed jobId, address indexed hook);
```

## Errors

| Error | Description |
|-------|-------------|
| `CompositeRouterHook__ZeroAddress()` | Address parameter is zero |
| `CompositeRouterHook__OnlyAgenticCommerce()` | Caller is not AgenticCommerce |
| `CompositeRouterHook__MaxPluginsReached()` | Global plugin limit (10) reached |
| `CompositeRouterHook__PluginAlreadyRegistered(address)` | Plugin already registered globally |
| `CompositeRouterHook__PluginNotFound(address)` | Plugin not found |
| `CompositeRouterHook__HooksLocked()` | Job is not in Open status |
| `CompositeRouterHook__NotJobClient()` | Caller is not the job's client |
| `CompositeRouterHook__TemplateNotFound(bytes32)` | Template does not exist |
| `CompositeRouterHook__SubHookNotWhitelisted(address)` | Hook not whitelisted on AgenticCommerce |
| `CompositeRouterHook__InvalidHook(address)` | Hook does not implement IACPHook |
| `CompositeRouterHook__DuplicateHook(address)` | Hook already in list |
| `CompositeRouterHook__TooManyJobHooks()` | Per-job hook limit reached |
| `CompositeRouterHook__MaxJobHooksReached()` | Global plugin limit reached |

## Security Considerations

1. **Access Control**: Only AgenticCommerce can call `beforeAction`/`afterAction`
2. **Hook Validation**: All sub-hooks must be whitelisted on AgenticCommerce and support ERC165
3. **Locking**: Per-job hooks can only be configured while job is `Open`
4. **Reentrancy**: Uses `ReentrancyGuardTransient` for protection
5. **afterAction Safety**: Failures emit events but don't revert (critical for reputation layer)
6. **Gas Limits**: MAX_PLUGINS = 10 for global plugins; maxHooksPerJob configurable

## Upgradeability

The contract is upgradeable using OpenZeppelin's UUPS pattern:

- Inherits `OwnableUpgradeable`
- Uses `initializer` modifier
- Includes `__gap` storage for future fields
- Constructor calls `_disableInitializers()`
