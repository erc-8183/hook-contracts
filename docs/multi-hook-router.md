# Multi-Hook Router

## The Problem

Today, each ERC-8183 job can only attach **one hook**. If a job needs escrow handling, privacy verification, and reputation tracking, all that logic must be crammed into a single contract.

This creates **monolithic hooks** — hard to build, hard to audit, and impossible to reuse across different job types.

## The Solution

A **Multi-Hook Router** sits between the core contract and individual hooks, forwarding callbacks to an ordered list of small, focused hooks.

```
                            CURRENT                              PROPOSED
                     ┌────────────────┐                   ┌────────────────┐
                     │   ERC-8183     │                   │   ERC-8183     │
                     └───────┬────────┘                   └───────┬────────┘
                             │                                    │
                             ▼                                    ▼
                   ┌──────────────────┐               ┌───────────────────┐
                   │  Single Hook     │               │  MultiHookRouter  │
                   │  (does everything│               └──┬──────┬──────┬──┘
                   │   or nothing)    │                  │      │      │
                   └──────────────────┘                  ▼      ▼      ▼
                                                      Hook1  Hook2  Hook3
                                                    (escrow)(privacy)(reputation)
```

## How It Works

1. Job creator sets the **MultiHookRouter** as the job's hook
2. Client configures which sub-hooks to use **per selector** — each hookable function (setBudget, fund, submit, complete, reject) has its own ordered hook list per job
3. On every state transition:
   - Router looks up the hooks for that specific selector
   - Calls each sub-hook's `beforeAction` in order — any can block the transition
   - Core executes the state change
   - Calls each sub-hook's `afterAction` in order — for bookkeeping
4. If a sub-hook was de-whitelisted after configuration, it is skipped (not reverted) with a `DewhitelistedHookSkipped` event

## Per-Selector Architecture

Unlike a flat router where every hook fires on every action, hooks are registered per selector:

```
Job #42 hook configuration:

  setBudget  → [BiddingHook]
  fund       → [FundTransferHook, LoggingHook]
  submit     → [FundTransferHook]
  complete   → [FundTransferHook, ReputationHook]
  reject     → [FundTransferHook]
```

A `ReputationHook` that only cares about completion is never called during `fund` or `submit`. This saves gas and avoids unnecessary coupling.

### Configuration Methods

| Method | Use Case |
|--------|----------|
| `configureHooks(jobId, selector, hooks)` | Set hooks for a single selector |
| `batchConfigureHooks(jobId, selectors, hooksPerSelector)` | Set hooks for multiple selectors atomically |
| `addHook(jobId, selector, hook)` | Append one hook to a selector's list |
| `removeHook(jobId, selector, hook)` | Remove one hook from a selector's list |
| `reorderHooks(jobId, selector, hooks)` | Reorder a selector's hook list (must be a permutation) |

All configuration is locked once the job leaves `Open` status (i.e., after funding).

## Per-Hook Data Dispatch

The router supports sending different `optParams` to each hook in a single call:

- **Broadcast mode** (default): When `optParams` is empty or < 64 bytes, every hook receives the same data unchanged.
- **Dispatch mode**: Caller encodes `optParams` as `abi.encode(bytes[])` where `bytes[i]` is the optParams for hook at position `i`. The router decodes, re-encodes each hook's data slice with the correct surrounding fields (caller, token, amount, etc.), and dispatches individually. If `bytes[].length` does not match the hook count, the call reverts with `HookDataLengthMismatch`.

Example — 2 hooks, each gets different optParams:

```solidity
bytes[] memory perHookOpt = new bytes[](2);
perHookOpt[0] = abi.encode(buyer, transferAmount); // FundTransferHook
perHookOpt[1] = "";                                 // LoggingHook (no data)
erc8183.setBudget(jobId, token, amount, abi.encode(perHookOpt));
```

## IERC8183HookMetadata — Selector Completeness

Hooks implement `IERC8183HookMetadata.requiredSelectors()` to declare cross-selector dependencies. For example, a `FundTransferHook` that needs to run on both `fund` and `submit` can declare both as required. The router validates completeness:

- **At `batchConfigureHooks` time**: immediately after storing, before returning.
- **At `fund` time**: the first non-config lifecycle call, as a safety net for hooks configured via single-selector `configureHooks` calls.

If any hook is configured for some selectors but missing from one it declared as required, the call reverts with `HookMissingRequiredSelector`.

## Hook Flow

### Without MultiHookRouter (Single Hook)

```
Client                    ERC-8183              Single Hook
  |                          |                      |
  |-- fund() -------------->|                      |
  |                          |-- beforeAction() -->|
  |                          |<--------------------|
  |                          |                      |
  |                          |  [state change]      |
  |                          |                      |
  |                          |-- afterAction() --->|
  |                          |<--------------------|
  |<-------------------------|                      |
```

One hook = 2 external calls per transition. Always.

### With MultiHookRouter — 5 Hooks

```
Client          ERC-8183          Router           H1    H2    H3    H4    H5
  |                |                 |
  |-- fund() ---->|                 |
  |                |-- beforeAction()-->|
  |                |                 |-- before() -->|
  |                |                 |<--------------|
  |                |                 |-- before() -------->|
  |                |                 |<--------------------|
  |                |                 |-- before() -------------->|
  |                |                 |<--------------------------|
  |                |                 |-- before() ---------------------->|
  |                |                 |<---------------------------------|
  |                |                 |-- before() ------------------------------>|
  |                |                 |<-----------------------------------------|
  |                |<----------------|
  |                |                 |
  |                |  [state change] |
  |                |                 |
  |                |-- afterAction()-->|
  |                |                 |-- after() --->|
  |                |                 |<--------------|
  |                |                 |-- after() ---------->|
  |                |                 |<--------------------|
  |                |                 |-- after() --------------->|
  |                |                 |<--------------------------|
  |                |                 |-- after() ----------------------->|
  |                |                 |<---------------------------------|
  |                |                 |-- after() -------------------------------->|
  |                |                 |<------------------------------------------|
  |                |<----------------|
  |<---------------|

External calls: 2 (core -> router) + 10 (router -> hooks) = 12 total
```

### Gas Overhead

| Hooks | External Calls Per Transition | Estimated Router Overhead |
|-------|-------------------------------|---------------------------|
| 0 (no router) | 2 (core -> hook) | -- |
| 1 (via router) | 4 (core -> router -> hook x2) | ~3,000 gas |
| 5 | 12 | ~15,000 gas |
| 10 | 22 | ~30,000 gas |
| 20 | 42 | ~60,000 gas |

The formula is `2 + (N x 2)` external calls per transition, where N is the number of hooks configured for that specific selector (not the total across all selectors). Each call from the router to a sub-hook is sequential — if any `beforeAction` reverts, the remaining hooks are never called and the entire transition is blocked.

## Sub-Hook Requirements

Sub-hooks must:
- Be whitelisted on the core contract (`whitelistedHooks`)
- Implement `IERC8183Hook` (ERC165 checked)
- Implement `IERC8183HookMetadata` (ERC165 checked) — return `requiredSelectors()`
- Hooks extending `BaseERC8183Hook` get `IERC8183Hook` for free but must add `IERC8183HookMetadata` individually

## Comparison

|  | Current (Single Hook) | Multi-Hook Router |
|---|---|---|
| **Hooks per job** | 1 | Per-selector, admin-capped |
| **Composability** | Must build one contract that does everything | Mix and match small, focused hooks |
| **Reusability** | Low — each hook is custom-built per use case | High — same privacy hook works across job types |
| **Audit surface** | One large contract | Multiple small contracts (easier to review individually) |
| **Core changes needed** | — | None |
| **Gas overhead** | Baseline | ~3,000 gas per additional hook per selector |
| **Flexibility** | Add a new concern = rewrite the hook | Add a new concern = plug in another hook |
| **optParams** | Single encoding shared by all logic | Per-hook dispatch — each hook gets its own optParams slice |

## Example: Job With Three Concerns

**Current approach** — build a single `EscrowPrivacyReputationHook`:
- 1 contract, ~500+ lines
- Tightly coupled — changing escrow logic risks breaking privacy logic
- Cannot reuse the privacy piece for a different job type

**With Multi-Hook Router** — configure 3 independent hooks:
- `FundTransferHook` — handles token escrow (already built)
- `PrivacyHook` — verifies ZK proofs for confidential deliverables
- `ReputationHook` — tracks provider completion rates

Each is independently developed, tested, and audited. A job that only needs escrow + reputation simply drops the privacy hook from the list.

## Industry Precedent

This is not a novel pattern. Major protocols use the same approach in production:

| Protocol | How They Do It |
|---|---|
| **Uniswap v4** | Hook middleware contracts chain multiple hooks per pool |
| **ERC-6900** | Modular smart accounts with composable validation, execution, and hook modules |
| **Safe (Gnosis)** | Multiple modules + guards enabled simultaneously on a single wallet |

## What Changes for Users

**Nothing.** Users interact with ERC-8183 the same way they do today. The router is transparent — it looks like a single hook to the core.

The only difference is during job setup: instead of deploying a custom hook, the client configures which existing hooks to attach per selector.

## Risk and Tradeoffs

| Consideration | Detail |
|---|---|
| **Gas cost** | Each additional hook adds ~3,000 gas per transition. 5 hooks = ~15,000 extra gas. Manageable on L2s, noticeable on L1. |
| **Ordering matters** | Hook execution order affects behavior. Access control hooks should run before payment hooks. |
| **Hook list is locked after funding** | Once money is escrowed, the hook list cannot change. This prevents manipulation mid-job. |
| **Sub-hook compatibility** | Sub-hooks must implement `IERC8183HookMetadata` alongside `IERC8183Hook`. Existing hooks extending `BaseERC8183Hook` need to add this interface. |
| **Caller must know the router** | When using per-hook data dispatch, callers encode optParams as `abi.encode(bytes[])`. Any optParams >= 64 bytes is decoded as a `bytes[]` — raw application data >= 64 bytes will revert if not in dispatch format. Use broadcast mode (empty optParams) or wrap in dispatch format. |
| **De-whitelisted hooks** | If a sub-hook is de-whitelisted on core after configuration, the router skips it silently (emitting an event) rather than reverting the entire transition. |

## Impact

- No changes to the core `AgenticCommerce` contract
- The router is a standalone contract (~510 lines)
- Existing `FundTransferHook` continues to work as-is for single-hook jobs
- Multi-hook support is additive — it does not break or replace anything
