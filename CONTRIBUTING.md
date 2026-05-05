# Building Hook Extensions

This repo is the **hook extension layer** for ERC-8183. Hooks let you extend the hookable ERC-8183 core with custom logic — bidding rules, escrow flows, compliance checks, and more — without modifying the core protocol.

## PR Rules

Every hook PR to this repo must satisfy:

- **One hook contract per PR.** A single hook contract — no batching, no auxiliary contracts.
- **Single `.sol` file.** All custom interfaces, structs, and errors live in the same file as the hook contract. The only external interface a hook may import from this repo is `IERC8183HookMetadata`.
- **MultiHookRouter-compatible.** Inherit `BaseERC8183Hook`, implement `IERC8183HookMetadata`, and advertise both interfaces via ERC165. The hook must be safe to use as a sub-hook behind `MultiHookRouter` — no assumption that `msg.sender` is the core contract directly, no whitelist coupling outside the core's hook whitelist.
- **Vendor-neutral.** No references to specific tokens, exchanges, bridges, or vendors in code, NatSpec, or naming. Use generic terms ("input token", "output token", "stablecoin").
- **No test files.** PRs add a hook contract only. Tests, fuzz harnesses, and mocks are out of scope for hook PRs.

## Correctness Rules

Hard requirements for hook contents:

- **Validate zero-address inputs in the constructor.** Revert on `address(0)` for every address dependency (token, registry, etc.). The core address is already validated by `BaseERC8183Hook` (`ZeroCoreAddress()`); declare your own named errors for additional dependencies.
- **No external mutating functions outside the hook callbacks.** State-changing entry points must be the inherited `beforeAction`/`afterAction`. The single permitted exception is recovery for cases that `claimRefund` cannot reach (it is not hookable) — see `FundTransferHook.recoverTokens` for the pattern.
- **Reentrancy posture for Profile B.** Token-custody hooks must follow checks-effects-interactions and treat `safeTransferFrom` / `safeTransfer` as untrusted (ERC777, fee-on-transfer, callback-laden tokens exist). The router's `nonReentrant` guard protects the router boundary only — sub-hooks must protect themselves.
- **No proxy or upgradeability patterns.** Hooks are immutable by design. To change behaviour, deploy a new hook and rotate the whitelist.

## Writing a Hook

### 1. Inherit `BaseERC8183Hook` and `IERC8183HookMetadata`

```solidity
contract YourHook is BaseERC8183Hook, IERC8183HookMetadata {
    constructor(address erc8183Contract_) BaseERC8183Hook(erc8183Contract_) {}

    // Override only the callbacks you need

    function requiredSelectors() external pure returns (bytes4[] memory) {
        // Selectors this hook MUST be configured for together. The router
        // reverts with HookMissingRequiredSelector at fund time if this hook
        // is configured on ANY of these but missing from one.
        //
        // Return empty if the hook has no cross-selector dependencies (e.g.
        // a one-shot KYC check on `fund`):
        //     return new bytes4[](0);
        //
        // Return the full list if the hook spans multiple selectors and
        // earlier-selector state is required for later ones (e.g. an escrow
        // that stores commitments on `setBudget` and releases them on
        // `complete` must declare both — otherwise the client could omit
        // `setBudget`, leaving the release path with no commitment to act on).
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IERC8183HookMetadata).interfaceId
            || super.supportsInterface(interfaceId);
    }
}
```

If your hook reads job state, define a typed accessor matching the existing examples:

```solidity
function _core() internal view returns (AgenticCommerce) {
    return AgenticCommerce(erc8183Contract);
}
```

Available callbacks (all no-ops by default):

| Callback | Triggered by |
|----------|-------------|
| `_preSetBudget` / `_postSetBudget` | `setBudget` |
| `_preFund` / `_postFund` | `fund` |
| `_preSubmit` / `_postSubmit` | `submit` |
| `_preComplete` / `_postComplete` | `complete` |
| `_preReject` / `_postReject` | `reject` |

`claimRefund` is deliberately not hookable.

### 2. Pick a profile

| Profile | When to use |
|---------|-------------|
| **A — Simple Policy** | Validation and light policy only (bidding, RFQ, KYC, limits). No extra token custody. |
| **B — Advanced Escrow** | Hooks that custody tokens and orchestrate multi-phase flows. |
| **C — Experimental** | Anything that doesn't fit A or B cleanly. Label clearly as high-risk. |

See [`hook-profiles.md`](./hook-profiles.md) for full guidance on each profile.

### 3. Document your hook

Include a NatSpec header in your contract explaining:

- **USE CASE** — what problem it solves (in vendor-neutral terms)
- **FLOW** — step-by-step, noting which steps are hook callbacks
- **TRUST MODEL** — what guarantees the hook provides and to whom

See `BiddingHook.sol` or `FundTransferHook.sol` for examples.

## Submitting

1. Add the hook to `contracts/hooks/`.
2. Add a row to the Hook Examples table in [`README.md`](./README.md):

```markdown
| [YourHook.sol](./contracts/hooks/YourHook.sol) | A / B / C | One-line description. |
```

3. Confirm `forge build` compiles cleanly.
4. Open a pull request — one hook per PR, with a brief description of the use case and any trust assumptions.

## Code style

- Solidity `^0.8.20`. Every file begins with `// SPDX-License-Identifier: MIT`.
- Follow the style of existing contracts (named errors, NatSpec, no magic numbers).
- Keep hooks focused — one responsibility per hook.
- Avoid unnecessary state; prefer `mapping(uint256 => ...)` keyed by `jobId`.
- Code comments should be as concise and as precise as possible — explain *why*, not *what*. Cite the invariant, constraint, or attack the code prevents; do not restate the code.
