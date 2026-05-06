# ERC-8183 Hook Profiles (Non‑Normative)

This document describes **recommended profiles** for using hooks with ERC-8183. It is **non‑normative**: the on‑chain standard only specifies the hook interface and lifecycle, not which profiles must be used. Profiles exist to help integrators choose the appropriate risk/complexity level:

- **Profile A — Simple Policy Hooks**: validation and light policy (bidding, RFQ, KYC, limits) around `setProvider` / `setBudget` / `fund`, without extra token custody or complex settlement logic.
- **Profile B — Advanced Escrow / Settlement Hooks**: hooks that custody tokens and orchestrate multi‑phase flows (e.g. two‑phase escrow, atomic side‑transfers), accepting higher complexity and liveness risk.
- **Profile C — Experimental / Custom Hooks**: hooks that fall outside A and B; should be treated as high‑risk or non‑production until well‑understood and audited.

The profiles assume a core compatible with the hookable ERC-8183 variant (e.g. `ERC8183` in the reference implementations), where:

- Each job MAY store a per‑job `hook` address set at `createJob`.
- Hookable functions call:
  - `beforeAction(jobId, selector, data)` before core logic.
  - `afterAction(jobId, selector, data)` after core logic.
- `selector` is the 4‑byte function selector (e.g. `setProvider(uint256,address,bytes)`).
- `data` encodes function arguments as documented in the spec.

`claimRefund` is deliberately **not hookable** so refunds after expiry cannot be blocked by a hook.

---

## Profile A — Simple Policy Hooks

**Goal:** Add validation and light policy checks around provider selection, budget, and funding, without extra token custody or complex settlement logic.

- **Typical responsibilities:**
  - Enforce bidding / RFQ rules on `setProvider` and/or `setBudget`.
  - Enforce allowlists, KYC, or simple limits on `fund`.
  - Optionally emit additional events or attestations after `complete`.
- **Should NOT:**
  - Custody tokens directly (no extra escrow inside the hook).
  - Depend on `afterAction` to enforce financial invariants.

### Recommended constraints

- **Hooked functions (typical):**
  - `setProvider(jobId, provider, optParams)`
  - `setBudget(jobId, amount, optParams)`
  - `fund(jobId, optParams)`
  - Optional: `complete(jobId, reason, optParams)` for logging/attestations only
- **beforeAction:**
  - MAY revert to block the action (e.g. invalid bid, bad signature, not allowlisted).
  - SHOULD NOT move tokens.
- **afterAction:**
  - SHOULD be treated as **best‑effort** side effects: logging, reputation updates, emitting attestations, etc.
  - SHOULD NOT be relied on for correctness of escrow or settlement.

### Example: Bidding / RFQ hook (conceptual)

**Use case:** Providers bid off‑chain; the client selects a winner and must prove on‑chain that the provider actually bid at that price.

- `setBudget(jobId, maxBudget, optParams=abi.encode(biddingDeadline))`
  - `beforeAction`: store `deadline` for this job.
- `setProvider(jobId, winner, optParams=abi.encode(bidAmount, signature))`
  - `beforeAction`:
    - Require `block.timestamp >= deadline` (bidding closed).
    - Recover signer from `signature` over `(chainId, hookAddress, jobId, bidAmount)`.
    - Require signer == `winner`.
    - Store `committedBidAmount`.
  - `afterAction`: mark bidding finalized.
- `setBudget(jobId, amount, optParams="")`
  - `beforeAction`: require `amount == committedBidAmount`.

**Properties:**

- Core escrow semantics unchanged.
- Hook enforces that the chosen `provider` actually committed to the winning `bidAmount`.
- Client still chooses the winner, but cannot fabricate a commitment.

---

## Profile B — Advanced Escrow / Settlement Hooks

**Goal:** Support complex payment flows that require **multiple assets and phases**, e.g.:

- Two‑phase escrow (capital to provider, output back to buyer).
- Atomic fund + side‑transfer.
- Revenue sharing or multi‑party payouts.

These hooks often:

- Custody tokens in the hook contract.
- Depend on `afterAction` revert semantics for atomicity.
- Introduce more ways for a bug to block job progression (until expiry).

### Recommended constraints

- **Hooked functions (typical):**
  - `setBudget` (store commitments / parameters).
  - `fund` (kick off capital flows).
  - `submit` (pull finished deliverable into hook escrow).
  - `complete` (release deliverable to final recipient).
  - Optional: `reject` (return deliverable to provider on rejection).
- **beforeAction:**
  - MAY revert to enforce prerequisites (allowances, deadlines, amounts).
  - MAY **pull** tokens into the hook (e.g. provider deposits output at `submit`).
- **afterAction:**
  - MAY **push** tokens from hook escrow to final recipients.
  - MAY revert to ensure atomic “all‑or‑nothing” flows.
  - SHOULD be clearly documented for integrators (which actions can fail due to hook logic).

### Example: Fund transfer / two‑phase escrow (high‑level)

**Use case:** Client pays an agent to transform/bridge/swap tokens. The agent:

- Receives capital.
- Produces output tokens.
- Must return those output tokens in a way linked to job completion.

A two‑phase hook can:

1. **setBudget** — store buyer + required output amount.
2. **fund** — after escrow locks the agent fee:
   - `afterAction`: pull capital from client, forward to provider.
3. **submit** — provider has produced output tokens:
   - `beforeAction`: pull output tokens from provider into hook escrow.
4. **complete** — evaluator approves deliverable:
   - `afterAction`: release output tokens from hook to buyer.
5. **reject** — evaluator rejects:
   - `afterAction`: return any deposited output tokens back to provider.
6. **expiry** — job expires:
   - `claimRefund` (core) refunds agent fee to client.
   - hook exposes a `recoverTokens(jobId)` function for provider to withdraw their deposited tokens.

**Properties:**

- Provider cannot mark job as `Submitted` without depositing output tokens.
- Buyer only receives tokens when evaluator completes the job.
- On rejection/expiry, provider can recover their tokens from the hook.
- If the hook misbehaves, the job may not progress before expiry; this is an accepted trade‑off for advanced flows.

---

## Profile C — Experimental / Custom Hooks

**Goal:** Capture hooks that do not conform cleanly to Profile A or B, or that introduce novel behaviour whose safety properties are not yet well‑understood.

- **Typical characteristics:**
  - Combine responsibilities of A and B in non‑standard ways (e.g. complex off‑chain dependencies plus custom token flows).
  - Depend on external protocols, bridges, or oracles in ways that are hard to model.
  - Assume invariants specific to a single deployment or ecosystem.
- **Risks:**
  - Harder to reason about; more likely to introduce subtle liveness or safety bugs.
  - Behaviour may change if external dependencies change or are upgraded.

### Recommended guidance

- Treat Profile C hooks as **experimental**:
  - Not recommended for general‑purpose production deployments.
  - Should be clearly labeled in documentation and UIs as “high‑risk / advanced”.
  - SHOULD undergo separate, focused audits before use with significant value.
- Prefer to **refactor** mature Profile C patterns into Profile A or B over time:
  - Once a pattern is well‑understood and widely used, it can usually be expressed as:
    - a pure policy hook (Profile A), or
    - an advanced escrow/settlement hook (Profile B) with clearly defined token flows.

