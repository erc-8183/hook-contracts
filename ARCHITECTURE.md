# ERC-8183 Hook Contracts — Architecture

## Overview

This repository contains two distinct integration points for the ERC-8183 Agentic Commerce Protocol:

| Contract | Role | Notes |
|----------|------|-------|
| `ThoughtProofEvaluator` | **Evaluator** — completes or rejects jobs after off-chain verification | Existing, unchanged |
| `ReasoningVerifierHook` | **Hook** — gates actions by delegating to `IReasoningVerifier` | **New (PR #11 refactor)** |
| `ThoughtProofReasoningVerifier` | **Reference implementation** of `IReasoningVerifier` | ThoughtProof-specific |
| `IReasoningVerifier` | **Generic interface** consumed by the hook | Protocol-agnostic |

---

## PR #11 Refactor: Generic Reasoning Hook

### Motivation

The original `ThoughtProofReasoningHook` was hardcoded to ThoughtProof as a dependency.
Feedback on the ERC-8183 standard requested that the hook abstraction be protocol-agnostic:
any reasoning verifier should be pluggable.

### Changes

1. **`IReasoningVerifier` (new)** — minimal interface, only what the hook needs:
   ```solidity
   function verifyReasoning(bytes32 claimHash)
       external view
       returns (bool verified, uint256 confidence);
   ```

2. **`ThoughtProofReasoningVerifier` (new)** — reference implementation of `IReasoningVerifier`.
   Preserves the existing attestation/signature pattern: off-chain service submits signed results
   keyed by `claimHash`. The `verifierSigner` EOA is the on-chain JWKS-style authority.

3. **`ReasoningVerifierHook` (new, replaces `ThoughtProofReasoningHook`)** — constructor
   accepts `IReasoningVerifier`. ThoughtProof is the reference implementation but is not
   a required dependency.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    ERC-8183 Job Contract                    │
│            (or any protocol using hook pattern)             │
└────────────────────────────┬────────────────────────────────┘
                             │  calls beforeAction(claimHash)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│               ReasoningVerifierHook                         │
│  - immutable verifier: IReasoningVerifier                   │
│  - minConfidence: uint256                                   │
│  beforeAction(): reverts if not verified / too low          │
│  afterAction(): informational, cannot revert                │
└────────────────────────────┬────────────────────────────────┘
                             │  calls verifyReasoning(claimHash)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  <<interface>> IReasoningVerifier                           │
│  verifyReasoning(bytes32) → (bool verified, uint256 conf)   │
└────────────────────────────┬────────────────────────────────┘
                             │  implemented by
                             ▼
┌─────────────────────────────────────────────────────────────┐
│         ThoughtProofReasoningVerifier (reference impl)      │
│  - verifierSigner: EOA of ThoughtProof off-chain service    │
│  - minVerifiers: uint256                                    │
│  - records: claimHash → VerificationRecord                  │
│  submitVerification(): stores signed result on-chain        │
│  verifyReasoning(): returns (verified, confidence)          │
└────────────────────────────┬────────────────────────────────┘
                             │  submitted by
                             ▼
┌─────────────────────────────────────────────────────────────┐
│         ThoughtProof Off-Chain Service (pot-sdk)            │
│  1. Receives claimHash from protocol                        │
│  2. Runs multi-model verification (3+ LLMs)                 │
│  3. Signs (claimHash, confidence, verifierCount,            │
│           attestationHash, chainId)                         │
│  4. Calls submitVerification() on-chain                     │
└─────────────────────────────────────────────────────────────┘
```

---

## ERC-8183 Flow (Evaluator — separate from hook)

```
Client                  Provider                ThoughtProof Evaluator
  |                        |                           |
  |-- createJob(evaluator=TP) ----------------------->|
  |-- fund() ------------->|                           |
  |                        |-- submit(deliverable) --->|
  |                        |                           |
  |                        |          [Off-chain: Multi-Model Verification]
  |                        |          1. Fetch deliverable from IPFS/URL
  |                        |          2. Run pot-sdk verification (3+ models)
  |                        |          3. Generate Epistemic Block
  |                        |                           |
  |                        |          [On-chain: Attestation]
  |                        |          IF confidence >= threshold:
  |                        |            complete(jobId, blockHash)
  |                        |          ELSE:
  |                        |            reject(jobId, reason)
  |                        |                           |
  |<-- funds released -----|<--------------------------|
```

---

## Hook Usage Example

```solidity
// Deploy ThoughtProof verifier
ThoughtProofReasoningVerifier verifier = new ThoughtProofReasoningVerifier(
    thoughtProofSignerEOA,  // authorized off-chain service
    3                       // minimum models
);

// Deploy hook with verifier (generic — could be any IReasoningVerifier)
ReasoningVerifierHook hook = new ReasoningVerifierHook(
    IReasoningVerifier(address(verifier)),
    700  // 70% minimum confidence
);

// ERC-8183 protocol calls:
hook.beforeAction(claimHash);  // reverts if not verified or too low confidence
hook.afterAction(claimHash);   // informational bookkeeping
```

---

## Naming Decisions

| Old name | New name | Reason |
|----------|----------|--------|
| `ThoughtProofReasoningHook` | `ReasoningVerifierHook` | Hook is now verifier-agnostic |
| _(none)_ | `IReasoningVerifier` | Extracted generic interface |
| _(none)_ | `ThoughtProofReasoningVerifier` | ThoughtProof as reference implementation |

---

## Stack Integration

| Layer | Standard | ThoughtProof |
|-------|----------|-------------|
| Identity | ERC-8004 | Agent #28388 |
| Auth | ERC-8128 | Signed HTTP requests (roadmap) |
| Payment | x402 | pot-sdk/pay |
| Commerce | ERC-8183 | **Evaluator + Hook Contracts** ← THIS |
| Verification | pot-sdk | Multi-model consensus engine |

---

## Security Properties

- **CEI pattern**: state is written before any external interaction in `submitVerification`
- **Signature replay protection**: each signature is stored in `usedSignatures` (hash-of-sig nonce)
- **Cross-chain replay protection**: `block.chainid` included in the signed message
- **Double-submission prevention**: `AlreadySubmitted` reverts on duplicate `claimHash`
- **Permissionless relay**: anyone can call `submitVerification` — only valid sigs accepted
- **Immutable verifier**: hook's verifier address is immutable post-deployment

---

## Remaining Risks

1. **claimHash collision**: if two distinct claims hash identically, the second is rejected
   (`AlreadySubmitted`). Callers should include sufficient context (nonce, jobId, chainId)
   in the pre-image of `claimHash`.

2. **verifierSigner key compromise**: if the off-chain service key is compromised, false
   results can be submitted. `setConfig()` allows rotating the signer, but already-submitted
   records are immutable.

3. **Confidence unit mismatch**: callers must agree that confidence is scaled by 1000.
   The interface comment documents this; hook constructors validate 100 ≤ minConfidence ≤ 1000.
