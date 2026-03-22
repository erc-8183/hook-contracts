# Reasoning Attestation Hook

## The Problem: Reputation ≠ Reasoning

Existing trust hooks (PR #6's `TrustGateACPHook`) answer: *"Is this agent historically trustworthy?"*

But reputation is backward-looking. A trusted agent can still make a catastrophic decision *right now* — a bad trade, a flawed analysis, a hallucinated deliverable. Reputation tells you the agent was good yesterday. It says nothing about whether *this specific reasoning chain* is sound.

This is the **Measurability Gap** (Catalini & Hui, 2025): the cost of generating a claim approaches zero, but verifying it remains bounded by expert bandwidth. For on-chain agents managing real value, this gap is existential.

## The Solution: Verify Reasoning, Not Just Reputation

`ThoughtProofReasoningHook` adds a second verification layer that checks the *quality of the current decision* before it reaches the chain:

```
Agent reasons about action
    → Calls ThoughtProof API (multi-model adversarial consensus)
    → Receives ECDSA-signed attestation: ALLOW or HOLD
    → Submits deliverable + attestation to AgenticCommerce
    → Hook verifies signature on-chain
    → ALLOW → submission proceeds
    → HOLD  → transaction reverts
```

### How Multi-Model Adversarial Consensus Works

ThoughtProof doesn't use a single AI model to verify reasoning. Instead:

1. **Decomposition** — The claim is broken into independently verifiable sub-claims
2. **Multi-Generator** — 3-4 independent models (different architectures, different training data) each evaluate the sub-claims
3. **Adversarial Critic** — A dedicated critic model challenges the generators, looking for blind spots
4. **Synthesis** — Disagreements are weighted and resolved into a final verdict with calibrated confidence

This means a single model's hallucination or bias gets caught by the others. The cryptographic attestation represents *consensus across model families*, not a single model's opinion.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 1: REPUTATION (TrustGateACPHook — PR #6)              │
│  "Is this agent historically trustworthy?"                    │
│  oracle.getUserData(agent) → reputationScore ≥ threshold      │
└────────────────────────────┬─────────────────────────────────┘
                             │ agent passes reputation check
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  LAYER 2: REASONING (ThoughtProofReasoningHook — this PR)    │
│  "Is THIS SPECIFIC decision sound?"                           │
│  ECDSA.verify(attestation, trustedSigner) → ALLOW or HOLD    │
│                                                               │
│  Multi-model adversarial consensus:                           │
│    Grok + DeepSeek + Gemini (generators)                      │
│    Claude (adversarial critic)                                │
│    → Signed verdict: ALLOW / HOLD + confidence + claimHash    │
└────────────────────────────┬─────────────────────────────────┘
                             │ reasoning verified
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  AgenticCommerce.submit() executes                            │
└──────────────────────────────────────────────────────────────┘
```

Both layers are independently deployable. Together they provide **defense-in-depth**: an agent must be both historically reputable AND currently reasoning correctly.

## Contract: `ThoughtProofReasoningHook.sol`

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| ECDSA over EdDSA | EVM-native `ecrecover` — no precompile dependency, cheaper gas |
| Nonce-based replay protection | Each attestation is single-use; prevents cross-job replay |
| 5-minute expiry (`MAX_ATTESTATION_AGE`) | Attestations must be fresh — stale reasoning about volatile markets is dangerous |
| `_preSubmit` hook point | Gates the *submission* (the agent's action), not funding or evaluation |
| Attestation stored on-chain | Full auditability — anyone can verify what reasoning was approved |
| `rotateSigner()` | ThoughtProof can rotate JWKS keys without redeploying the hook |

### Attestation Format

The agent passes the attestation via `optParams` in the `submit()` call:

```solidity
optParams = abi.encode(
    bytes32 claimHash,      // keccak256 of the agent's reasoning claim
    bytes32 verdict,        // keccak256("ALLOW") or keccak256("HOLD")
    uint256 confidence,     // 0-10000 basis points (e.g., 9200 = 92%)
    uint256 timestamp,      // When ThoughtProof issued the attestation
    bytes32 nonce,          // Unique nonce (single-use, prevents replay)
    bytes   signature       // 65-byte ECDSA signature from ThoughtProof
)
```

The signature covers `keccak256(abi.encode(jobId, claimHash, verdict, confidence, timestamp, nonce))`, binding the attestation to a specific job.

### Security Properties

- **Replay resistance**: Each nonce is marked as used on first verification
- **Freshness**: Attestations older than 5 minutes are rejected
- **Job binding**: Signature includes the jobId — attestation for job #1 can't be used for job #2
- **Signer rotation**: Owner can update the trusted signer without redeploying
- **Signature malleability**: EIP-2 `s`-value restriction enforced in `_recoverSigner`
- **Non-blocking for non-submit actions**: Only `_preSubmit` is overridden; fund, complete, reject pass through untouched

## Integration Example

```solidity
// Deploy the hook
ThoughtProofReasoningHook hook = new ThoughtProofReasoningHook(
    address(agenticCommerce),     // ACP contract
    0xThoughtProofSignerAddress,  // From ThoughtProof JWKS
    owner                         // Admin for signer rotation
);

// Create a job with the hook attached
agenticCommerce.createJob(
    provider,
    evaluator,
    address(hook),        // ← ThoughtProof reasoning gate
    "Swap 50k USDC for ETH on Uniswap V3",
    50_000e6,
    block.timestamp + 1 hours
);

// Agent submits with ThoughtProof attestation in optParams
agenticCommerce.submit(jobId, deliverableHash, attestationBytes);
// → Hook verifies signature + verdict → allows or reverts
```

## Composability with PR #6

This hook is designed to stack with `TrustGateACPHook`:

```solidity
// Option A: Sequential hooks via StaticAggregationHook
//   1. TrustGateACPHook checks reputation
//   2. ThoughtProofReasoningHook checks reasoning
//   Both must pass.

// Option B: Single hook that composes both
//   Extend ThoughtProofReasoningHook to also call ITrustOracle
//   (not included to keep concerns separated)
```

## Steel-Man: Why This Might Not Work

To be intellectually honest, here are the strongest arguments against this approach — and what we do about each one:

### 1. Oracle Trust Assumption
**Attack**: This hook trusts ThoughtProof's off-chain signer. If the signer key is compromised, all attestations are worthless. An attacker with the key can sign ALLOW for any action.

**Mitigation**: Three layers of defense:
- **Short TTL (5 min)**: A compromised key has a very narrow window of exploitation before attestations expire naturally.
- **Key rotation**: `rotateSigner()` allows immediate revocation. Old attestations become invalid the moment the signer changes.
- **Future: Multi-sig signing**: The hook interface is designed to support M-of-N signer verification (multiple ThoughtProof nodes must agree before an attestation is valid). This eliminates single-key compromise as an attack vector entirely.

### 2. Latency vs. MEV
**Attack**: The 5-minute attestation window creates a race condition. A valid ALLOW attestation for "Swap 50k USDC for ETH" could become dangerous if ETH drops 30% within those 5 minutes. The attestation is stale but still cryptographically valid.

**Why this is the wrong framing**: This hook answers "Should this agent execute this type of action?" — not "Should this specific transaction execute at this specific block?" Those are fundamentally different questions with different verification horizons:
- **Reasoning verification** (this hook): "Is the agent's logic sound? Does the trade match its stated strategy? Are there obvious red flags?" → 5-minute freshness is appropriate.
- **Execution protection** (MEV): "Is this transaction being front-run? Is the slippage acceptable at this exact block?" → Use Flashbots Protect, MEV Blocker, or private mempools.

These two layers are complementary, not competing. A reasoning-verified trade can still use MEV protection for execution. We solve *whether* to trade; MEV protection solves *how* to trade safely.

### 3. Centralization of Verification
**Attack**: ThoughtProof is currently the sole attestation provider. If ThoughtProof goes offline, all hooked contracts are frozen (no submissions can proceed). Single point of failure.

**Mitigation**: This is a real and acknowledged limitation at launch. The path to decentralization is already designed:
- **Short-term**: The `EvaluatorRegistry` from PR #6 allows registering multiple verification providers for the same domain. If ThoughtProof goes down, the agent can obtain an attestation from an alternative registered provider.
- **Medium-term**: M-of-N multi-attestation — require signatures from 2-of-3 independent verification providers (e.g., ThoughtProof + Maiat + a third party). No single provider can unilaterally approve or block.
- **Fallback**: Contracts can be deployed with a fallback evaluator that activates if no attestation is available within a timeout window, ensuring liveness is never permanently compromised.

### 4. Cost of Verification
**Attack**: Every submission requires an off-chain API call. This adds latency (~2-5 seconds) and cost ($0.005-$1.00 per verification). For micro-transactions, the verification cost could exceed the transaction value.

**Mitigation**: This hook is explicitly designed for **high-value agent actions** — the use cases where getting it wrong costs more than getting it verified:
- A $50,000 swap paying $0.50 for verification = 0.001% overhead.
- A $500 trade paying $0.01 for verification = 0.002% overhead.
- A $5 micro-trade? Use a simpler hook (reputation-only) or no hook at all.

The cost scales with depth: fast/low-stakes checks cost $0.005; deep/critical analysis costs up to $1.00. Operators choose the depth that matches their risk tolerance. The economic argument is: **if the potential loss from a bad AI decision exceeds $100, verification pays for itself.**

### 5. Adversarial Prompt Injection
**Attack**: A malicious agent could craft its reasoning claim to specifically fool the multi-model consensus. If all models share similar training data or architectural biases, a carefully constructed adversarial input could trick all of them simultaneously.

**Why this is exponentially harder than it sounds**: ThoughtProof's multi-model adversarial consensus uses models from **different families** with **different architectures** and **different training data**:
- Transformer-based (Claude, GPT)
- Mixture-of-Experts (DeepSeek, Grok)
- Multimodal-native (Gemini)

A prompt that fools one architecture doesn't transfer to another. Research on adversarial transferability (Papernot et al., 2016; Tramèr et al., 2017) shows that cross-architecture adversarial examples are significantly harder to construct than single-model attacks — roughly exponentially harder with each additional independent model family.

Additionally, the **adversarial critic layer** is specifically trained to look for:
- Reasoning that sounds confident but contains logical gaps
- Claims that are technically true but misleading in context
- Patterns that match known adversarial prompt structures

This doesn't make the system 100% robust (no verification system is), but it raises the cost of a successful attack from "craft one clever prompt" to "simultaneously fool 4+ independent model families while passing adversarial criticism" — a qualitatively different and much harder problem.

## API Reference

ThoughtProof verification endpoint:
```
POST https://api.thoughtproof.ai/v1/check
{
  "claim": "Swap 50k USDC for ETH at current market price",
  "domain": "defi",
  "depth": "standard",
  "agentId": "agent_..."
}
→ { "verdict": "ALLOW", "confidence": 0.92, "receipt": { ... } }
```

Full API docs: [api.thoughtproof.ai/openapi.json](https://api.thoughtproof.ai/openapi.json)

JWKS (for signer verification): [thoughtproof.ai/.well-known/jwks.json](https://thoughtproof.ai/.well-known/jwks.json)

## License

MIT
