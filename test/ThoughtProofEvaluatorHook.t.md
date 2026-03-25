# ThoughtProofEvaluatorHook — Test Specification

## Unit Test Cases

These tests validate the ThoughtProofEvaluatorHook contract logic.
Can be executed with Foundry (`forge test`) or as B1/B2 agent consumption tests.

---

### 1. Deployment & Configuration

| # | Test | Expected |
|---|------|----------|
| 1.1 | Deploy with valid params (acpContract, 7000 BP, verifier) | Success, minConfidenceBP=7000, verifier trusted |
| 1.2 | Deploy with confidenceBP > 10000 | Revert: InvalidConfidence |
| 1.3 | setTrustedVerifier by owner | Success, VerifierUpdated event |
| 1.4 | setTrustedVerifier by non-owner | Revert: OnlyOwner |
| 1.5 | setMinConfidence to 9000 | Success, MinConfidenceUpdated(7000, 9000) |
| 1.6 | setMinConfidence to 10001 | Revert: InvalidConfidence |

### 2. Attestation Submission

| # | Test | Expected |
|---|------|----------|
| 2.1 | Trusted verifier submits ALLOW attestation | Success, AttestationSubmitted event |
| 2.2 | Untrusted address submits attestation | Revert: NotTrustedVerifier |
| 2.3 | Submit attestation for same jobId twice | Revert: AttestationExists |
| 2.4 | Submit with confidenceBP > 10000 | Revert: InvalidConfidence |
| 2.5 | Submit HOLD attestation | Success, verdict=HOLD stored |
| 2.6 | Submit BLOCK attestation | Success, verdict=BLOCK stored |
| 2.7 | Verify attestation fields stored correctly | All fields match input |
| 2.8 | Verify timestamp is block.timestamp | att.timestamp == block.timestamp |

### 3. Pre-Complete Gate (Core Safety Logic)

| # | Test | Expected |
|---|------|----------|
| 3.1 | complete() with ALLOW + confidence >= threshold | Passes (no revert) |
| 3.2 | complete() with NO attestation | Revert: NoAttestation |
| 3.3 | complete() with HOLD verdict | Revert: VerdictNotAllow(HOLD) |
| 3.4 | complete() with BLOCK verdict | Revert: VerdictNotAllow(BLOCK) |
| 3.5 | complete() with ALLOW but confidence < threshold | Revert: InsufficientConfidence(7000, 5000) |
| 3.6 | complete() with ALLOW and confidence == threshold | Passes (boundary) |
| 3.7 | complete() with ALLOW and confidence == 10000 | Passes (maximum) |

### 4. View Helpers

| # | Test | Expected |
|---|------|----------|
| 4.1 | isVerified() with valid ALLOW above threshold | Returns true |
| 4.2 | isVerified() with HOLD | Returns false |
| 4.3 | isVerified() with ALLOW below threshold | Returns false |
| 4.4 | isVerified() with no attestation | Returns false |
| 4.5 | getAttestation() returns correct struct | All fields match |

### 5. Edge Cases

| # | Test | Expected |
|---|------|----------|
| 5.1 | Attestation for non-existent jobId | Succeeds (no job existence check — deliberate) |
| 5.2 | Remove trusted verifier, try submit | Revert: NotTrustedVerifier |
| 5.3 | Multiple verifiers registered | Each can submit for different jobs |
| 5.4 | Zero confidenceBP attestation | Succeeds but isVerified=false |
| 5.5 | Gas: attestation storage fits in expected slots | Gas benchmarks within range |

---

## Integration Test Scenarios (B2 On-Chain)

### Scenario A: Happy Path
1. Deploy ACP + Hook with verifier V1
2. Create job with hook=ThoughtProofEvaluatorHook
3. Fund job
4. Provider submits deliverable
5. V1 calls submitAttestation(jobId, ALLOW, 9600, synthesisHash, deliverableHash, 3)
6. Evaluator calls complete(jobId)
7. ✅ Settlement succeeds, payment released

### Scenario B: Verification Blocks Settlement
1. Deploy ACP + Hook
2. Create + Fund + Submit job
3. V1 calls submitAttestation(jobId, HOLD, 5000, ...)
4. Evaluator calls complete(jobId)
5. ❌ Reverts: VerdictNotAllow(HOLD)
6. Job remains in Submitted state, funds safe in escrow

### Scenario C: Low Confidence Blocks Settlement
1. Deploy ACP + Hook with minConfidence=7000
2. Create + Fund + Submit job
3. V1 calls submitAttestation(jobId, ALLOW, 5000, ...)
4. Evaluator calls complete(jobId)
5. ❌ Reverts: InsufficientConfidence(7000, 5000)

### Scenario D: No Verification = No Settlement
1. Deploy ACP + Hook
2. Create + Fund + Submit job
3. Evaluator calls complete(jobId) WITHOUT attestation
4. ❌ Reverts: NoAttestation
5. Funds remain in escrow until attestation or expiry
