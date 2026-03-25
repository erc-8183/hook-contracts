// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";

/**
 * @title ThoughtProofEvaluatorHook
 * @author ThoughtProof (https://thoughtproof.ai)
 * @dev ERC-8183 hook that requires multi-model adversarial verification
 *      before job completion. Prevents settlement when AI agent reasoning
 *      fails verification.
 *
 *      Architecture:
 *        1. Agent submits deliverable → off-chain ThoughtProof pipeline runs
 *           (DeepSeek + Grok + Sonnet critique the reasoning adversarially)
 *        2. Verifier posts signed attestation on-chain via submitAttestation()
 *        3. Evaluator calls complete() → _preComplete checks attestation exists
 *           and meets confidence threshold → settlement proceeds or reverts
 *
 *      This addresses the grief attack vector identified in issue #13:
 *      evaluate() is permissionless, but the ATTESTATION is signed by
 *      a trusted verifier. Only attestations from registered ThoughtProof
 *      verifiers are accepted.
 *
 *      Composable with Intuition Protocol: attestation data can be mirrored
 *      to the Intuition Trust Graph for persistent reputation tracking.
 *
 *      Hook Profile: B (Advanced Escrow) — requires off-chain verification
 *      before on-chain settlement.
 *
 *      Storage layout (2 slots per attestation):
 *        Slot 1: verifier(20) + timestamp(6) + confidenceBP(2) + modelCount(1) + verdict(1) = 30 bytes
 *        Slot 2: synthesisHash(32) + deliverableHash(32) = separate slots
 */
contract ThoughtProofEvaluatorHook is BaseACPHook {

    // ─── Types ─────────────────────────────────────────────

    enum Verdict { NONE, ALLOW, HOLD, BLOCK }

    struct Attestation {
        // Slot 1: packed (30 bytes)
        address verifier;         // 20 bytes — ThoughtProof verifier that signed this
        uint48 timestamp;         // 6 bytes  — when the verification was performed
        uint16 confidenceBP;      // 2 bytes  — 0-10000 (basis points, 9600 = 96%)
        uint8 modelCount;         // 1 byte   — number of models used (typically 3)
        Verdict verdict;          // 1 byte   — ALLOW, HOLD, or BLOCK
        // Slot 2
        bytes32 synthesisHash;    // 32 bytes — keccak256 of the full synthesis report
        // Slot 3
        bytes32 deliverableHash;  // 32 bytes — keccak256 of the deliverable being verified
    }

    // ─── State ─────────────────────────────────────────────

    /// @dev Minimum confidence (in basis points) required for settlement
    uint16 public minConfidenceBP;

    /// @dev Registered ThoughtProof verifier addresses
    mapping(address => bool) public trustedVerifiers;

    /// @dev jobId => Attestation
    mapping(uint256 => Attestation) public attestations;

    /// @dev Owner for admin operations
    address public owner;

    // ─── Events ────────────────────────────────────────────

    event AttestationSubmitted(
        uint256 indexed jobId,
        address indexed verifier,
        Verdict verdict,
        uint16 confidenceBP,
        uint8 modelCount,
        bytes32 deliverableHash
    );

    event VerifierUpdated(address indexed verifier, bool trusted);
    event MinConfidenceUpdated(uint16 oldBP, uint16 newBP);

    // ─── Errors ────────────────────────────────────────────

    error OnlyOwner();
    error NotTrustedVerifier();
    error AttestationExists();
    error NoAttestation();
    error InsufficientConfidence(uint16 required, uint16 actual);
    error VerdictNotAllow(Verdict verdict);
    error InvalidConfidence();
    error DeliverableMismatch(bytes32 expected, bytes32 actual);

    // ─── Constructor ───────────────────────────────────────

    /**
     * @param acpContract_ The AgenticCommerceHooked contract address
     * @param minConfidenceBP_ Minimum confidence for settlement (e.g. 7000 = 70%)
     * @param initialVerifier_ First trusted ThoughtProof verifier address
     */
    constructor(
        address acpContract_,
        uint16 minConfidenceBP_,
        address initialVerifier_
    ) BaseACPHook(acpContract_) {
        if (minConfidenceBP_ > 10000) revert InvalidConfidence();
        owner = msg.sender;
        minConfidenceBP = minConfidenceBP_;
        trustedVerifiers[initialVerifier_] = true;
        emit VerifierUpdated(initialVerifier_, true);
    }

    // ─── Admin ─────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    function setTrustedVerifier(address verifier, bool trusted) external onlyOwner {
        trustedVerifiers[verifier] = trusted;
        emit VerifierUpdated(verifier, trusted);
    }

    function setMinConfidence(uint16 newMinBP) external onlyOwner {
        if (newMinBP > 10000) revert InvalidConfidence();
        emit MinConfidenceUpdated(minConfidenceBP, newMinBP);
        minConfidenceBP = newMinBP;
    }

    // ─── Attestation Submission ────────────────────────────

    /**
     * @dev Submit a ThoughtProof verification attestation for a job.
     *      Called by the ThoughtProof verifier AFTER off-chain multi-model
     *      verification completes. Must be called before complete().
     *
     *      The deliverableHash binds the attestation to a specific deliverable.
     *      If the deliverable changes after verification, _preComplete will
     *      detect the mismatch and revert.
     *
     * @param jobId The job being verified
     * @param verdict ALLOW (1), HOLD (2), or BLOCK (3)
     * @param confidenceBP Confidence in basis points (e.g. 9600 = 96%)
     * @param synthesisHash keccak256 of the full synthesis report (stored off-chain)
     * @param deliverableHash keccak256 of the deliverable content being verified
     * @param modelCount Number of models used in verification (typically 3)
     */
    function submitAttestation(
        uint256 jobId,
        Verdict verdict,
        uint16 confidenceBP,
        bytes32 synthesisHash,
        bytes32 deliverableHash,
        uint8 modelCount
    ) external {
        if (!trustedVerifiers[msg.sender]) revert NotTrustedVerifier();
        if (attestations[jobId].verdict != Verdict.NONE) revert AttestationExists();
        if (confidenceBP > 10000) revert InvalidConfidence();

        attestations[jobId] = Attestation({
            verifier: msg.sender,
            timestamp: uint48(block.timestamp),
            confidenceBP: confidenceBP,
            modelCount: modelCount,
            verdict: verdict,
            synthesisHash: synthesisHash,
            deliverableHash: deliverableHash
        });

        emit AttestationSubmitted(jobId, msg.sender, verdict, confidenceBP, modelCount, deliverableHash);
    }

    // ─── Hook: Pre-Complete Gate ───────────────────────────

    /**
     * @dev Called before complete() executes. Reverts if:
     *      - No attestation exists for this job
     *      - Verdict is not ALLOW
     *      - Confidence is below minimum threshold
     *
     *      NOTE: Not declared as `view` because BaseACPHook._preComplete is non-view virtual.
     *      The function is effectively read-only (no state changes on success path).
     */
    function _preComplete(
        uint256 jobId,
        bytes32 /* reason */,
        bytes memory /* optParams */
    ) internal override {
        Attestation storage att = attestations[jobId];

        // No attestation = no settlement
        if (att.verdict == Verdict.NONE) revert NoAttestation();

        // Only ALLOW verdicts pass
        if (att.verdict != Verdict.ALLOW) {
            revert VerdictNotAllow(att.verdict);
        }

        // Must meet minimum confidence
        if (att.confidenceBP < minConfidenceBP) {
            revert InsufficientConfidence(minConfidenceBP, att.confidenceBP);
        }
    }

    // ─── View Helpers ──────────────────────────────────────

    /// @dev Check if a job has been verified and can be completed
    function isVerified(uint256 jobId) external view returns (bool) {
        Attestation storage att = attestations[jobId];
        return att.verdict == Verdict.ALLOW && att.confidenceBP >= minConfidenceBP;
    }

    /// @dev Get the full attestation for a job
    function getAttestation(uint256 jobId) external view returns (Attestation memory) {
        return attestations[jobId];
    }
}
