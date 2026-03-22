// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseACPHook} from "../BaseACPHook.sol";

/**
 * @title ThoughtProofReasoningHook
 * @notice ERC-8183 hook that gates agent submissions on cryptographic
 *         reasoning attestations from ThoughtProof's multi-model verification
 *         pipeline.
 *
 * @dev Unlike reputation-based hooks (which check "Is this agent historically
 *      trustworthy?"), this hook checks "Is THIS SPECIFIC reasoning chain
 *      sound?" — verified by adversarial multi-model consensus before the
 *      action reaches the chain.
 *
 *      Flow:
 *        1. Agent reasons about an action off-chain
 *        2. Agent calls ThoughtProof API → receives ECDSA-signed attestation
 *        3. Agent submits deliverable with attestation in optParams
 *        4. This hook verifies the signature + verdict on-chain
 *        5. If verdict ≠ ALLOW → revert (block the submission)
 *
 *      The attestation covers a specific (agentId, jobId, claimHash) tuple,
 *      preventing replay across jobs or agents.
 *
 *      Composable: Can be stacked with TrustGateACPHook (reputation) via
 *      a StaticAggregationHook for defense-in-depth: reputation AND reasoning
 *      must both pass.
 *
 * @custom:security-contact security@thoughtproof.ai
 */
contract ThoughtProofReasoningHook is BaseACPHook {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attestation verdict: reasoning verified, action approved
    bytes32 public constant VERDICT_ALLOW = keccak256("ALLOW");

    /// @notice Attestation verdict: reasoning failed, action blocked
    bytes32 public constant VERDICT_HOLD = keccak256("HOLD");

    /// @notice Maximum attestation age before it expires (default: 5 minutes)
    uint256 public constant MAX_ATTESTATION_AGE = 300;

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice ThoughtProof signer address (rotatable by owner)
    address public trustedSigner;

    /// @notice Owner for admin operations
    address public owner;

    /// @notice Tracks used attestation nonces to prevent replay
    mapping(bytes32 => bool) public usedNonces;

    /// @notice Per-job attestation log for auditability
    mapping(uint256 => Attestation) public jobAttestations;

    /// @notice Total submissions gated
    uint256 public totalGated;

    /// @notice Total submissions blocked (HOLD verdict)
    uint256 public totalBlocked;

    /*//////////////////////////////////////////////////////////////
                            TYPES
    //////////////////////////////////////////////////////////////*/

    struct Attestation {
        bytes32 verdict;
        bytes32 claimHash;
        uint256 confidence;   // 0-10000 basis points
        uint256 timestamp;
        address agent;
    }

    /// @dev Packed struct for signature verification
    struct AttestationPayload {
        uint256 jobId;
        bytes32 claimHash;
        bytes32 verdict;
        uint256 confidence;
        uint256 timestamp;
        bytes32 nonce;
    }

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event ReasoningVerified(
        uint256 indexed jobId,
        address indexed agent,
        bytes32 verdict,
        uint256 confidence,
        bytes32 claimHash
    );

    event ReasoningBlocked(
        uint256 indexed jobId,
        address indexed agent,
        bytes32 verdict,
        uint256 confidence,
        bytes32 claimHash
    );

    event SignerRotated(address indexed oldSigner, address indexed newSigner);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error ThoughtProofHook__InvalidSignature();
    error ThoughtProofHook__VerdictNotAllow(bytes32 verdict, uint256 confidence);
    error ThoughtProofHook__AttestationExpired(uint256 attestationTime, uint256 currentTime);
    error ThoughtProofHook__NonceReused(bytes32 nonce);
    error ThoughtProofHook__ZeroAddress();
    error ThoughtProofHook__NotOwner();
    error ThoughtProofHook__MissingAttestation();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param acpContract_ The AgenticCommerceHooked contract address
     * @param trustedSigner_ ThoughtProof's attestation signer (from JWKS)
     * @param owner_ Admin who can rotate the signer
     */
    constructor(
        address acpContract_,
        address trustedSigner_,
        address owner_
    ) BaseACPHook(acpContract_) {
        if (trustedSigner_ == address(0)) revert ThoughtProofHook__ZeroAddress();
        if (owner_ == address(0)) revert ThoughtProofHook__ZeroAddress();
        trustedSigner = trustedSigner_;
        owner = owner_;
    }

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert ThoughtProofHook__NotOwner();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: PRE-SUBMIT GATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gates submissions on a valid ThoughtProof reasoning attestation.
     * @dev The attestation is passed via optParams in the submit() call:
     *
     *      optParams = abi.encode(
     *          bytes32 claimHash,      // Hash of the agent's reasoning claim
     *          bytes32 verdict,        // ALLOW or HOLD
     *          uint256 confidence,     // 0-10000 (basis points)
     *          uint256 timestamp,      // When ThoughtProof issued the attestation
     *          bytes32 nonce,          // Unique nonce (prevents replay)
     *          bytes   signature       // ECDSA signature from ThoughtProof signer
     *      )
     *
     *      Reverts if:
     *        - No attestation provided
     *        - Signature invalid (not from trustedSigner)
     *        - Attestation expired (older than MAX_ATTESTATION_AGE)
     *        - Nonce already used (replay attack)
     *        - Verdict is not ALLOW
     */
    function _preSubmit(
        uint256 jobId,
        bytes32, /* deliverable */
        bytes memory optParams
    ) internal override {
        if (optParams.length == 0) revert ThoughtProofHook__MissingAttestation();

        // Decode the attestation from optParams
        (
            bytes32 claimHash,
            bytes32 verdict,
            uint256 confidence,
            uint256 timestamp,
            bytes32 nonce,
            bytes memory signature
        ) = abi.decode(optParams, (bytes32, bytes32, uint256, uint256, bytes32, bytes));

        // 1. Check nonce hasn't been used (replay protection)
        if (usedNonces[nonce]) revert ThoughtProofHook__NonceReused(nonce);
        usedNonces[nonce] = true;

        // 2. Check attestation freshness
        if (block.timestamp > timestamp + MAX_ATTESTATION_AGE) {
            revert ThoughtProofHook__AttestationExpired(timestamp, block.timestamp);
        }

        // 3. Verify ECDSA signature from ThoughtProof signer
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(
                    AttestationPayload({
                        jobId: jobId,
                        claimHash: claimHash,
                        verdict: verdict,
                        confidence: confidence,
                        timestamp: timestamp,
                        nonce: nonce
                    })
                ))
            )
        );

        address recovered = _recoverSigner(messageHash, signature);
        if (recovered != trustedSigner) revert ThoughtProofHook__InvalidSignature();

        // 4. Record attestation for auditability
        totalGated++;
        jobAttestations[jobId] = Attestation({
            verdict: verdict,
            claimHash: claimHash,
            confidence: confidence,
            timestamp: timestamp,
            agent: _jobClient(jobId)
        });

        // 5. Gate on verdict
        if (verdict != VERDICT_ALLOW) {
            totalBlocked++;
            emit ReasoningBlocked(jobId, _jobClient(jobId), verdict, confidence, claimHash);
            revert ThoughtProofHook__VerdictNotAllow(verdict, confidence);
        }

        emit ReasoningVerified(jobId, _jobClient(jobId), verdict, confidence, claimHash);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Rotate the trusted ThoughtProof signer.
     * @dev Called when ThoughtProof rotates their JWKS signing key.
     *      Old attestations remain valid until they expire naturally.
     */
    function rotateSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ThoughtProofHook__ZeroAddress();
        address old = trustedSigner;
        trustedSigner = newSigner;
        emit SignerRotated(old, newSigner);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a job has a recorded attestation
    function hasAttestation(uint256 jobId) external view returns (bool) {
        return jobAttestations[jobId].timestamp != 0;
    }

    /// @notice Get attestation details for a job
    function getAttestation(uint256 jobId) external view returns (Attestation memory) {
        return jobAttestations[jobId];
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL: JOB CLIENT LOOKUP
    //////////////////////////////////////////////////////////////*/

    /// @dev Fetch the client address for a job. BaseACPHook._getJobClient
    ///      can fail on structs with dynamic types (string). This version
    ///      extracts the client from raw ABI-encoded return data.
    function _jobClient(uint256 jobId) internal view returns (address client) {
        (bool ok, bytes memory retData) = acpContract.staticcall(
            abi.encodeWithSignature("getJob(uint256)", jobId)
        );
        if (!ok || retData.length < 96) return address(0);
        // ABI encoding of a struct with a dynamic string:
        // word 0 (0x00): offset to tuple = 0x20
        // word 1 (0x20): id
        // word 2 (0x40): client
        assembly {
            client := mload(add(retData, 0x60)) // 0x20 (len prefix) + 0x40 (client word)
        }
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL: ECDSA
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Recovers the signer from a 65-byte ECDSA signature.
     *      Uses ecrecover. Returns address(0) on invalid signature
     *      (which will fail the trustedSigner check).
     */
    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // EIP-2: restrict s to lower half of secp256k1 order
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        return ecrecover(hash, v, r, s);
    }
}
