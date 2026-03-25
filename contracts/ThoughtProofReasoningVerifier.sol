// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IReasoningVerifier.sol";

/// @title ThoughtProofReasoningVerifier
/// @notice Reference implementation of IReasoningVerifier for the ThoughtProof protocol.
///
///         ThoughtProof's off-chain service runs multi-model consensus verification
///         (pot-sdk) and submits signed results on-chain via submitVerification().
///         Hook contracts (ReasoningVerifierHook) call verifyReasoning() to gate actions.
///
/// @dev Attestation pattern (JWKS-style authority):
///      The authorized verifierSigner EOA is the on-chain representation of the
///      ThoughtProof service identity — analogous to a JWKS public key.
///      The off-chain service signs: keccak256(claimHash, confidence, verifierCount,
///      attestationHash, block.chainid), prefixed with the Ethereum signed message header.
///      chainId inclusion prevents cross-chain signature replay.
///
/// @custom:version 1.0.0
/// @custom:security CEI pattern, chainId replay protection, per-signature nonce via usedSignatures
contract ThoughtProofReasoningVerifier is IReasoningVerifier {

    // ============ Config ============

    address public owner;
    address public verifierSigner; // authorized ThoughtProof off-chain service EOA
    uint256 public minVerifiers;   // minimum number of models that must agree

    // ============ State ============

    struct VerificationRecord {
        bool verified;
        uint256 confidence;       // confidence * 1000 (e.g. 850 = 0.850)
        uint256 verifierCount;    // number of models that participated
        bytes32 attestationHash;  // keccak256 of the full Epistemic Block (stored off-chain)
        bytes32 deliverableHash;  // keccak256 of the deliverable content that was verified
        uint256 timestamp;
    }

    /// @notice claimHash => verification record
    mapping(bytes32 => VerificationRecord) public records;

    /// @notice signature hash => used; prevents replay across distinct calls
    mapping(bytes32 => bool) public usedSignatures;

    uint256 public totalSubmissions;

    // ============ Events ============

    event VerificationSubmitted(
        bytes32 indexed claimHash,
        uint256 confidence,
        uint256 verifierCount,
        bytes32 attestationHash
    );

    event ConfigUpdated(address verifierSigner, uint256 minVerifiers);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ============ Errors ============

    error Unauthorized();
    error InvalidSignature();
    error AlreadySubmitted();
    error SignatureAlreadyUsed();
    error InvalidParameters();
    error BelowMinVerifiers();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ============ Constructor ============

    /// @param _verifierSigner  EOA of the authorized ThoughtProof off-chain service.
    /// @param _minVerifiers    Minimum number of models required (≥ 2).
    constructor(address _verifierSigner, uint256 _minVerifiers) {
        if (_verifierSigner == address(0)) revert InvalidParameters();
        if (_minVerifiers < 2) revert InvalidParameters();
        owner = msg.sender;
        verifierSigner = _verifierSigner;
        minVerifiers = _minVerifiers;
    }

    // ============ IReasoningVerifier ============

    /// @inheritdoc IReasoningVerifier
    function verifyReasoning(bytes32 claimHash)
        external
        view
        override
        returns (bool verified, uint256 confidence)
    {
        VerificationRecord storage rec = records[claimHash];
        return (rec.verified, rec.confidence);
    }

    // ============ Submit ============

    /// @notice Submit a signed verification result from the ThoughtProof off-chain service.
    ///
    ///         The off-chain service:
    ///         1. Runs multi-model verification (pot-sdk) producing a confidence score
    ///            and an Epistemic Block.
    ///         2. Signs: keccak256(claimHash, confidence, verifierCount, attestationHash, chainId)
    ///         3. Calls this function with the signature.
    ///
    ///         Anyone may relay the submission; only a valid signature from verifierSigner is accepted.
    ///
    /// @param claimHash       keccak256 of the claim/action content (same hash the hook uses)
    /// @param confidence      Confidence * 1000 (0–1000)
    /// @param verifierCount   Number of models that participated
    /// @param attestationHash keccak256 of the full Epistemic Block (resolvable via api.thoughtproof.ai)
    /// @param deliverableHash keccak256 of the deliverable content verified (binds attestation to content)
    /// @param signature       65-byte ECDSA signature from verifierSigner
    function submitVerification(
        bytes32 claimHash,
        uint256 confidence,
        uint256 verifierCount,
        bytes32 attestationHash,
        bytes32 deliverableHash,
        bytes calldata signature
    ) external {
        // 1. Validate parameters
        if (claimHash == bytes32(0) || attestationHash == bytes32(0)) revert InvalidParameters();
        if (verifierCount < minVerifiers) revert BelowMinVerifiers();

        // 2. Prevent double-submission for the same claim
        if (records[claimHash].timestamp != 0) revert AlreadySubmitted();

        // 3. Verify signature (includes chainId — no cross-chain replay)
        _verifySignature(claimHash, confidence, verifierCount, attestationHash, deliverableHash, signature);

        // 4. Store result (CEI: state update before any external interaction)
        totalSubmissions++;
        records[claimHash] = VerificationRecord({
            verified: true,
            confidence: confidence,
            verifierCount: verifierCount,
            attestationHash: attestationHash,
            deliverableHash: deliverableHash,
            timestamp: block.timestamp
        });

        emit VerificationSubmitted(claimHash, confidence, verifierCount, attestationHash);
    }

    // ============ Views ============

    /// @notice Get the full verification record for a claim.
    function getRecord(bytes32 claimHash)
        external
        view
        returns (VerificationRecord memory)
    {
        return records[claimHash];
    }

    // ============ Admin ============

    /// @notice Update the authorized signer and/or minimum verifier count.
    function setConfig(address _verifierSigner, uint256 _minVerifiers) external onlyOwner {
        if (_verifierSigner == address(0)) revert InvalidParameters();
        if (_minVerifiers < 2) revert InvalidParameters();
        verifierSigner = _verifierSigner;
        minVerifiers = _minVerifiers;
        emit ConfigUpdated(_verifierSigner, _minVerifiers);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidParameters();
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
    }

    // ============ Internal ============

    function _verifySignature(
        bytes32 claimHash,
        uint256 confidence,
        uint256 verifierCount,
        bytes32 attestationHash,
        bytes32 deliverableHash,
        bytes calldata signature
    ) internal {
        bytes32 dataHash = keccak256(abi.encodePacked(
            claimHash, confidence, verifierCount, attestationHash, deliverableHash, block.chainid
        ));
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", dataHash
        ));

        bytes32 sigHash = keccak256(signature);
        if (usedSignatures[sigHash]) revert SignatureAlreadyUsed();
        usedSignatures[sigHash] = true;

        address recovered = _recoverSigner(messageHash, signature);
        if (recovered != verifierSigner) revert InvalidSignature();
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig)
        internal
        pure
        returns (address)
    {
        if (sig.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        if (v < 27) v += 27;

        address recovered = ecrecover(hash, v, r, s);
        if (recovered == address(0)) revert InvalidSignature();
        return recovered;
    }
}
