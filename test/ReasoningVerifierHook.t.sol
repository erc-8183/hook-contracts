// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IReasoningVerifier} from "../src/IReasoningVerifier.sol";
import {ThoughtProofReasoningVerifier} from "../src/ThoughtProofReasoningVerifier.sol";
import {ReasoningVerifierHook} from "../src/ReasoningVerifierHook.sol";

// ============================================================
// Mock Verifier (not ThoughtProof-specific — tests the interface)
// ============================================================

/// @notice Minimal mock that implements IReasoningVerifier for hook testing.
///         Allows direct injection of (verified, confidence) without signature logic.
contract MockReasoningVerifier is IReasoningVerifier {
    mapping(bytes32 => bool) private _verified;
    mapping(bytes32 => uint256) private _confidence;

    function setResult(bytes32 claimHash, bool verified, uint256 confidence) external {
        _verified[claimHash] = verified;
        _confidence[claimHash] = confidence;
    }

    function verifyReasoning(bytes32 claimHash)
        external
        view
        override
        returns (bool verified, uint256 confidence)
    {
        return (_verified[claimHash], _confidence[claimHash]);
    }
}

// ============================================================
// ThoughtProofReasoningVerifier tests
// ============================================================

contract ThoughtProofReasoningVerifierTest is Test {
    ThoughtProofReasoningVerifier verifier;

    uint256 signerKey = 0xA11CE;
    address signer;

    uint256 constant MIN_VERIFIERS = 3;
    bytes32 constant DEFAULT_DELIVERABLE = keccak256("test-deliverable");

    function setUp() public {
        signer = vm.addr(signerKey);
        verifier = new ThoughtProofReasoningVerifier(signer, MIN_VERIFIERS);
    }

    // ---- Helpers ----

    function _sign(
        bytes32 claimHash,
        uint256 confidence,
        uint256 verifierCount,
        bytes32 attestationHash,
        bytes32 deliverableHash
    ) internal view returns (bytes memory) {
        bytes32 dataHash = keccak256(abi.encodePacked(
            claimHash, confidence, verifierCount, attestationHash, deliverableHash, block.chainid
        ));
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", dataHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    // ---- Deployment ----

    function test_Deployment() public view {
        assertEq(verifier.owner(), address(this));
        assertEq(verifier.verifierSigner(), signer);
        assertEq(verifier.minVerifiers(), MIN_VERIFIERS);
        assertEq(verifier.totalSubmissions(), 0);
    }

    function test_Deployment_RevertZeroSigner() public {
        vm.expectRevert(ThoughtProofReasoningVerifier.InvalidParameters.selector);
        new ThoughtProofReasoningVerifier(address(0), MIN_VERIFIERS);
    }

    function test_Deployment_RevertTooFewVerifiers() public {
        vm.expectRevert(ThoughtProofReasoningVerifier.InvalidParameters.selector);
        new ThoughtProofReasoningVerifier(signer, 1);
    }

    // ---- verifyReasoning: not yet submitted ----

    function test_VerifyReasoning_NotSubmitted() public view {
        bytes32 claimHash = keccak256("unknown-claim");
        (bool verified, uint256 confidence) = verifier.verifyReasoning(claimHash);
        assertFalse(verified);
        assertEq(confidence, 0);
    }

    // ---- submitVerification happy path ----

    function test_SubmitVerification_HappyPath() public {
        bytes32 claimHash = keccak256("claim-001");
        uint256 confidence = 850;
        uint256 verifierCount = 3;
        bytes32 attestationHash = keccak256("epistemic-block-001");

        bytes memory sig = _sign(claimHash, confidence, verifierCount, attestationHash, DEFAULT_DELIVERABLE);
        verifier.submitVerification(claimHash, confidence, verifierCount, attestationHash, DEFAULT_DELIVERABLE, sig);

        (bool verified, uint256 conf) = verifier.verifyReasoning(claimHash);
        assertTrue(verified);
        assertEq(conf, confidence);
        assertEq(verifier.totalSubmissions(), 1);
    }

    function test_SubmitVerification_RecordDetails() public {
        bytes32 claimHash = keccak256("claim-002");
        uint256 confidence = 920;
        uint256 verifierCount = 5;
        bytes32 attestationHash = keccak256("block-002");

        bytes memory sig = _sign(claimHash, confidence, verifierCount, attestationHash, DEFAULT_DELIVERABLE);
        verifier.submitVerification(claimHash, confidence, verifierCount, attestationHash, DEFAULT_DELIVERABLE, sig);

        ThoughtProofReasoningVerifier.VerificationRecord memory rec = verifier.getRecord(claimHash);
        assertTrue(rec.verified);
        assertEq(rec.confidence, confidence);
        assertEq(rec.verifierCount, verifierCount);
        assertEq(rec.attestationHash, attestationHash);
        assertGt(rec.timestamp, 0);
    }

    function test_SubmitVerification_LowConfidenceStillStored() public {
        // Low confidence is stored; the hook enforces the minimum threshold
        bytes32 claimHash = keccak256("claim-low");
        uint256 confidence = 100;
        bytes32 attestationHash = keccak256("block-low");

        bytes memory sig = _sign(claimHash, confidence, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE);
        verifier.submitVerification(claimHash, confidence, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE, sig);

        (bool verified, uint256 conf) = verifier.verifyReasoning(claimHash);
        assertTrue(verified);
        assertEq(conf, 100);
    }

    // ---- submitVerification: error cases ----

    function test_Submit_RevertOnZeroClaimHash() public {
        bytes32 attestationHash = keccak256("block");
        bytes memory sig = _sign(bytes32(0), 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE);
        vm.expectRevert(ThoughtProofReasoningVerifier.InvalidParameters.selector);
        verifier.submitVerification(bytes32(0), 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE, sig);
    }

    function test_Submit_RevertOnZeroAttestationHash() public {
        bytes32 claimHash = keccak256("claim");
        bytes memory sig = _sign(claimHash, 850, MIN_VERIFIERS, bytes32(0), DEFAULT_DELIVERABLE);
        vm.expectRevert(ThoughtProofReasoningVerifier.InvalidParameters.selector);
        verifier.submitVerification(claimHash, 850, MIN_VERIFIERS, bytes32(0), DEFAULT_DELIVERABLE, sig);
    }

    function test_Submit_RevertBelowMinVerifiers() public {
        bytes32 claimHash = keccak256("claim-fewverifiers");
        bytes32 attestationHash = keccak256("block");
        bytes memory sig = _sign(claimHash, 850, 2, attestationHash, DEFAULT_DELIVERABLE);
        vm.expectRevert(ThoughtProofReasoningVerifier.BelowMinVerifiers.selector);
        verifier.submitVerification(claimHash, 850, 2, attestationHash, DEFAULT_DELIVERABLE, sig);
    }

    function test_Submit_RevertDoubleSubmission() public {
        bytes32 claimHash = keccak256("claim-double");
        bytes32 attestationHash = keccak256("block-double");

        bytes memory sig = _sign(claimHash, 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE);
        verifier.submitVerification(claimHash, 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE, sig);

        bytes32 attestationHash2 = keccak256("block-double-2");
        bytes memory sig2 = _sign(claimHash, 850, MIN_VERIFIERS, attestationHash2, DEFAULT_DELIVERABLE);
        vm.expectRevert(ThoughtProofReasoningVerifier.AlreadySubmitted.selector);
        verifier.submitVerification(claimHash, 850, MIN_VERIFIERS, attestationHash2, DEFAULT_DELIVERABLE, sig2);
    }

    function test_Submit_RevertInvalidSignature() public {
        bytes32 claimHash = keccak256("claim-badsig");
        bytes32 attestationHash = keccak256("block-badsig");

        uint256 wrongKey = 0xBAD;
        bytes32 dataHash = keccak256(abi.encodePacked(
            claimHash, uint256(850), uint256(MIN_VERIFIERS), attestationHash, DEFAULT_DELIVERABLE, block.chainid
        ));
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", dataHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, messageHash);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(ThoughtProofReasoningVerifier.InvalidSignature.selector);
        verifier.submitVerification(claimHash, 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE, badSig);
    }

    function test_Submit_RevertSignatureReplay() public {
        bytes32 claimHash1 = keccak256("claim-replay-1");
        bytes32 claimHash2 = keccak256("claim-replay-2");
        bytes32 attestationHash = keccak256("block-replay");

        bytes memory sig = _sign(claimHash1, 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE);
        verifier.submitVerification(claimHash1, 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE, sig);

        // Same signature, different claim — replay attempt
        vm.expectRevert(ThoughtProofReasoningVerifier.SignatureAlreadyUsed.selector);
        verifier.submitVerification(claimHash2, 850, MIN_VERIFIERS, attestationHash, DEFAULT_DELIVERABLE, sig);
    }

    // ---- Admin ----

    function test_SetConfig() public {
        address newSigner = address(0xBEEF);
        verifier.setConfig(newSigner, 5);
        assertEq(verifier.verifierSigner(), newSigner);
        assertEq(verifier.minVerifiers(), 5);
    }

    function test_SetConfig_OnlyOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(ThoughtProofReasoningVerifier.Unauthorized.selector);
        verifier.setConfig(address(0xBEEF), 3);
    }

    function test_TransferOwnership() public {
        address newOwner = address(0xCAFE);
        verifier.transferOwnership(newOwner);
        assertEq(verifier.owner(), newOwner);
    }

    function test_TransferOwnership_RevertZero() public {
        vm.expectRevert(ThoughtProofReasoningVerifier.InvalidParameters.selector);
        verifier.transferOwnership(address(0));
    }
}

// ============================================================
// ReasoningVerifierHook tests (uses MockReasoningVerifier)
// ============================================================

contract ReasoningVerifierHookTest is Test {
    MockReasoningVerifier mockVerifier;
    ReasoningVerifierHook hook;

    uint256 constant MIN_CONFIDENCE = 700;

    function setUp() public {
        mockVerifier = new MockReasoningVerifier();
        hook = new ReasoningVerifierHook(IReasoningVerifier(address(mockVerifier)), MIN_CONFIDENCE);
    }

    // ---- Deployment ----

    function test_Deployment() public view {
        assertEq(address(hook.verifier()), address(mockVerifier));
        assertEq(hook.minConfidence(), MIN_CONFIDENCE);
        assertEq(hook.owner(), address(this));
    }

    function test_Deployment_RevertZeroVerifier() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(IReasoningVerifier(address(0)), MIN_CONFIDENCE);
    }

    function test_Deployment_RevertConfidenceTooLow() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(IReasoningVerifier(address(mockVerifier)), 99);
    }

    function test_Deployment_RevertConfidenceTooHigh() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        new ReasoningVerifierHook(IReasoningVerifier(address(mockVerifier)), 1001);
    }

    // ---- beforeAction: allow ----

    function test_BeforeAction_AllowsWhenVerifiedAboveThreshold() public {
        bytes32 claimHash = keccak256("claim-allow");
        mockVerifier.setResult(claimHash, true, 850);
        hook.beforeAction(claimHash); // should not revert
    }

    function test_BeforeAction_AllowsAtExactThreshold() public {
        bytes32 claimHash = keccak256("claim-exact");
        mockVerifier.setResult(claimHash, true, MIN_CONFIDENCE);
        hook.beforeAction(claimHash); // should not revert
    }

    // ---- beforeAction: block ----

    function test_BeforeAction_RevertsWhenNotVerified() public {
        bytes32 claimHash = keccak256("claim-unverified");
        // Not registered in mock — verified=false, confidence=0
        vm.expectRevert(
            abi.encodeWithSelector(ReasoningVerifierHook.NotVerified.selector, claimHash)
        );
        hook.beforeAction(claimHash);
    }

    function test_BeforeAction_RevertsWhenVerifiedButConfidenceTooLow() public {
        bytes32 claimHash = keccak256("claim-lowconf");
        mockVerifier.setResult(claimHash, true, 600); // below 700

        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.ConfidenceTooLow.selector,
                claimHash, uint256(600), uint256(MIN_CONFIDENCE)
            )
        );
        hook.beforeAction(claimHash);
    }

    function test_BeforeAction_RevertsAtOneBelow() public {
        bytes32 claimHash = keccak256("claim-699");
        mockVerifier.setResult(claimHash, true, MIN_CONFIDENCE - 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ReasoningVerifierHook.ConfidenceTooLow.selector,
                claimHash, uint256(MIN_CONFIDENCE - 1), uint256(MIN_CONFIDENCE)
            )
        );
        hook.beforeAction(claimHash);
    }

    // ---- afterAction ----

    function test_AfterAction_DoesNotRevert_WhenVerified() public {
        bytes32 claimHash = keccak256("claim-after-ok");
        mockVerifier.setResult(claimHash, true, 850);
        hook.afterAction(claimHash); // must not revert
    }

    function test_AfterAction_DoesNotRevert_WhenNotVerified() public {
        bytes32 claimHash = keccak256("claim-after-unverified");
        // afterAction is informational — must never revert
        hook.afterAction(claimHash);
    }

    function test_AfterAction_DoesNotRevert_WhenLowConfidence() public {
        bytes32 claimHash = keccak256("claim-after-low");
        mockVerifier.setResult(claimHash, true, 200);
        hook.afterAction(claimHash); // must not revert
    }

    // ---- Protocol-agnostic: swap verifier ----

    function test_HookWorksWithAnyVerifier() public {
        // Deploy a second mock to prove the hook is verifier-agnostic
        MockReasoningVerifier altVerifier = new MockReasoningVerifier();
        ReasoningVerifierHook altHook = new ReasoningVerifierHook(
            IReasoningVerifier(address(altVerifier)), 800
        );

        bytes32 claimHash = keccak256("claim-alt");
        altVerifier.setResult(claimHash, true, 900);
        altHook.beforeAction(claimHash); // should pass

        // Same claim, but on original hook (different verifier state) — not set
        vm.expectRevert(
            abi.encodeWithSelector(ReasoningVerifierHook.NotVerified.selector, claimHash)
        );
        hook.beforeAction(claimHash);
    }

    // ---- Integration: hook + ThoughtProofReasoningVerifier ----

    function test_Integration_HookWithRealVerifier() public {
        uint256 signerKey = 0xA11CE;
        address signer = vm.addr(signerKey);

        ThoughtProofReasoningVerifier tpVerifier = new ThoughtProofReasoningVerifier(signer, 3);
        ReasoningVerifierHook tpHook = new ReasoningVerifierHook(
            IReasoningVerifier(address(tpVerifier)), 700
        );

        bytes32 claimHash = keccak256("integration-claim");
        uint256 confidence = 850;
        uint256 verifierCount = 3;
        bytes32 attestationHash = keccak256("integration-block");

        // Before submission: hook should revert
        vm.expectRevert(
            abi.encodeWithSelector(ReasoningVerifierHook.NotVerified.selector, claimHash)
        );
        tpHook.beforeAction(claimHash);

        // Submit to verifier
        bytes32 deliverableHash = keccak256("integration-deliverable");
        bytes32 dataHash = keccak256(abi.encodePacked(
            claimHash, confidence, verifierCount, attestationHash, deliverableHash, block.chainid
        ));
        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", dataHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        tpVerifier.submitVerification(claimHash, confidence, verifierCount, attestationHash, deliverableHash, sig);

        // After submission: hook should pass
        tpHook.beforeAction(claimHash);
    }

    // ---- Admin ----

    function test_SetMinConfidence() public {
        hook.setMinConfidence(800);
        assertEq(hook.minConfidence(), 800);
    }

    function test_SetMinConfidence_OnlyOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(ReasoningVerifierHook.Unauthorized.selector);
        hook.setMinConfidence(800);
    }

    function test_SetMinConfidence_RevertTooLow() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        hook.setMinConfidence(99);
    }

    function test_SetMinConfidence_RevertTooHigh() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        hook.setMinConfidence(1001);
    }

    function test_TransferOwnership() public {
        address newOwner = address(0xCAFE);
        hook.transferOwnership(newOwner);
        assertEq(hook.owner(), newOwner);

        // Old owner can no longer act
        vm.expectRevert(ReasoningVerifierHook.Unauthorized.selector);
        hook.setMinConfidence(800);
    }

    function test_TransferOwnership_RevertZero() public {
        vm.expectRevert(ReasoningVerifierHook.InvalidParameters.selector);
        hook.transferOwnership(address(0));
    }
}
