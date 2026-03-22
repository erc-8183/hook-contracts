// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ThoughtProofReasoningHook} from "../contracts/hooks/ThoughtProofReasoningHook.sol";

/// @dev Minimal mock of AgenticCommerceHooked matching its exact struct layout
contract MockACP {
    enum JobStatus { Open, Funded, Submitted, Completed, Rejected, Expired }

    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        address hook;
        string description;
        uint256 budget;
        uint256 expiredAt;
        JobStatus status;
    }

    mapping(uint256 => Job) public jobs;

    function setJob(uint256 jobId, address client_, address provider_) external {
        jobs[jobId] = Job({
            id: jobId,
            client: client_,
            provider: provider_,
            evaluator: address(0),
            hook: address(0),
            description: "",
            budget: 1000e6,
            expiredAt: block.timestamp + 1 days,
            status: JobStatus.Submitted
        });
    }

    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }

    /// @dev Simulate ACP calling the hook's beforeAction
    function callBeforeAction(
        address hookAddr,
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external {
        ThoughtProofReasoningHook(hookAddr).beforeAction(jobId, selector, data);
    }
}

contract ThoughtProofReasoningHookTest is Test {
    ThoughtProofReasoningHook hook;
    MockACP acp;

    uint256 constant SIGNER_PK = 0xBEEF;
    address signer;
    address owner = address(0xCAFE);
    address agent = address(0xABCD);
    address provider = address(0xDEAD);

    bytes4 constant SEL_SUBMIT = bytes4(keccak256("submit(uint256,bytes32,bytes)"));

    function setUp() public {
        // Warp to a sane timestamp (avoids underflow in expiry tests)
        vm.warp(1_700_000_000);

        signer = vm.addr(SIGNER_PK);
        acp = new MockACP();
        hook = new ThoughtProofReasoningHook(address(acp), signer, owner, 0);

        // Set up a test job
        acp.setJob(1, agent, provider);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPERS
    //////////////////////////////////////////////////////////////*/

    function _makeAttestation(
        uint256 jobId,
        bytes32 claimHash,
        bytes32 verdict,
        uint256 confidence,
        uint256 timestamp,
        bytes32 nonce
    ) internal pure returns (bytes memory) {
        // Build the payload hash exactly as the contract does
        bytes32 payloadHash = keccak256(abi.encode(
            ThoughtProofReasoningHook.AttestationPayload({
                jobId: jobId,
                claimHash: claimHash,
                verdict: verdict,
                confidence: confidence,
                timestamp: timestamp,
                nonce: nonce
            })
        ));

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                payloadHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        return abi.encode(claimHash, verdict, confidence, timestamp, nonce, signature);
    }

    /*//////////////////////////////////////////////////////////////
                    HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_allowsSubmitWithValidAttestation() public {
        bytes32 claimHash = keccak256("Swap 50k USDC for ETH");
        bytes32 verdict = hook.VERDICT_ALLOW();
        uint256 confidence = 9200; // 92%
        uint256 timestamp = block.timestamp;
        bytes32 nonce = bytes32(uint256(1));

        bytes memory optParams = _makeAttestation(
            1, claimHash, verdict, confidence, timestamp, nonce
        );

        // BaseACPHook._preSubmit receives (deliverable, optParams) decoded from data
        bytes memory hookData = abi.encode(
            bytes32("deliverable_hash"),
            optParams
        );

        acp.callBeforeAction(address(hook), 1, SEL_SUBMIT, hookData);

        // Verify attestation was recorded
        assertTrue(hook.hasAttestation(1));
        assertEq(hook.totalGated(), 1);
        assertEq(hook.totalBlocked(), 0);

        // Verify attestation details
        ThoughtProofReasoningHook.Attestation memory att = hook.getAttestation(1);
        assertEq(att.verdict, verdict);
        assertEq(att.confidence, confidence);
        assertEq(att.claimHash, claimHash);
    }

    /*//////////////////////////////////////////////////////////////
                    REVERT: HOLD VERDICT
    //////////////////////////////////////////////////////////////*/

    function test_revertsOnHoldVerdict() public {
        bytes32 claimHash = keccak256("Swap 50k USDC for PEPE");
        bytes32 verdict = hook.VERDICT_HOLD();
        uint256 confidence = 1500; // 15%
        uint256 timestamp = block.timestamp;
        bytes32 nonce = bytes32(uint256(2));

        bytes memory optParams = _makeAttestation(
            1, claimHash, verdict, confidence, timestamp, nonce
        );

        bytes memory hookData = abi.encode(bytes32("deliverable"), optParams);

        vm.expectRevert(
            abi.encodeWithSelector(
                ThoughtProofReasoningHook.ThoughtProofHook__VerdictNotAllow.selector,
                verdict,
                confidence
            )
        );
        acp.callBeforeAction(address(hook), 1, SEL_SUBMIT, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                    REVERT: REPLAY ATTACK
    //////////////////////////////////////////////////////////////*/

    function test_revertsOnNonceReuse() public {
        bytes32 claimHash = keccak256("Safe trade");
        bytes32 verdict = hook.VERDICT_ALLOW();
        bytes32 nonce = bytes32(uint256(3));

        bytes memory optParams = _makeAttestation(
            1, claimHash, verdict, 9000, block.timestamp, nonce
        );

        bytes memory hookData = abi.encode(bytes32("deliverable"), optParams);

        // First call succeeds
        acp.callBeforeAction(address(hook), 1, SEL_SUBMIT, hookData);

        // Set up a new job for second attempt
        acp.setJob(2, agent, provider);

        bytes memory optParams2 = _makeAttestation(
            2, claimHash, verdict, 9000, block.timestamp, nonce
        );
        bytes memory hookData2 = abi.encode(bytes32("deliverable"), optParams2);

        // Second call with same nonce reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                ThoughtProofReasoningHook.ThoughtProofHook__NonceReused.selector,
                nonce
            )
        );
        acp.callBeforeAction(address(hook), 2, SEL_SUBMIT, hookData2);
    }

    /*//////////////////////////////////////////////////////////////
                    REVERT: EXPIRED ATTESTATION
    //////////////////////////////////////////////////////////////*/

    function test_revertsOnExpiredAttestation() public {
        bytes32 claimHash = keccak256("Old trade");
        bytes32 verdict = hook.VERDICT_ALLOW();
        uint256 oldTimestamp = block.timestamp - 600; // 10 min ago
        bytes32 nonce = bytes32(uint256(4));

        bytes memory optParams = _makeAttestation(
            1, claimHash, verdict, 9000, oldTimestamp, nonce
        );

        bytes memory hookData = abi.encode(bytes32("deliverable"), optParams);

        vm.expectRevert(
            abi.encodeWithSelector(
                ThoughtProofReasoningHook.ThoughtProofHook__AttestationExpired.selector,
                oldTimestamp,
                block.timestamp
            )
        );
        acp.callBeforeAction(address(hook), 1, SEL_SUBMIT, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                    REVERT: WRONG SIGNER
    //////////////////////////////////////////////////////////////*/

    function test_revertsOnWrongSigner() public {
        // Sign with a different key
        uint256 fakePk = 0xDEAD;
        bytes32 claimHash = keccak256("Fake attestation");
        bytes32 verdict = hook.VERDICT_ALLOW();
        uint256 timestamp = block.timestamp;
        bytes32 nonce = bytes32(uint256(5));

        bytes32 payloadHash = keccak256(abi.encode(
            ThoughtProofReasoningHook.AttestationPayload({
                jobId: 1,
                claimHash: claimHash,
                verdict: verdict,
                confidence: 9000,
                timestamp: timestamp,
                nonce: nonce
            })
        ));

        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakePk, messageHash);
        bytes memory fakeSig = abi.encodePacked(r, s, v);

        bytes memory optParams = abi.encode(
            claimHash, verdict, uint256(9000), timestamp, nonce, fakeSig
        );
        bytes memory hookData = abi.encode(bytes32("deliverable"), optParams);

        vm.expectRevert(ThoughtProofReasoningHook.ThoughtProofHook__InvalidSignature.selector);
        acp.callBeforeAction(address(hook), 1, SEL_SUBMIT, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                    REVERT: MISSING ATTESTATION
    //////////////////////////////////////////////////////////////*/

    function test_revertsOnMissingAttestation() public {
        bytes memory hookData = abi.encode(bytes32("deliverable"), bytes(""));

        vm.expectRevert(ThoughtProofReasoningHook.ThoughtProofHook__MissingAttestation.selector);
        acp.callBeforeAction(address(hook), 1, SEL_SUBMIT, hookData);
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN: SIGNER ROTATION
    //////////////////////////////////////////////////////////////*/

    function test_ownerCanRotateSigner() public {
        address newSigner = address(0xBEEF2);

        vm.prank(owner);
        hook.rotateSigner(newSigner);

        assertEq(hook.trustedSigner(), newSigner);
    }

    function test_nonOwnerCannotRotateSigner() public {
        vm.prank(agent);
        vm.expectRevert(ThoughtProofReasoningHook.ThoughtProofHook__NotOwner.selector);
        hook.rotateSigner(address(0xBEEF2));
    }

    /*//////////////////////////////////////////////////////////////
                    NON-SUBMIT SELECTORS PASS THROUGH
    //////////////////////////////////////////////////////////////*/

    function test_nonSubmitSelectorsPassThrough() public {
        bytes4 fundSel = bytes4(keccak256("fund(uint256,bytes)"));

        // Fund should pass through without attestation
        acp.callBeforeAction(address(hook), 1, fundSel, bytes(""));
    }
}
