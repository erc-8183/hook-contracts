// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library UnderwritingTypes {
    enum SidecarState {
        None,
        Committed,
        Protected,
        EvidenceSubmitted,
        SuccessPendingConfirmation,
        RejectSettled
    }

    struct UnderwriteCommit {
        address underwriter;
        uint64 validUntil;
        bytes32 policyHash;
        bytes32 quoteIdHash;
        bytes32 termsHash;
    }

    struct SubmitEvidence {
        bytes32 bundleHash;
        bytes32 policyHash;
        bytes32 quoteIdHash;
        bytes32 termsHash;
    }

    struct CompleteDecision {
        uint256 jobId;
        bytes32 reason;
        uint64 deadline;
        uint256 nonce;
    }

    struct RejectDecision {
        uint256 jobId;
        bytes32 reason;
        uint64 deadline;
        uint256 nonce;
    }
}
