// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@acp/AgenticCommerce.sol";
import "./UnderwritingTypes.sol";

/**
 * @title UnderwritingWorkflowCore
 * @notice Internal workflow module behind `UnderwritingHook`.
 *
 * USE CASE
 * --------
 * This abstract module owns the underwriting state that ACP itself does not
 * track: the registered underwriter set, the locked commitment for each job,
 * and the optional parent/close linkage for a two-stage underwritten flow.
 *
 * `UnderwritingHook` remains the thin ACP-facing shell.
 * This module is where the underwriting-specific admission rules and sidecar
 * state live: commit locking, evidence matching, `AwaitingClose`, close-job
 * lineage, and the trimmed MCU-style state machine used by the coordinator and
 * evaluator scaffold.
 *
 * FLOW (workflow helpers marked with →)
 * ----
 *  1. Hook admin registers an allowed underwriter through the shell:
 *     → `_registerUnderwriter` / `_unregisterUnderwriter` maintain the local
 *       allowlist.
 *
 *  2. Client calls `setBudget(jobId, amount, abi.encode(commit))`:
 *     → `_preSetBudgetWorkflow` decodes the commit, locks the first
 *       `{commit,budget}` pair for the job, and classifies it as:
 *         - a root underwriting job (`parentJobId == 0`), or
 *         - a close job that points at an already approved parent job.
 *
 *  3. Provider submits `deliverable = evidence.bundleHash` with
 *     `optParams = abi.encode(SubmitEvidence)`:
 *     → `_postSubmitWorkflow` verifies the submitted bundle, policy, quote,
 *       and terms hashes against the committed underwriting terms.
 *
 *  4. After the shell relays an underwriter completion/rejection into ACP:
 *     → `_postCompleteWorkflow` either marks a root job `AwaitingClose` or, for
 *       a close job, clears the parent/close linkage after success.
 *     → `_postRejectWorkflow` clears only the active close slot so the parent
 *       may remain open for a later replacement close job.
 *
 * RECOVERY
 * --------
 *  - repeated `setBudget`: once a job is locked, only the exact same
 *    `{commit,budget}` pair may be replayed; any change reverts with
 *    `CommitLocked`.
 *  - stale close jobs: because `claimRefund()` is outside hook callbacks, the
 *    next close commit lazily clears the parent's active close slot when the
 *    previous close already reached a terminal state.
 *
 * KEY PROPERTY
 * ------------
 * ACP stays the generic escrow lifecycle. This module adds underwriting-specific
 * workflow state without teaching ACP core about underwriter policy or
 * parent/close lineage.
 */
abstract contract UnderwritingWorkflowCore {
    error UnderwriterNotRegistered();
    error ProviderRequired();
    error EvaluatorMismatch();
    error ZeroAddress();
    error CommitExpired();
    error CommitLocked();
    error CommitNotFound();
    error ParentNotCommitted();
    error ParentNotAwaitingClose();
    error ActiveCloseExists();
    error ParentMismatch();
    error EvidenceMismatch();
    error InvalidState();

    // -------------------------------------------------------------------------
    // Workflow storage
    // -------------------------------------------------------------------------

    mapping(address => bool) internal registeredUnderwriterByAddress;
    mapping(uint256 => UnderwritingTypes.UnderwriteCommit) internal commits;
    mapping(uint256 => bytes32) internal commitHashByJobId; // keccak256 lock for the committed underwriting terms
    mapping(uint256 => address) internal committedPaymentTokenByJobId; // payment token locked alongside the commit hash
    mapping(uint256 => uint256) internal committedBudgetByJobId; // budget that was locked alongside the commit hash
    mapping(uint256 => bool) internal awaitingCloseByJobId; // true once an approved parent may admit a close job
    mapping(uint256 => uint256) internal parentJobIdByCloseJobId; // reverse lookup from close job -> parent job
    mapping(uint256 => uint256) internal activeCloseJobIdByParentJobId; // at most one live close job per parent
    mapping(uint256 => UnderwritingTypes.SidecarState) internal sidecarStateByJobId;

    // -------------------------------------------------------------------------
    // Underwriter registry
    // -------------------------------------------------------------------------

    /// @dev Admit an underwriter signer that future commits may reference.
    function _registerUnderwriter(address underwriter) internal {
        if (underwriter == address(0)) revert ZeroAddress();
        registeredUnderwriterByAddress[underwriter] = true;
    }

    /// @dev Remove an underwriter signer from the local allowlist.
    function _unregisterUnderwriter(address underwriter) internal {
        if (underwriter == address(0)) revert ZeroAddress();
        delete registeredUnderwriterByAddress[underwriter];
    }

    /// @dev Check whether an underwriter is currently allowed for new root commits.
    function _isRegisteredUnderwriter(address underwriter) internal view returns (bool) {
        return registeredUnderwriterByAddress[underwriter];
    }

    // -------------------------------------------------------------------------
    // Workflow views
    // -------------------------------------------------------------------------

    /// @dev Return the stored underwriting commit for a job, if any.
    function _getCommit(uint256 jobId) internal view returns (UnderwritingTypes.UnderwriteCommit memory) {
        return commits[jobId];
    }

    /// @dev Return whether a completed parent job is waiting for a close stage.
    function _isAwaitingClose(uint256 jobId) internal view returns (bool) {
        return awaitingCloseByJobId[jobId];
    }

    /// @dev Return the parent job recorded for an admitted close job.
    function _getParentJobId(uint256 closeJobId) internal view returns (uint256) {
        return parentJobIdByCloseJobId[closeJobId];
    }

    /// @dev Return the currently active close job for a parent, if any.
    function _getActiveCloseJobId(uint256 parentJobId) internal view returns (uint256) {
        return activeCloseJobIdByParentJobId[parentJobId];
    }

    /// @dev Return the current sidecar state for a job, or `None` when absent.
    function _getSidecarState(uint256 jobId) internal view returns (UnderwritingTypes.SidecarState) {
        return sidecarStateByJobId[jobId];
    }

    /// @dev Return the settlement identity for a job.
    function _getSettlementJobId(uint256 jobId) internal view returns (uint256) {
        if (commitHashByJobId[jobId] == bytes32(0)) return 0;

        UnderwritingTypes.UnderwriteCommit memory commit = commits[jobId];
        if (commit.parentJobId != 0) {
            return commit.parentJobId;
        }

        return jobId;
    }

    /// @dev Return the underwriter committed for a job.
    function _getUnderwriter(uint256 jobId) internal view returns (address) {
        return _requireCommit(jobId).underwriter;
    }

    // -------------------------------------------------------------------------
    // ACP lifecycle workflow helpers
    // -------------------------------------------------------------------------

    /// @dev Lock underwriting terms on first `setBudget` and admit close jobs
    ///      only when the referenced parent workflow is ready.
    function _preSetBudgetWorkflow(
        AgenticCommerce acp,
        address expectedEvaluator,
        uint256 jobId,
        address paymentToken,
        uint256 amount,
        bytes memory optParams
    ) internal {
        AgenticCommerce.Job memory job = acp.getJob(jobId);
        UnderwritingTypes.UnderwriteCommit memory commit = abi.decode(optParams, (UnderwritingTypes.UnderwriteCommit));
        bytes32 newCommitHash = keccak256(abi.encode(commit));

        if (job.provider == address(0)) revert ProviderRequired();
        if (job.evaluator != expectedEvaluator) revert EvaluatorMismatch();

        // Once a job is committed, only an exact replay of the same
        // `{commit,budget}` pair is allowed.
        if (commitHashByJobId[jobId] != bytes32(0)) {
            if (commitHashByJobId[jobId] != newCommitHash) revert CommitLocked();
            if (committedPaymentTokenByJobId[jobId] != paymentToken) revert CommitLocked();
            if (committedBudgetByJobId[jobId] != amount) revert CommitLocked();
            return;
        }

        if (commit.validUntil <= block.timestamp) revert CommitExpired();

        if (commit.parentJobId == 0) {
            // Root jobs must name a currently registered underwriter.
            if (!registeredUnderwriterByAddress[commit.underwriter]) revert UnderwriterNotRegistered();
        } else {
            // Close jobs must point at a compatible, approved parent workflow.
            _clearStaleCloseIfTerminal(acp, commit.parentJobId);
            _validateCloseCommit(acp, jobId, job, commit);
            parentJobIdByCloseJobId[jobId] = commit.parentJobId;
            activeCloseJobIdByParentJobId[commit.parentJobId] = jobId;
        }

        commitHashByJobId[jobId] = newCommitHash;
        committedPaymentTokenByJobId[jobId] = paymentToken;
        committedBudgetByJobId[jobId] = amount;
        commits[jobId] = commit;
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.Committed;
    }

    /// @dev Require a committed job to still be in the `Committed` sidecar phase.
    function _preFundWorkflow(AgenticCommerce acp, uint256 jobId) internal view {
        UnderwritingTypes.UnderwriteCommit memory commit = _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Committed) revert InvalidState();
        if (commit.parentJobId != 0) _assertParentReadyForClose(acp, commit.parentJobId);
    }

    /// @dev Transition a funded job into `FeeEscrowed`.
    function _postFundWorkflow(uint256 jobId) internal {
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Committed) revert InvalidState();
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.FeeEscrowed;
    }

    /// @dev Mark a fee-funded job as externally protected by the coordinator.
    function _markProtectedWorkflow(uint256 jobId) internal {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.FeeEscrowed) revert InvalidState();
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.Protected;
    }

    /// @dev Require a protected job before provider submission.
    function _preSubmitWorkflow(AgenticCommerce acp, uint256 jobId) internal view {
        UnderwritingTypes.UnderwriteCommit memory commit = _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Protected) revert InvalidState();
        if (commit.parentJobId != 0) _assertParentReadyForClose(acp, commit.parentJobId);
    }

    /// @dev Ensure the submitted evidence exactly matches the committed hashes.
    function _postSubmitWorkflow(uint256 jobId, bytes32 deliverable, bytes memory optParams) internal {
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Protected) revert InvalidState();

        UnderwritingTypes.SubmitEvidence memory evidence = abi.decode(optParams, (UnderwritingTypes.SubmitEvidence));
        UnderwritingTypes.UnderwriteCommit memory commit = _requireCommit(jobId);

        if (deliverable != evidence.bundleHash) revert EvidenceMismatch();
        if (evidence.policyHash != commit.policyHash) revert EvidenceMismatch();
        if (evidence.quoteIdHash != commit.quoteIdHash) revert EvidenceMismatch();
        if (evidence.termsHash != commit.termsHash) revert EvidenceMismatch();

        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.EvidenceSubmitted;
    }

    /// @dev Require a submitted underwriting job before evaluator completion.
    function _preDecisionWorkflow(AgenticCommerce acp, uint256 jobId) internal view {
        UnderwritingTypes.UnderwriteCommit memory commit = _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.EvidenceSubmitted) revert InvalidState();
        if (commit.parentJobId != 0) _assertParentReadyForClose(acp, commit.parentJobId);
    }

    /// @dev Allow client-side open rejection, but require submitted evidence
    ///      for evaluator-driven terminal rejection once the job has progressed.
    function _preRejectWorkflow(AgenticCommerce acp, uint256 jobId) internal view {
        AgenticCommerce.Job memory job = acp.getJob(jobId);
        if (job.status == AgenticCommerce.JobStatus.Open) return;
        _preDecisionWorkflow(acp, jobId);
    }

    /// @dev Advance workflow state after ACP completes an underwritten job.
    function _postCompleteWorkflow(uint256 jobId) internal {
        UnderwritingTypes.UnderwriteCommit memory commit = _requireCommit(jobId);
        if (commit.parentJobId == 0 && commit.allowCloseJob) {
            // A successful parent job may now admit one close job.
            awaitingCloseByJobId[jobId] = true;
            sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.AwaitingClose;
            return;
        }

        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.SuccessPendingConfirmation;

        if (commit.parentJobId != 0) {
            // A successful close job retires the parent/close linkage.
            uint256 parentJobId = commit.parentJobId;
            if (activeCloseJobIdByParentJobId[parentJobId] == jobId) {
                delete activeCloseJobIdByParentJobId[parentJobId];
            }
            delete awaitingCloseByJobId[parentJobId];
            sidecarStateByJobId[parentJobId] = UnderwritingTypes.SidecarState.SuccessPendingConfirmation;
        }
    }

    /// @dev Clear the active close slot when a close job is rejected.
    function _postRejectWorkflow(uint256 jobId) internal {
        if (commitHashByJobId[jobId] == bytes32(0)) return;

        UnderwritingTypes.UnderwriteCommit memory commit = commits[jobId];
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.RejectSettled;

        if (commit.parentJobId != 0 && activeCloseJobIdByParentJobId[commit.parentJobId] == jobId) {
            delete activeCloseJobIdByParentJobId[commit.parentJobId];
        }
    }

    // -------------------------------------------------------------------------
    // Validation helpers
    // -------------------------------------------------------------------------

    /// @dev Admit a close commit only when it matches an approved parent
    ///      workflow and no different live close job is already occupying the slot.
    function _validateCloseCommit(
        AgenticCommerce acp,
        uint256 jobId,
        AgenticCommerce.Job memory job,
        UnderwritingTypes.UnderwriteCommit memory commit
    ) internal view {
        UnderwritingTypes.UnderwriteCommit memory parentCommit = commits[commit.parentJobId];
        AgenticCommerce.Job memory parentJob = acp.getJob(commit.parentJobId);
        uint256 activeCloseJobId = activeCloseJobIdByParentJobId[commit.parentJobId];

        if (commitHashByJobId[commit.parentJobId] == bytes32(0)) revert ParentNotCommitted();
        if (parentJob.id == 0) revert ParentMismatch();
        if (commit.parentJobId == jobId) revert ParentMismatch();
        if (parentCommit.parentJobId != 0 || !parentCommit.allowCloseJob || commit.allowCloseJob) {
            revert ParentMismatch();
        }
        if (
            parentJob.client != job.client || parentJob.provider != job.provider || parentJob.evaluator != job.evaluator
                || parentJob.hook != job.hook
        ) revert ParentMismatch();
        if (parentCommit.underwriter != commit.underwriter) revert ParentMismatch();
        _assertParentReadyForClose(acp, commit.parentJobId);
        if (activeCloseJobId != 0 && activeCloseJobId != jobId) revert ActiveCloseExists();
    }

    /// @dev Ensure the parent root job is still eligible for a close stage.
    function _assertParentReadyForClose(AgenticCommerce acp, uint256 parentJobId) internal view {
        AgenticCommerce.Job memory parentJob = acp.getJob(parentJobId);
        if (
            parentJob.status != AgenticCommerce.JobStatus.Completed
                || !awaitingCloseByJobId[parentJobId]
                || sidecarStateByJobId[parentJobId] != UnderwritingTypes.SidecarState.AwaitingClose
        ) {
            revert ParentNotAwaitingClose();
        }
    }

    /// @dev Lazily clear a parent's active close slot when the recorded close
    ///      job has already reached a terminal state outside the hook callbacks.
    function _clearStaleCloseIfTerminal(AgenticCommerce acp, uint256 parentJobId) internal {
        uint256 activeCloseJobId = activeCloseJobIdByParentJobId[parentJobId];
        if (activeCloseJobId == 0) return;

        AgenticCommerce.Job memory activeCloseJob = acp.getJob(activeCloseJobId);
        if (
            activeCloseJob.status == AgenticCommerce.JobStatus.Rejected
                || activeCloseJob.status == AgenticCommerce.JobStatus.Expired
        ) {
            delete activeCloseJobIdByParentJobId[parentJobId];
        }
    }

    /// @dev Load a previously locked commit or revert if the job never
    ///      established underwriting terms.
    function _requireCommit(uint256 jobId) internal view returns (UnderwritingTypes.UnderwriteCommit memory) {
        if (commitHashByJobId[jobId] == bytes32(0)) revert CommitNotFound();
        return commits[jobId];
    }
}
