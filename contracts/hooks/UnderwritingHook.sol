// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@acp/AgenticCommerce.sol";
import "../BaseACPHook.sol";
import "./IUnderwritingHookView.sol";
import "./UnderwritingTypes.sol";
import "./UnderwritingWorkflowCore.sol";

interface IUnderwritingWiringTarget {
    function acp() external view returns (address);
    function hook() external view returns (address);
}

/**
 * @title UnderwritingHook
 * @notice Experimental underwriting example whose top-level hook acts as the
 *         ACP-facing shell, while `UnderwritingWorkflowCore` owns the internal
 *         underwriting workflow state and sidecar gating.
 *
 * USE CASE
 * --------
 * This hook adds an underwriting trust layer between the client and provider
 * for jobs where the client does not want ACP to release funds based only on
 * provider submission. Instead, submitted evidence must also be independently
 * approved or rejected by a registered underwriter signer before the job can
 * be finalized.
 *
 * The same underwriting mechanism supports both:
 *  - a normal single-stage underwritten job (token swap,etc.), and
 *  - a two-stage underwritten flow (open/close position, Defi yield farming, etc.) where a parent job, once approved, may
 *    later admit one hook-linked close job under the same underwriter.
 *
 * FLOW (hook callbacks marked with →)
 * ----
 *  1. Hook admin registers an allowed underwriter signer.
 *  2. Hook admin wires the underwriting evaluator and coordinator.
 *  3. Client creates a job with `hook = this` and `evaluator = evaluator`.
 *  3. Client calls `setBudget(jobId, amount, abi.encode(commit))`:
 *     → `_preSetBudget`: delegate into `UnderwritingWorkflowCore` to lock the
 *       committed underwriting terms and classify the job as:
 *         - `SingleStage`, or
 *         - `ParentPlusClose` when `allowCloseJob = true`.
 *  4. Client funds the job through the normal ACP flow.
 *     → `_postFund`: mark the sidecar state `FeeEscrowed`.
 *  5. Coordinator marks the job `Protected`.
 *  6. Provider submits `deliverable = evidence.bundleHash` with
 *     `optParams = abi.encode(SubmitEvidence)`:
 *     → `_postSubmit`: verify the submitted bundle, policy, quote, and terms
 *       hashes against the committed underwriting terms and mark the sidecar
 *       state `EvidenceSubmitted`.
 *  7. The underwriter signs either `CompleteDecision` or `RejectDecision`
 *     off-chain.
 *  8. Anyone may relay that signature through the separate evaluator contract:
 *     → evaluator verifies deadline, nonce, and signer
 *     → ACP `complete()` or `reject()` finalizes the job
 *     → this hook records the resulting workflow state.
 *  9. If the first job was committed with `allowCloseJob = true` and is
 *     approved:
 *     → `_postComplete`: mark the parent job `AwaitingClose`.
 * 10. A later close job is just another normal ACP `createJob(...)` call whose
 *     committed payload points back to the parent `jobId`:
 *     → `_preSetBudget`: validate same actors, same underwriter, and parent
 *       readiness before admitting the close stage.
 * 11. The close job then follows the same ACP rail plus coordinator protection:
 *     `setBudget -> fund -> markProtected -> submit -> evaluator complete/reject`.
 *
 * RECOVERY
 * --------
 *  - close rejection: `_postReject` clears only the active close linkage so
 *    the parent may stay `AwaitingClose`.
 *  - close expiry: `claimRefund()` remains outside the hook surface; the next
 *    close commit lazily clears the stale close slot if the previous close job
 *    already reached `Expired`.
 *
 * KEY PROPERTY
 * ------------
 * ACP remains the generic escrow rail. `UnderwritingHook` is the ACP-facing
 * shell, while `UnderwritingWorkflowCore` owns the internal underwriting
 * workflow state, including commit locking, sidecar state, parent/close
 * linkage, and close-stage admission rules.
 *
 * TRUST MODEL
 * -----------
 * ACP escrow behavior stays unchanged. This hook adds policy around who may
 * underwrite a job, what evidence must be submitted, and whether a later close
 * job is allowed. It reduces client risk from bad provider behavior by binding
 * payment release to an agreed underwriter decision and to committed evidence
 * hashes. Parent/close lineage is intentionally kept in hook state rather than
 * promoted into ACP core so this example can model a two-stage underwriting
 * flow without expanding the shared escrow kernel with workflow-specific
 * linkage primitives. This example is intentionally labeled
 * experimental rather than production-ready settlement infrastructure.
 */
contract UnderwritingHook is BaseACPHook, IUnderwritingHookView, UnderwritingWorkflowCore {
    error OnlyAdmin();
    error OnlyCoordinator();
    error WiringAlreadySet();
    error WiringIncomplete();
    error InvalidWiring();

    AgenticCommerce public immutable acp;
    address public immutable admin;
    address public evaluator;
    address public coordinator;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert OnlyCoordinator();
        _;
    }

    constructor(address acpContract_, address admin_) BaseACPHook(acpContract_) {
        if (admin_ == address(0)) revert ZeroAddress();
        acp = AgenticCommerce(acpContract_);
        admin = admin_;
    }

    function setWiring(address evaluator_, address coordinator_) external onlyAdmin {
        if (evaluator != address(0) || coordinator != address(0)) revert WiringAlreadySet();
        if (evaluator_ == address(0) || coordinator_ == address(0)) revert ZeroAddress();

        _assertWiringTarget(evaluator_);
        _assertWiringTarget(coordinator_);

        evaluator = evaluator_;
        coordinator = coordinator_;
    }

    function registerUnderwriter(address underwriter) external onlyAdmin {
        _registerUnderwriter(underwriter);
    }

    function unregisterUnderwriter(address underwriter) external onlyAdmin {
        _unregisterUnderwriter(underwriter);
    }

    function registeredUnderwriters(address underwriter) external view returns (bool) {
        return _isRegisteredUnderwriter(underwriter);
    }

    function getCommit(uint256 jobId) external view returns (UnderwritingTypes.UnderwriteCommit memory) {
        return _getCommit(jobId);
    }

    function jobUnderwriter(uint256 jobId) external view returns (address) {
        return _getUnderwriter(jobId);
    }

    function jobSidecarState(uint256 jobId) external view returns (UnderwritingTypes.SidecarState) {
        return _getSidecarState(jobId);
    }

    function jobSettlementJobId(uint256 jobId) external view returns (uint256) {
        return _getSettlementJobId(jobId);
    }

    function isAwaitingClose(uint256 jobId) external view returns (bool) {
        return _isAwaitingClose(jobId);
    }

    function getParentJobId(uint256 closeJobId) external view returns (uint256) {
        return _getParentJobId(closeJobId);
    }

    function getActiveCloseJobId(uint256 parentJobId) external view returns (uint256) {
        return _getActiveCloseJobId(parentJobId);
    }

    function markProtected(uint256 jobId) external onlyCoordinator {
        _markProtectedWorkflow(jobId);
    }

    function _preSetBudget(uint256 jobId, address, address token, uint256 amount, bytes memory optParams) internal override {
        _requireWiring();
        _preSetBudgetWorkflow(acp, evaluator, jobId, token, amount, optParams);
    }

    function _preFund(uint256 jobId, address, bytes memory) internal view override {
        _preFundWorkflow(acp, jobId);
    }

    function _postFund(uint256 jobId, address, bytes memory) internal override {
        _postFundWorkflow(jobId);
    }

    function _preSubmit(uint256 jobId, address, bytes32, bytes memory) internal view override {
        _preSubmitWorkflow(acp, jobId);
    }

    function _postSubmit(
        uint256 jobId,
        address,
        bytes32 deliverable,
        bytes memory optParams
    ) internal override {
        _postSubmitWorkflow(jobId, deliverable, optParams);
    }

    function _postComplete(uint256 jobId, address, bytes32, bytes memory) internal override {
        _postCompleteWorkflow(jobId);
    }

    function _preComplete(uint256 jobId, address, bytes32, bytes memory) internal view override {
        _preDecisionWorkflow(acp, jobId);
    }

    function _preReject(uint256 jobId, address, bytes32, bytes memory) internal view override {
        _preRejectWorkflow(acp, jobId);
    }

    function _postReject(uint256 jobId, address, bytes32, bytes memory) internal override {
        _postRejectWorkflow(jobId);
    }

    function _requireWiring() internal view {
        if (evaluator == address(0) || coordinator == address(0)) revert WiringIncomplete();
    }

    function _assertWiringTarget(address target) internal view {
        IUnderwritingWiringTarget wiringTarget = IUnderwritingWiringTarget(target);

        try wiringTarget.acp() returns (address targetAcp) {
            if (targetAcp != address(acp)) revert InvalidWiring();
        } catch {
            revert InvalidWiring();
        }

        try wiringTarget.hook() returns (address targetHook) {
            if (targetHook != address(this)) revert InvalidWiring();
        } catch {
            revert InvalidWiring();
        }
    }
}
