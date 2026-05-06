// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@acp/AgenticCommerce.sol";
import "@acp/IACPHook.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./IUnderwritingHookView.sol";
import "./UnderwritingTypes.sol";

/**
 * @title UnderwritingHook
 * @notice Experimental single-stage underwriting hook.
 *
 * USE CASE
 * --------
 * For jobs that need more than evaluator attestation, this hook lets the
 * client and provider pre-commit underwriting terms at `setBudget(...)`, then
 * requires the provider's submission evidence to match those committed terms
 * before an allowed underwriter can finalize the job through a signed
 * completion or rejection decision.
 *
 * FLOW
 * ----
 *  1. Admin registers an allowed underwriter signer and sets the evaluator.
 *  2. Client or provider calls `setBudget(...)` with
 *     `optParams = abi.encode(UnderwriteCommit)`.
 *  3. The hook commit-locks `{underwriteCommit, paymentToken, budget}`.
 *  4. After the job is funded, the hook marks it `Protected`.
 *  5. Provider submits `deliverable = evidence.bundleHash` with
 *     `optParams = abi.encode(SubmitEvidence)`.
 *  6. The hook checks `bundleHash`, `policyHash`, `quoteIdHash`, and
 *     `termsHash` against the locked commit and marks the job
 *     `EvidenceSubmitted`.
 *  7. The underwriter signs a `CompleteDecision` or `RejectDecision`.
 *  8. `UnderwritingEvaluator` verifies the signature and relays
 *     `complete()` / `reject()` into ACP.
 *
 * TRUST MODEL
 * -----------
 * ACP keeps custody and settlement. This hook only adds underwriting policy:
 * who may underwrite a job, which evidence hashes must match, and that final
 * completion or rejection requires a registered underwriter signature after
 * evidence submission.
 */
contract UnderwritingHook is ERC165, IACPHook, IUnderwritingHookView {
    error OnlyACPContract();
    error OnlyAdmin();
    error ZeroAddress();
    error EvaluatorAlreadySet();
    error EvaluatorNotSet();
    error UnderwriterNotRegistered();
    error ProviderRequired();
    error EvaluatorMismatch();
    error CommitExpired();
    error CommitLocked();
    error CommitNotFound();
    error EvidenceMismatch();
    error InvalidState();

    AgenticCommerce public immutable acp;
    address public immutable admin;
    address public evaluator;

    mapping(address => bool) internal registeredUnderwriterByAddress;
    mapping(uint256 => UnderwritingTypes.UnderwriteCommit) internal commits;
    mapping(uint256 => bytes32) internal commitHashByJobId;
    mapping(uint256 => address) internal committedPaymentTokenByJobId;
    mapping(uint256 => uint256) internal committedBudgetByJobId;
    mapping(uint256 => UnderwritingTypes.SidecarState) internal sidecarStateByJobId;

    bytes4 private constant SEL_SET_BUDGET =
        bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
    bytes4 private constant SEL_FUND =
        bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 private constant SEL_SUBMIT =
        bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_COMPLETE =
        bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_REJECT =
        bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    modifier onlyACP() {
        if (msg.sender != address(acp)) revert OnlyACPContract();
        _;
    }

    constructor(address acpContract_, address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        acp = AgenticCommerce(acpContract_);
        admin = admin_;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IACPHook).interfaceId || super.supportsInterface(interfaceId);
    }

    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override onlyACP {
        if (selector == SEL_SET_BUDGET) {
            (address caller, address token, uint256 amount, bytes memory optParams) = abi.decode(
                data, (address, address, uint256, bytes)
            );
            _preSetBudget(jobId, caller, token, amount, optParams);
        } else if (selector == SEL_FUND) {
            (address caller, bytes memory optParams) = abi.decode(data, (address, bytes));
            _preFund(jobId, caller, optParams);
        } else if (selector == SEL_SUBMIT) {
            (address caller, bytes32 deliverable, bytes memory optParams) = abi.decode(
                data, (address, bytes32, bytes)
            );
            _preSubmit(jobId, caller, deliverable, optParams);
        } else if (selector == SEL_COMPLETE) {
            (address caller, bytes32 reason, bytes memory optParams) = abi.decode(
                data, (address, bytes32, bytes)
            );
            _preComplete(jobId, caller, reason, optParams);
        } else if (selector == SEL_REJECT) {
            (address caller, bytes32 reason, bytes memory optParams) = abi.decode(
                data, (address, bytes32, bytes)
            );
            _preReject(jobId, caller, reason, optParams);
        }
    }

    function afterAction(uint256 jobId, bytes4 selector, bytes calldata data) external override onlyACP {
        if (selector == SEL_SET_BUDGET) {
            (address caller, address token, uint256 amount, bytes memory optParams) = abi.decode(
                data, (address, address, uint256, bytes)
            );
            _postSetBudget(jobId, caller, token, amount, optParams);
        } else if (selector == SEL_FUND) {
            (address caller, bytes memory optParams) = abi.decode(data, (address, bytes));
            _postFund(jobId, caller, optParams);
        } else if (selector == SEL_SUBMIT) {
            (address caller, bytes32 deliverable, bytes memory optParams) = abi.decode(
                data, (address, bytes32, bytes)
            );
            _postSubmit(jobId, caller, deliverable, optParams);
        } else if (selector == SEL_COMPLETE) {
            (address caller, bytes32 reason, bytes memory optParams) = abi.decode(
                data, (address, bytes32, bytes)
            );
            _postComplete(jobId, caller, reason, optParams);
        } else if (selector == SEL_REJECT) {
            (address caller, bytes32 reason, bytes memory optParams) = abi.decode(
                data, (address, bytes32, bytes)
            );
            _postReject(jobId, caller, reason, optParams);
        }
    }

    function setEvaluator(address evaluator_) external onlyAdmin {
        if (evaluator_ == address(0)) revert ZeroAddress();
        if (evaluator != address(0)) revert EvaluatorAlreadySet();
        evaluator = evaluator_;
    }

    function registerUnderwriter(address underwriter) external onlyAdmin {
        if (underwriter == address(0)) revert ZeroAddress();
        registeredUnderwriterByAddress[underwriter] = true;
    }

    function unregisterUnderwriter(address underwriter) external onlyAdmin {
        if (underwriter == address(0)) revert ZeroAddress();
        delete registeredUnderwriterByAddress[underwriter];
    }

    function registeredUnderwriters(address underwriter) external view returns (bool) {
        return registeredUnderwriterByAddress[underwriter];
    }

    function getCommit(uint256 jobId) external view returns (UnderwritingTypes.UnderwriteCommit memory) {
        return commits[jobId];
    }

    function jobUnderwriter(uint256 jobId) external view returns (address) {
        return _requireCommit(jobId).underwriter;
    }

    function jobSidecarState(uint256 jobId) external view returns (UnderwritingTypes.SidecarState) {
        return sidecarStateByJobId[jobId];
    }

    function _preSetBudget(
        uint256 jobId,
        address,
        address token,
        uint256 amount,
        bytes memory optParams
    ) internal {
        if (evaluator == address(0)) revert EvaluatorNotSet();

        AgenticCommerce.Job memory job = acp.getJob(jobId);
        UnderwritingTypes.UnderwriteCommit memory commit = abi.decode(optParams, (UnderwritingTypes.UnderwriteCommit));
        bytes32 newCommitHash = keccak256(abi.encode(commit));

        if (job.provider == address(0)) revert ProviderRequired();
        if (job.evaluator != evaluator) revert EvaluatorMismatch();

        if (commitHashByJobId[jobId] != bytes32(0)) {
            if (commitHashByJobId[jobId] != newCommitHash) revert CommitLocked();
            if (committedPaymentTokenByJobId[jobId] != token) revert CommitLocked();
            if (committedBudgetByJobId[jobId] != amount) revert CommitLocked();
            return;
        }

        if (commit.validUntil <= block.timestamp) revert CommitExpired();
        if (!registeredUnderwriterByAddress[commit.underwriter]) revert UnderwriterNotRegistered();

        commitHashByJobId[jobId] = newCommitHash;
        committedPaymentTokenByJobId[jobId] = token;
        committedBudgetByJobId[jobId] = amount;
        commits[jobId] = commit;
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.Committed;
    }

    function _postSetBudget(uint256, address, address, uint256, bytes memory) internal pure {}

    function _preFund(uint256 jobId, address, bytes memory) internal view {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Committed) revert InvalidState();
    }

    function _postFund(uint256 jobId, address, bytes memory) internal {
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Committed) revert InvalidState();
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.Protected;
    }

    function _preSubmit(uint256 jobId, address, bytes32, bytes memory) internal view {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Protected) revert InvalidState();
    }

    function _postSubmit(
        uint256 jobId,
        address,
        bytes32 deliverable,
        bytes memory optParams
    ) internal {
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.Protected) revert InvalidState();

        UnderwritingTypes.SubmitEvidence memory evidence = abi.decode(optParams, (UnderwritingTypes.SubmitEvidence));
        UnderwritingTypes.UnderwriteCommit memory commit = _requireCommit(jobId);

        if (deliverable != evidence.bundleHash) revert EvidenceMismatch();
        if (evidence.policyHash != commit.policyHash) revert EvidenceMismatch();
        if (evidence.quoteIdHash != commit.quoteIdHash) revert EvidenceMismatch();
        if (evidence.termsHash != commit.termsHash) revert EvidenceMismatch();

        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.EvidenceSubmitted;
    }

    function _preComplete(uint256 jobId, address, bytes32, bytes memory) internal view {
        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.EvidenceSubmitted) revert InvalidState();
    }

    function _preReject(uint256 jobId, address, bytes32, bytes memory) internal view {
        AgenticCommerce.Job memory job = acp.getJob(jobId);
        if (job.status == AgenticCommerce.JobStatus.Open) return;

        _requireCommit(jobId);
        if (sidecarStateByJobId[jobId] != UnderwritingTypes.SidecarState.EvidenceSubmitted) revert InvalidState();
    }

    function _postComplete(uint256 jobId, address, bytes32, bytes memory) internal {
        _requireCommit(jobId);
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.SuccessPendingConfirmation;
    }

    function _postReject(uint256 jobId, address, bytes32, bytes memory) internal {
        if (commitHashByJobId[jobId] == bytes32(0)) return;
        sidecarStateByJobId[jobId] = UnderwritingTypes.SidecarState.RejectSettled;
    }

    function _requireCommit(uint256 jobId) internal view returns (UnderwritingTypes.UnderwriteCommit memory) {
        if (commitHashByJobId[jobId] == bytes32(0)) revert CommitNotFound();
        return commits[jobId];
    }
}
