// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../BaseACPHook.sol";
import "@acp/AgenticCommerce.sol";

/**
 * @title FundTransferHook
 * @notice Example ACP hook for two-phase fund transfer jobs.
 *
 * USE CASE
 * --------
 * An agent's job is to convert / bridge / swap tokens on the client's behalf.
 * The client provides capital (e.g. USDC) to the provider, who uses it to
 * produce output tokens (e.g. DAI). The hook ensures the provider deposits the
 * output tokens back before the job can be completed, then releases them to a
 * designated buyer (usually the client).
 *
 * The service fee for the job is handled by the core ACP escrow (job.budget).
 * The capital and output token flow is handled entirely by this hook.
 *
 * FLOW (hook callbacks marked with ->)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *
 *  2. Client calls setBudget(jobId, serviceFee, optParams: abi.encode(buyer, transferAmount)):
 *     -> _preSetBudget: decode optParams, store {buyer, transferAmount} as commitment.
 *     -> core: set job.budget = serviceFee.
 *
 *  3. Client approves core contract for serviceFee AND this hook for transferAmount.
 *     Client calls fund(jobId, ""):
 *     -> _preFund: verify client has approved this hook for transferAmount.
 *     -> core: pull serviceFee from client into escrow, set Funded.
 *     -> _postFund: pull transferAmount from client, forward to provider (capital).
 *
 *  4. Provider uses the capital to produce output tokens off-chain/on-chain.
 *
 *  5. Provider approves this hook for transferAmount.
 *     Provider calls submit(jobId, deliverable, ""):
 *     -> _preSubmit: pull transferAmount from provider into hook (escrow).
 *     -> core: set Submitted.
 *
 *  6. Evaluator calls complete(jobId, reason, ""):
 *     -> core: release serviceFee to provider.
 *     -> _postComplete: release transferAmount from hook to buyer.
 *
 * RECOVERY
 * --------
 *  - reject (Funded/Submitted): _postReject returns escrowed tokens to provider.
 *  - expiry (claimRefund not hookable): provider calls recoverTokens(jobId).
 *
 * KEY PROPERTY: The provider cannot submit without depositing the output tokens,
 * and the buyer only receives tokens when the evaluator completes the job.
 */
contract FundTransferHook is BaseACPHook {
    using SafeERC20 for IERC20;

    struct TransferCommitment {
        address buyer;
        uint256 transferAmount;
        bool providerDeposited; // true once provider has deposited output tokens
    }

    IERC20 public immutable token;

    mapping(uint256 => TransferCommitment) public commitments;

    error CommitmentNotSet();
    error InsufficientAllowance();
    error ZeroAddress();
    error ZeroAmount();
    error NotDeposited();
    error AlreadyDeposited();
    error NothingToRecover();
    error JobNotExpired();

    constructor(address token_, address acpContract_) BaseACPHook(acpContract_) {
        if (token_ == address(0)) revert ZeroAddress();
        token = IERC20(token_);
    }

    /// @dev Typed accessor for the core contract
    function _core() internal view returns (AgenticCommerce) {
        return AgenticCommerce(acpContract);
    }

    // -------------------------------------------------------------------------
    // Hook callbacks (called by AgenticCommerce via beforeAction/afterAction)
    // -------------------------------------------------------------------------

    /// @dev Store transfer commitment from setBudget optParams.
    function _preSetBudget(uint256 jobId, address, address, uint256, bytes memory optParams) internal override {
        if (optParams.length == 0) return;
        (address buyer, uint256 transferAmount) = abi.decode(optParams, (address, uint256));
        if (buyer == address(0)) revert ZeroAddress();
        if (transferAmount == 0) revert ZeroAmount();
        commitments[jobId] = TransferCommitment({
            buyer: buyer,
            transferAmount: transferAmount,
            providerDeposited: false
        });
    }

    /// @dev Verify client has approved this hook for the committed transferAmount.
    function _preFund(uint256 jobId, address, bytes memory) internal override {
        TransferCommitment memory c = commitments[jobId];
        if (c.buyer == address(0)) revert CommitmentNotSet();
        AgenticCommerce.Job memory job = _core().getJob(jobId);
        uint256 allowance = token.allowance(job.client, address(this));
        if (allowance < c.transferAmount) revert InsufficientAllowance();
    }

    /// @dev Pull transferAmount from client and forward to provider (capital).
    function _postFund(uint256 jobId, address, bytes memory) internal override {
        TransferCommitment memory c = commitments[jobId];
        AgenticCommerce.Job memory job = _core().getJob(jobId);
        token.safeTransferFrom(job.client, job.provider, c.transferAmount);
    }

    /// @dev Pull transferAmount from provider into hook escrow (output tokens).
    function _preSubmit(uint256 jobId, address, bytes32, bytes memory) internal override {
        TransferCommitment storage c = commitments[jobId];
        if (c.buyer == address(0)) revert CommitmentNotSet();
        if (c.providerDeposited) revert AlreadyDeposited();
        AgenticCommerce.Job memory job = _core().getJob(jobId);
        c.providerDeposited = true;
        token.safeTransferFrom(job.provider, address(this), c.transferAmount);
    }

    /// @dev Release escrowed tokens to buyer after evaluator completes the job.
    function _postComplete(uint256 jobId, address, bytes32, bytes memory) internal override {
        TransferCommitment memory c = commitments[jobId];
        if (!c.providerDeposited) revert NotDeposited();
        delete commitments[jobId];
        token.safeTransfer(c.buyer, c.transferAmount);
    }

    /// @dev Return escrowed tokens to provider on rejection.
    function _postReject(uint256 jobId, address, bytes32, bytes memory) internal override {
        TransferCommitment memory c = commitments[jobId];
        if (!c.providerDeposited) {
            delete commitments[jobId];
            return;
        }
        AgenticCommerce.Job memory job = _core().getJob(jobId);
        delete commitments[jobId];
        token.safeTransfer(job.provider, c.transferAmount);
    }

    // -------------------------------------------------------------------------
    // Recovery for expiry (claimRefund is not hookable)
    // -------------------------------------------------------------------------

    /// @dev Provider can recover deposited tokens after the job expires.
    ///      claimRefund is deliberately not hookable, so this is a direct call.
    function recoverTokens(uint256 jobId) external {
        TransferCommitment memory c = commitments[jobId];
        if (!c.providerDeposited) revert NothingToRecover();
        AgenticCommerce.Job memory job = _core().getJob(jobId);
        if (job.status != AgenticCommerce.JobStatus.Expired) revert JobNotExpired();
        delete commitments[jobId];
        token.safeTransfer(job.provider, c.transferAmount);
    }

    // -------------------------------------------------------------------------
    // View
    // -------------------------------------------------------------------------

    function getCommitment(uint256 jobId) external view returns (address buyer, uint256 transferAmount, bool providerDeposited) {
        TransferCommitment memory c = commitments[jobId];
        return (c.buyer, c.transferAmount, c.providerDeposited);
    }
}
