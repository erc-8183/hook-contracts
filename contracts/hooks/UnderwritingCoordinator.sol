// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@acp/AgenticCommerce.sol";
import "./UnderwritingHook.sol";
import "./UnderwritingTypes.sol";

contract UnderwritingCoordinator {
    error ZeroAddress();
    error WrongHook();
    error WrongJobStatus();
    error InvalidState();

    AgenticCommerce public immutable acp;
    UnderwritingHook public immutable hook;

    event FundingOrchestrated(uint256 indexed jobId, uint256 indexed settlementJobId);

    constructor(address acpContract_, address hook_) {
        if (acpContract_ == address(0) || hook_ == address(0)) revert ZeroAddress();
        acp = AgenticCommerce(acpContract_);
        hook = UnderwritingHook(hook_);
    }

    function orchestrateFunding(uint256 jobId) external {
        AgenticCommerce.Job memory job = acp.getJob(jobId);
        if (job.hook != address(hook)) revert WrongHook();
        if (job.status != AgenticCommerce.JobStatus.Funded) revert WrongJobStatus();
        if (hook.jobSidecarState(jobId) != UnderwritingTypes.SidecarState.FeeEscrowed) revert InvalidState();

        hook.markProtected(jobId);
        emit FundingOrchestrated(jobId, hook.jobSettlementJobId(jobId));
    }
}
