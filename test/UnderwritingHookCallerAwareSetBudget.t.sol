// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@acp/AgenticCommerce.sol";
import "../contracts/hooks/UnderwritingHook.sol";
import "../contracts/hooks/UnderwritingTypes.sol";
import "../contracts/hooks/UnderwritingWorkflowCore.sol";

contract MockAcpCaller {
    mapping(uint256 => AgenticCommerce.Job) internal jobs;

    function setJob(AgenticCommerce.Job memory job) external {
        jobs[job.id] = job;
    }

    function getJob(uint256 jobId) external view returns (AgenticCommerce.Job memory) {
        return jobs[jobId];
    }

    function callBeforeAction(
        UnderwritingHook hook,
        uint256 jobId,
        bytes4 selector,
        bytes memory data
    ) external {
        hook.beforeAction(jobId, selector, data);
    }
}

contract MockWiringTarget {
    address public immutable acp;
    address public immutable hook;

    constructor(address acp_, address hook_) {
        acp = acp_;
        hook = hook_;
    }
}

contract UnderwritingHookCallerAwareSetBudgetTest is Test {
    uint256 internal constant JOB_ID = 1;
    uint256 internal constant AMOUNT = 1 ether;

    address internal constant CLIENT = address(0xCA11);
    address internal constant PROVIDER = address(0xBEEF);
    address internal constant PAYMENT_TOKEN = address(0xC0FFEE);
    address internal constant OTHER_PAYMENT_TOKEN = address(0xABCD);
    address internal constant UNDERWRITER = address(0xFEE1);

    MockAcpCaller internal acp;
    UnderwritingHook internal hook;
    MockWiringTarget internal evaluator;
    MockWiringTarget internal coordinator;

    function setUp() public {
        acp = new MockAcpCaller();
        hook = new UnderwritingHook(address(acp), address(this));
        evaluator = new MockWiringTarget(address(acp), address(hook));
        coordinator = new MockWiringTarget(address(acp), address(hook));

        hook.setWiring(address(evaluator), address(coordinator));
        hook.registerUnderwriter(UNDERWRITER);

        acp.setJob(
            AgenticCommerce.Job({
                id: JOB_ID,
                client: CLIENT,
                provider: PROVIDER,
                evaluator: address(evaluator),
                description: "job",
                budget: 0,
                expiredAt: block.timestamp + 1 days,
                status: AgenticCommerce.JobStatus.Open,
                hook: address(hook),
                paymentToken: PAYMENT_TOKEN,
                providerAgentId: 0
            })
        );
    }

    function test_beforeAction_setBudget_acceptsAcpTokenAwarePayload() public {
        UnderwritingTypes.UnderwriteCommit memory commit = UnderwritingTypes.UnderwriteCommit({
            parentJobId: 0,
            underwriter: UNDERWRITER,
            validUntil: uint64(block.timestamp + 1 days),
            policyHash: keccak256("policy"),
            quoteIdHash: keccak256("quote"),
            termsHash: keccak256("terms"),
            allowCloseJob: false
        });

        acp.callBeforeAction(
            hook,
            JOB_ID,
            bytes4(keccak256("setBudget(uint256,address,uint256,bytes)")),
            abi.encode(CLIENT, PAYMENT_TOKEN, AMOUNT, abi.encode(commit))
        );

        assertEq(
            uint256(hook.jobSidecarState(JOB_ID)),
            uint256(UnderwritingTypes.SidecarState.Committed)
        );
        assertEq(hook.jobUnderwriter(JOB_ID), UNDERWRITER);

        UnderwritingTypes.UnderwriteCommit memory storedCommit = hook.getCommit(JOB_ID);
        assertEq(storedCommit.termsHash, commit.termsHash);
    }

    function test_beforeAction_setBudget_rejectsReplayWithDifferentPaymentToken() public {
        UnderwritingTypes.UnderwriteCommit memory commit = UnderwritingTypes.UnderwriteCommit({
            parentJobId: 0,
            underwriter: UNDERWRITER,
            validUntil: uint64(block.timestamp + 1 days),
            policyHash: keccak256("policy"),
            quoteIdHash: keccak256("quote"),
            termsHash: keccak256("terms"),
            allowCloseJob: false
        });

        bytes4 selector = bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
        bytes memory optParams = abi.encode(commit);

        acp.callBeforeAction(
            hook,
            JOB_ID,
            selector,
            abi.encode(CLIENT, PAYMENT_TOKEN, AMOUNT, optParams)
        );

        vm.expectRevert(UnderwritingWorkflowCore.CommitLocked.selector);
        acp.callBeforeAction(
            hook,
            JOB_ID,
            selector,
            abi.encode(CLIENT, OTHER_PAYMENT_TOKEN, AMOUNT, optParams)
        );
    }
}
