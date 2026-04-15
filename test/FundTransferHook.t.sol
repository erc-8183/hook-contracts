// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@acp/AgenticCommerce.sol";
import "../contracts/hooks/FundTransferHook.sol";

contract MockToken is ERC20 {
    constructor() ERC20("Mock USDC", "USDC") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract FundTransferHookTest is Test {
    AgenticCommerce public acp;
    FundTransferHook public hook;
    MockToken public token;

    address public admin = makeAddr("admin");
    address public client = makeAddr("client");
    address public provider = makeAddr("provider");
    address public evaluator = makeAddr("evaluator");
    address public buyer = makeAddr("buyer");
    address public treasury = makeAddr("treasury");

    uint256 constant SERVICE_FEE = 10e18;
    uint256 constant TRANSFER_AMOUNT = 1000e18;

    function setUp() public {
        vm.startPrank(admin);

        token = new MockToken();

        AgenticCommerce impl = new AgenticCommerce();
        bytes memory initData = abi.encodeCall(AgenticCommerce.initialize, (treasury));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        acp = AgenticCommerce(address(proxy));

        hook = new FundTransferHook(address(token), address(acp));
        acp.setHookWhitelist(address(hook), true);

        vm.stopPrank();

        token.mint(client, SERVICE_FEE + TRANSFER_AMOUNT);
        token.mint(provider, TRANSFER_AMOUNT); // provider needs output tokens to deposit at submit
    }

    // -------------------------------------------------------------------------
    // Happy path: full job lifecycle
    // -------------------------------------------------------------------------

    function test_happyPath() public {
        // Step 1: client creates job
        vm.prank(client);
        uint256 jobId = acp.createJob(
            provider,
            evaluator,
            block.timestamp + 1 days,
            "Swap 1000 USDC to DAI",
            address(hook),
            0
        );

        // Step 2: client sets budget + transfer commitment
        // SERVICE_FEE goes to provider as payment for the job
        // TRANSFER_AMOUNT is the capital being swapped, output goes to buyer
        vm.prank(client);
        acp.setBudget(jobId, address(token), SERVICE_FEE, abi.encode(buyer, TRANSFER_AMOUNT));

        (address storedBuyer, uint256 storedAmount,) = hook.getCommitment(jobId);
        assertEq(storedBuyer, buyer);
        assertEq(storedAmount, TRANSFER_AMOUNT);

        // Step 3: client funds — approves core for service fee, hook for capital
        vm.startPrank(client);
        token.approve(address(acp), SERVICE_FEE);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.fund(jobId, SERVICE_FEE, "");
        vm.stopPrank();

        // service fee locked in core, capital forwarded directly to provider
        assertEq(token.balanceOf(address(acp)), SERVICE_FEE);
        assertEq(token.balanceOf(provider), TRANSFER_AMOUNT * 2); // original + received capital
        assertEq(token.balanceOf(client), 0);

        // Step 4: provider does work off-chain (simulated), then deposits output tokens
        vm.startPrank(provider);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.submit(jobId, keccak256("deliverable"), "");
        vm.stopPrank();

        // output tokens now locked in hook escrow
        assertEq(token.balanceOf(address(hook)), TRANSFER_AMOUNT);
        assertEq(token.balanceOf(provider), TRANSFER_AMOUNT); // spent the capital they received

        // Step 5: evaluator approves, triggering settlement
        vm.prank(evaluator);
        acp.complete(jobId, keccak256("approved"), "");

        // provider receives service fee, buyer receives output tokens
        assertEq(token.balanceOf(provider), TRANSFER_AMOUNT + SERVICE_FEE);
        assertEq(token.balanceOf(buyer), TRANSFER_AMOUNT);
        assertEq(token.balanceOf(address(hook)), 0);
        assertEq(token.balanceOf(address(acp)), 0);
    }

    // -------------------------------------------------------------------------
    // Reject path: provider gets output tokens back, client gets service fee back
    // -------------------------------------------------------------------------

    function test_rejectAfterSubmit() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "swap job", address(hook), 0);

        vm.prank(client);
        acp.setBudget(jobId, address(token), SERVICE_FEE, abi.encode(buyer, TRANSFER_AMOUNT));

        vm.startPrank(client);
        token.approve(address(acp), SERVICE_FEE);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.fund(jobId, SERVICE_FEE, "");
        vm.stopPrank();

        vm.startPrank(provider);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.submit(jobId, keccak256("deliverable"), "");
        vm.stopPrank();

        vm.prank(evaluator);
        acp.reject(jobId, keccak256("bad work"), "");

        // provider gets their deposited output tokens back
        assertEq(token.balanceOf(provider), TRANSFER_AMOUNT * 2); // original + got back what they deposited
        // client gets service fee refunded
        assertEq(token.balanceOf(client), SERVICE_FEE);
        assertEq(token.balanceOf(address(hook)), 0);
        assertEq(token.balanceOf(buyer), 0);
    }

    // -------------------------------------------------------------------------
    // Error cases
    // -------------------------------------------------------------------------

    function test_submitWithoutApproval_reverts() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "swap job", address(hook), 0);

        vm.prank(client);
        acp.setBudget(jobId, address(token), SERVICE_FEE, abi.encode(buyer, TRANSFER_AMOUNT));

        vm.startPrank(client);
        token.approve(address(acp), SERVICE_FEE);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.fund(jobId, SERVICE_FEE, "");
        vm.stopPrank();

        // provider does NOT approve hook — submit should revert
        vm.prank(provider);
        vm.expectRevert();
        acp.submit(jobId, keccak256("deliverable"), "");
    }

    function test_fundWithoutCommitment_reverts() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "swap job", address(hook), 0);

        // setBudget with empty optParams — no commitment stored
        vm.prank(client);
        acp.setBudget(jobId, address(token), SERVICE_FEE, "");

        vm.startPrank(client);
        token.approve(address(acp), SERVICE_FEE);
        token.approve(address(hook), TRANSFER_AMOUNT);
        vm.expectRevert(FundTransferHook.CommitmentNotSet.selector);
        acp.fund(jobId, SERVICE_FEE, "");
        vm.stopPrank();
    }

    function test_cannotSubmitTwice_reverts() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "swap job", address(hook), 0);

        vm.prank(client);
        acp.setBudget(jobId, address(token), SERVICE_FEE, abi.encode(buyer, TRANSFER_AMOUNT));

        vm.startPrank(client);
        token.approve(address(acp), SERVICE_FEE);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.fund(jobId, SERVICE_FEE, "");
        vm.stopPrank();

        vm.startPrank(provider);
        token.approve(address(hook), TRANSFER_AMOUNT * 2);
        acp.submit(jobId, keccak256("deliverable"), "");

        // job is now Submitted — cannot submit again
        vm.expectRevert();
        acp.submit(jobId, keccak256("deliverable2"), "");
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Expiry recovery
    // -------------------------------------------------------------------------

    function test_recoverTokensAfterExpiry() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "swap job", address(hook), 0);

        vm.prank(client);
        acp.setBudget(jobId, address(token), SERVICE_FEE, abi.encode(buyer, TRANSFER_AMOUNT));

        vm.startPrank(client);
        token.approve(address(acp), SERVICE_FEE);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.fund(jobId, SERVICE_FEE, "");
        vm.stopPrank();

        vm.startPrank(provider);
        token.approve(address(hook), TRANSFER_AMOUNT);
        acp.submit(jobId, keccak256("deliverable"), "");
        vm.stopPrank();

        // fast-forward past expiry
        vm.warp(block.timestamp + 2 days);

        // client claims service fee refund via core
        vm.prank(client);
        acp.claimRefund(jobId);
        assertEq(token.balanceOf(client), SERVICE_FEE);

        // provider recovers their deposited output tokens via hook
        vm.prank(provider);
        hook.recoverTokens(jobId);
        assertEq(token.balanceOf(provider), TRANSFER_AMOUNT * 2);
    }
}
