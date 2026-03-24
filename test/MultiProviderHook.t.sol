// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/AgenticCommerceHooked.sol";
import "../contracts/hooks/MultiProviderHook.sol";
import "../contracts/erc8004/ERC8004ProviderRegistry.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MultiProviderHookTest
 * @notice Comprehensive tests for MultiProviderHook.
 * @dev Tests provider management, payment distribution, and security.
 */
contract MultiProviderHookTest is Test {
    AgenticCommerceHooked public acp;
    ERC8004ProviderRegistry public registry;
    MultiProviderHook public hook;
    MockToken public token;

    address public client = makeAddr("client");
    address public provider1 = makeAddr("provider1");
    address public provider2 = makeAddr("provider2");
    address public provider3 = makeAddr("provider3");
    address public evaluator = makeAddr("evaluator");
    address public treasury = makeAddr("treasury");

    uint256 public constant INITIAL_BALANCE = 1_000_000e18;
    uint256 public constant JOB_BUDGET = 100_000e18;
    uint256 public constant PLATFORM_FEE_BP = 100; // 1%

    function setUp() public {
        // Deploy token
        token = new MockToken("Mock Token", "MOCK");

        // Deploy ACP
        acp = new AgenticCommerceHooked(address(token), treasury);

        // Deploy registry
        registry = new ERC8004ProviderRegistry(address(token));

        // Deploy hook
        hook = new MultiProviderHook(address(acp), address(registry), address(token));

        // Fund accounts
        token.transfer(client, INITIAL_BALANCE);
        token.transfer(provider1, INITIAL_BALANCE);
        token.transfer(provider2, INITIAL_BALANCE);
        token.transfer(provider3, INITIAL_BALANCE);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provider Management Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_AddProvider_Success() public {
        uint256 jobId = _createJob();

        vm.prank(client);
        hook.addProvider(jobId, provider1);

        address[] memory providers = hook.getJobProviders(jobId);
        assertEq(providers.length, 1);
        assertEq(providers[0], provider1);
    }

    function test_AddProvider_Revert_NotClient() public {
        uint256 jobId = _createJob();

        vm.prank(provider1);
        vm.expectRevert(MultiProviderHook.MultiProviderHook_OnlyClient.selector);
        hook.addProvider(jobId, provider2);
    }

    function test_AddProvider_Revert_AfterFunding() public {
        uint256 jobId = _createJob();

        // Add one provider first
        vm.prank(client);
        hook.addProvider(jobId, provider1);

        // Fund job
        _fundJob(jobId);

        // Try to add provider after funding
        vm.prank(client);
        vm.expectRevert(MultiProviderHook.MultiProviderHook_OnlyBeforeFunding.selector);
        hook.addProvider(jobId, provider2);
    }

    function test_AddProvider_Revert_ZeroAddress() public {
        uint256 jobId = _createJob();

        vm.prank(client);
        vm.expectRevert(MultiProviderHook.MultiProviderHook_ZeroAddress.selector);
        hook.addProvider(jobId, address(0));
    }

    function test_RemoveProvider_Success() public {
        uint256 jobId = _createJob();

        // Add providers
        vm.startPrank(client);
        hook.addProvider(jobId, provider1);
        hook.addProvider(jobId, provider2);
        hook.addProvider(jobId, provider3);
        vm.stopPrank();

        // Verify all added
        address[] memory providers = hook.getJobProviders(jobId);
        assertEq(providers.length, 3);

        // Remove one
        vm.prank(client);
        hook.removeProvider(jobId, provider2);

        // Verify removed
        providers = hook.getJobProviders(jobId);
        assertEq(providers.length, 2);
        assertTrue(_containsProvider(providers, provider1));
        assertTrue(_containsProvider(providers, provider3));
        assertFalse(_containsProvider(providers, provider2));
    }

    function test_RemoveProvider_Revert_LastProvider() public {
        uint256 jobId = _createJob();

        // Add only one provider
        vm.prank(client);
        hook.addProvider(jobId, provider1);

        // Try to remove last provider
        vm.prank(client);
        // Should revert from registry
        vm.expectRevert();
        hook.removeProvider(jobId, provider1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Funding Validation Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Fund_Success_WithProviders() public {
        uint256 jobId = _createJob();

        // Add providers
        vm.startPrank(client);
        hook.addProvider(jobId, provider1);
        hook.addProvider(jobId, provider2);
        vm.stopPrank();

        // Fund should succeed
        _fundJob(jobId);

        // Verify funded
        assertTrue(hook.jobFunded(jobId));
        assertEq(hook.jobBudget(jobId), JOB_BUDGET);
    }

    function test_Fund_Revert_EmptyProviderSet() public {
        uint256 jobId = _createJob();

        // Set budget first (required before fund)
        vm.prank(client);
        acp.setBudget(jobId, JOB_BUDGET, "");

        // Try to fund without providers
        vm.startPrank(client);
        token.approve(address(acp), JOB_BUDGET);

        // Must pass expectedBudget in optParams for hook validation to run
        vm.expectRevert(MultiProviderHook.MultiProviderHook_InvalidProviderSet.selector);
        acp.fund(jobId, JOB_BUDGET, abi.encode(JOB_BUDGET, ""));
        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Payment Distribution Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_PaymentDistribution_TwoProviders() public {
        uint256 jobId = _createMultiProviderJob();

        // Complete job
        vm.prank(evaluator);
        acp.complete(jobId, bytes32(0), "");

        // Check payments distributed
        uint256 balance1 = token.balanceOf(provider1);
        uint256 balance2 = token.balanceOf(provider2);

        // Each should get 50% of budget (minus platform fee)
        uint256 expectedPerProvider = JOB_BUDGET / 2;

        // Allow for small rounding errors
        assertApproxEqAbs(balance1 - INITIAL_BALANCE, expectedPerProvider, 1e18);
        assertApproxEqAbs(balance2 - INITIAL_BALANCE, expectedPerProvider, 1e18);
    }

    function test_PaymentDistribution_ThreeProviders() public {
        uint256 jobId = _createJob();

        // Add 3 providers
        vm.startPrank(client);
        hook.addProvider(jobId, provider1);
        hook.addProvider(jobId, provider2);
        hook.addProvider(jobId, provider3);
        vm.stopPrank();

        // Fund the job
        _fundJob(jobId);

        // Submit work (required before complete)
        vm.prank(address(hook));
        acp.submit(jobId, bytes32(0), "");

        // Complete job
        vm.prank(evaluator);
        acp.complete(jobId, bytes32(0), "");

        // Each should get proportional share via basis points (10000 total)
        // Provider 1 gets 3334 bp, providers 2 & 3 get 3333 bp each
        uint256 balance1 = token.balanceOf(provider1);
        uint256 balance2 = token.balanceOf(provider2);
        uint256 balance3 = token.balanceOf(provider3);

        // Calculate expected amounts: balance * share / 10000
        // Provider 1: 3334/10000 of budget
        // Provider 2: 3333/10000 of budget
        // Provider 3: 3333/10000 of budget
        uint256 expected1 = (JOB_BUDGET * 3334) / 10000;
        uint256 expected2 = (JOB_BUDGET * 3333) / 10000;
        uint256 expected3 = (JOB_BUDGET * 3333) / 10000;

        assertApproxEqAbs(balance1 - INITIAL_BALANCE, expected1, 1e18);
        assertApproxEqAbs(balance2 - INITIAL_BALANCE, expected2, 1e18);
        assertApproxEqAbs(balance3 - INITIAL_BALANCE, expected3, 1e18);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Security Tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_Security_ProviderSetValidation() public {
        uint256 jobId = _createJob();

        // Initially not valid
        assertFalse(hook.isValidProviderSet(jobId));

        // Add one provider
        vm.prank(client);
        hook.addProvider(jobId, provider1);

        // Now valid
        assertTrue(hook.isValidProviderSet(jobId));
    }

    function test_Security_OnlyClientModifications() public {
        uint256 jobId = _createJob();

        // Provider tries to add themselves
        vm.prank(provider1);
        vm.expectRevert(MultiProviderHook.MultiProviderHook_OnlyClient.selector);
        hook.addProvider(jobId, provider1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Integration Test with ERC-8001 Coordination
    // ═══════════════════════════════════════════════════════════════════════

    function test_Integration_MultiProviderAndCoordination() public {
        // This test shows how MultiProviderHook can work alongside ERC-8001 coordination
        // (Full integration would require deploying both hooks and testing together)

        // Create job with multi-provider
        uint256 jobId = _createMultiProviderJob();

        // Verify providers are set
        address[] memory providers = hook.getJobProviders(jobId);
        assertEq(providers.length, 2);

        // Verify can complete normally
        _completeJob(jobId);

        // Verify payments distributed
        assertGt(token.balanceOf(provider1), INITIAL_BALANCE);
        assertGt(token.balanceOf(provider2), INITIAL_BALANCE);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    function _createJob() internal returns (uint256 jobId) {
        vm.prank(client);
        // Pass hook as both provider AND hook parameter so callbacks fire
        return acp.createJob(address(hook), evaluator, block.timestamp + 1 days, "Test Job", address(hook));
    }

    function _createMultiProviderJob() internal returns (uint256 jobId) {
        jobId = _createJob();

        // Add two providers
        vm.startPrank(client);
        hook.addProvider(jobId, provider1);
        hook.addProvider(jobId, provider2);
        vm.stopPrank();

        // Fund job
        _fundJob(jobId);

        // Submit work
        vm.prank(address(hook)); // Hook acts as provider for this test
        acp.submit(jobId, bytes32(0), "");

        return jobId;
    }

    function _fundJob(uint256 jobId) internal {
        vm.startPrank(client);
        // Set budget first
        acp.setBudget(jobId, JOB_BUDGET, "");
        token.approve(address(acp), JOB_BUDGET);
        // Pass budget in optParams so hook can track it
        acp.fund(jobId, JOB_BUDGET, abi.encode(JOB_BUDGET, ""));
        vm.stopPrank();
    }

    function _completeJob(uint256 jobId) internal {
        vm.prank(evaluator);
        acp.complete(jobId, bytes32(0), "");
    }

    function _containsProvider(address[] memory providers, address prov) internal pure returns (bool) {
        for (uint256 i = 0; i < providers.length; i++) {
            if (providers[i] == prov) return true;
        }
        return false;
    }
}

/**
 * @title MockToken
 * @dev Simple ERC-20 mock for testing
 */
contract MockToken is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1_000_000_000e18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
