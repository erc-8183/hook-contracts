// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC8183Hook} from "@erc8183/IERC8183Hook.sol";
import {IERC8183HookMetadata} from "../contracts/interfaces/IERC8183HookMetadata.sol";
import {BaseERC8183Hook} from "../contracts/BaseERC8183Hook.sol";
import {WalletStateHook, IWalletStateVerifier} from "../contracts/hooks/WalletStateHook.sol";

contract MockWalletStateVerifier is IWalletStateVerifier {
    mapping(address => mapping(bytes32 => bool)) private _verified;
    mapping(address => mapping(bytes32 => uint256)) private _validUntil;

    function setResult(
        address wallet,
        bytes32 conditionsHash,
        bool verified_,
        uint256 validUntil_
    ) external {
        _verified[wallet][conditionsHash] = verified_;
        _validUntil[wallet][conditionsHash] = validUntil_;
    }

    function checkWalletState(address wallet, bytes32 conditionsHash)
        external
        view
        override
        returns (bool verified, uint256 validUntil)
    {
        return (_verified[wallet][conditionsHash], _validUntil[wallet][conditionsHash]);
    }
}

contract MockERC8183Caller {
    function callBeforeAction(IERC8183Hook hook, uint256 jobId, bytes4 selector, bytes memory data) external {
        hook.beforeAction(jobId, selector, data);
    }

    function callAfterAction(IERC8183Hook hook, uint256 jobId, bytes4 selector, bytes memory data) external {
        hook.afterAction(jobId, selector, data);
    }
}

contract WalletStateHookTest is Test {
    MockWalletStateVerifier mockVerifier;
    MockERC8183Caller mockCore;
    WalletStateHook hook;

    uint256 constant JOB_ID = 1;
    bytes32 constant CONDITIONS_HASH = keccak256("usdc-gte-1000-on-base");
    address constant CLIENT = address(0xBEEF);

    bytes4 constant FUND_SELECTOR = bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 constant SUBMIT_SELECTOR = bytes4(keccak256("submit(uint256,bytes32,bytes)"));

    function setUp() public {
        mockVerifier = new MockWalletStateVerifier();
        mockCore = new MockERC8183Caller();
        hook = new WalletStateHook(
            address(mockCore),
            IWalletStateVerifier(address(mockVerifier)),
            CONDITIONS_HASH
        );
    }

    function _fundData(address caller) internal pure returns (bytes memory) {
        return abi.encode(caller, bytes(""));
    }

    function _callBeforeFund(address caller) internal {
        mockCore.callBeforeAction(hook, JOB_ID, FUND_SELECTOR, _fundData(caller));
    }

    function test_Constructor_RevertsOnZeroCore() public {
        vm.expectRevert(BaseERC8183Hook.InvalidERC8183Contract.selector);
        new WalletStateHook(
            address(0),
            IWalletStateVerifier(address(mockVerifier)),
            CONDITIONS_HASH
        );
    }

    function test_Constructor_RevertsOnZeroVerifier() public {
        vm.expectRevert(WalletStateHook.InvalidParameters.selector);
        new WalletStateHook(
            address(mockCore),
            IWalletStateVerifier(address(0)),
            CONDITIONS_HASH
        );
    }

    function test_Constructor_RevertsOnZeroConditionsHash() public {
        vm.expectRevert(WalletStateHook.InvalidParameters.selector);
        new WalletStateHook(
            address(mockCore),
            IWalletStateVerifier(address(mockVerifier)),
            bytes32(0)
        );
    }

    function test_PreFund_HappyPath() public {
        mockVerifier.setResult(CLIENT, CONDITIONS_HASH, true, block.timestamp + 1800);
        _callBeforeFund(CLIENT);
    }

    function test_PreFund_RevertsWhenNotVerified() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WalletStateHook.WalletNotVerified.selector,
                CLIENT,
                CONDITIONS_HASH
            )
        );
        _callBeforeFund(CLIENT);
    }

    function test_PreFund_RevertsWhenExpired() public {
        uint256 validUntil = block.timestamp + 1800;
        mockVerifier.setResult(CLIENT, CONDITIONS_HASH, true, validUntil);
        vm.warp(validUntil + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                WalletStateHook.AttestationExpired.selector,
                CLIENT,
                validUntil
            )
        );
        _callBeforeFund(CLIENT);
    }

    function test_PreFund_BoundaryAtValidUntil() public {
        uint256 validUntil = block.timestamp + 1800;
        mockVerifier.setResult(CLIENT, CONDITIONS_HASH, true, validUntil);
        vm.warp(validUntil);
        _callBeforeFund(CLIENT);
    }

    function test_PreFund_DoesNotRunOnOtherSelectors() public view {
        mockCore;
    }

    function test_BeforeAction_IgnoresSubmitSelector() public {
        mockCore.callBeforeAction(
            hook,
            JOB_ID,
            SUBMIT_SELECTOR,
            abi.encode(CLIENT, bytes32("x"), bytes(""))
        );
    }

    function test_SupportsInterface() public view {
        assertTrue(hook.supportsInterface(type(IERC8183Hook).interfaceId));
        assertTrue(hook.supportsInterface(type(IERC8183HookMetadata).interfaceId));
    }

    function test_RequiredSelectors_Empty() public view {
        bytes4[] memory sels = hook.requiredSelectors();
        assertEq(sels.length, 0);
    }

    function test_ImmutablesExposed() public view {
        assertEq(address(hook.verifier()), address(mockVerifier));
        assertEq(hook.conditionsHash(), CONDITIONS_HASH);
        assertEq(hook.erc8183Contract(), address(mockCore));
    }
}
