// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/AgenticCommerceHooked.sol";
import "../contracts/erc8001/ERC8001.sol";
import "../contracts/erc8001/interfaces/IERC8001.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract DirectTest is Test {
    AgenticCommerceHooked public acp;
    ERC8001 public coordination;
    MockERC20 public token;

    address public client;
    address public provider;
    address public evaluator;
    address public arbiter;
    address public treasury;
    uint256 public clientKey;

    bytes32 public domainSeparator;

    bytes32 public constant AGENT_INTENT_TYPEHASH = keccak256(
        "AgentIntent(bytes32 payloadHash,uint64 expiry,uint64 nonce,address agentId,bytes32 coordinationType,uint256 coordinationValue,address[] participants)"
    );

    function setUp() public {
        token = new MockERC20("Test Token", "TEST");
        treasury = makeAddr("treasury");
        acp = new AgenticCommerceHooked(address(token), treasury);
        coordination = new ERC8001();

        (client, clientKey) = makeAddrAndKey("client");
        (provider,) = makeAddrAndKey("provider");
        (evaluator,) = makeAddrAndKey("evaluator");
        (arbiter,) = makeAddrAndKey("arbiter");

        vm.deal(client, 100 ether);
        vm.deal(provider, 100 ether);

        token.mint(client, 100000 * 10 ** 18);
        token.mint(provider, 100000 * 10 ** 18);

        vm.prank(client);
        token.approve(address(acp), type(uint256).max);
        vm.prank(provider);
        token.approve(address(acp), type(uint256).max);

        domainSeparator = coordination.DOMAIN_SEPARATOR();
    }

    function _createParticipants() internal view returns (address[] memory) {
        address[] memory participants = new address[](4);
        address[4] memory addrs = [client, provider, evaluator, arbiter];

        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = i + 1; j < 4; j++) {
                if (uint160(addrs[j]) < uint160(addrs[i])) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                }
            }
        }

        for (uint256 i = 0; i < 4; i++) {
            participants[i] = addrs[i];
        }

        return participants;
    }

    function test_DirectPropose() public {
        // Create payload
        bytes32 coordinationType = keccak256("COMPLETE_JOB");
        IERC8001.CoordinationPayload memory payload = IERC8001.CoordinationPayload({
            version: keccak256("1"),
            coordinationType: coordinationType,
            coordinationData: "",
            conditionsHash: bytes32(0),
            timestamp: block.timestamp,
            metadata: ""
        });
        bytes32 payloadHash = keccak256(abi.encode(payload));

        address[] memory participants = _createParticipants();

        IERC8001.AgentIntent memory intent = IERC8001.AgentIntent({
            payloadHash: payloadHash,
            expiry: uint64(block.timestamp + 1 hours),
            nonce: 1,
            agentId: client,
            coordinationType: coordinationType,
            coordinationValue: 0,
            participants: participants
        });

        // Sign intent
        bytes32 participantsHash = keccak256(abi.encodePacked(intent.participants));
        bytes32 structHash = keccak256(
            abi.encode(
                AGENT_INTENT_TYPEHASH,
                intent.payloadHash,
                intent.expiry,
                intent.nonce,
                intent.agentId,
                intent.coordinationType,
                intent.coordinationValue,
                participantsHash
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(clientKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Call ERC-8001 directly
        vm.prank(client);
        bytes32 intentHash = coordination.proposeCoordination(intent, signature, payload);

        console.log("Success! Intent hash:");
        console.logBytes32(intentHash);
    }
}
