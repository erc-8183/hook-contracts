// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title IRNWYTrustOracle
/// @notice Interface for agent-identity-based trust oracles.
/// @dev Lookup key is (agentId, chainId, registry) — supports multi-chain,
///      multi-registry agent identity resolution.
///      Reference implementation deployed on Base mainnet:
///      https://basescan.org/address/0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4
interface IRNWYTrustOracle {
    /// @notice Returns the full trust record for an agent.
    /// @param agentId  Agent ID within the registry
    /// @param chainId  Chain where the agent is registered (e.g., 8453 for Base)
    /// @param registry Registry identifier (e.g., "erc8004", "olas")
    function getScore(
        uint256 agentId,
        uint256 chainId,
        string calldata registry
    ) external view returns (
        uint8  score,
        uint8  tier,
        uint8  sybilSeverity,
        uint40 updatedAt
    );

    /// @notice Returns true if the agent has a recorded trust score.
    function hasScore(
        uint256 agentId,
        uint256 chainId,
        string calldata registry
    ) external view returns (bool);

    /// @notice Returns true if the agent's trust score meets or exceeds the threshold.
    function meetsThreshold(
        uint256 agentId,
        uint256 chainId,
        string calldata registry,
        uint8 threshold
    ) external view returns (bool);

    /// @notice Returns the total number of agents with recorded scores.
    function agentCount() external view returns (uint256);
}

/**
 * @title TrustGateHook
 * @notice ERC-8183 hook that gates job lifecycle transitions by on-chain trust score.
 *
 * @dev Inherits BaseERC8183Hook for correct selector routing, data decoding,
 *      and onlyERC8183 caller authentication. Reads from any oracle implementing
 *      IRNWYTrustOracle — an agent-identity-based trust interface using
 *      (agentId, chainId, registry) lookups across multiple chains and registries.
 *
 *      Reference implementation: RNWY Trust Oracle on Base mainnet.
 *      138,000+ agent scores covering ERC-8004, Olas, and Virtuals across 11 chains.
 *      Contract: 0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4
 *
 *
 *      TRUST BOUNDARY
 *      --------------
 *      This hook gates on AGENT-QUALITY signals — behavioral trust, commerce
 *      history, sybil detection, and funding-source tracing for registered
 *      agents keyed by (agentId, chainId, registry). It answers: is this
 *      registered agent a quality counterparty?
 *
 *      This is distinct from (and complementary to) WALLET-RISK gating, which
 *      evaluates arbitrary EOAs by address alone and answers: is this wallet
 *      risky? A relying party can run both hooks independently — one for
 *      participant-level quality checks, one for transaction-level risk.
 *
 *
 *      HOOK POINTS
 *      -----------
 *      - _preFund      : check client trust, revert if below threshold
 *      - _preSubmit    : check provider trust, revert if below threshold
 *      - _postComplete : emit outcome event (never reverts)
 *      - _postReject   : emit outcome event (never reverts)
 *
 *      The hook maps wallet addresses to agent IDs via an owner-managed
 *      registry. The oracle does all scoring; the hook is a gate, not a judge.
 *
 *
 *      MULTIHOOKROUTER
 *      ---------------
 *      Implements IERC8183HookMetadata. requiredSelectors() returns an empty
 *      array; client and provider trust checks are independent gates and
 *      neither depends on the other being configured.
 */
contract TrustGateHook is BaseERC8183Hook, IERC8183HookMetadata, Ownable {

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    IRNWYTrustOracle public oracle;
    uint8 public threshold;
    uint256 public defaultChainId;
    string public defaultRegistry;

    /// @notice Wallet address → agent ID.
    mapping(address => uint256) public agentIds;

    /// @notice Tracks which wallets have been explicitly registered.
    /// @dev Separate from agentIds so that agentId == 0 is a valid registered value.
    mapping(address => bool) public registered;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event AgentIdSet(address indexed wallet, uint256 agentId);
    event ThresholdUpdated(uint8 oldThreshold, uint8 newThreshold);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event TrustGated(uint256 indexed jobId, address indexed agent, uint256 agentId, bool allowed);
    event OutcomeRecorded(uint256 indexed jobId, bool completed);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TrustGateHook__ZeroAddress();
    error TrustGateHook__NoAgentId(address agent);
    error TrustGateHook__BelowThreshold(uint256 jobId, address agent, uint256 agentId, uint8 threshold);
    error TrustGateHook__ArrayLengthMismatch();
    error TrustGateHook__SameValue();
    error TrustGateHook__InvalidThreshold(uint8 threshold);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param erc8183Contract_ ERC-8183 core (AgenticCommerce) or MultiHookRouter
     * @param oracle_          IRNWYTrustOracle implementation
     * @param threshold_       Minimum trust score (1-100) to pass the gate
     * @param chainId_         Default chain ID for oracle lookups (e.g., 8453 for Base)
     * @param registry_        Default registry for oracle lookups (e.g., "erc8004")
     */
    constructor(
        address erc8183Contract_,
        address oracle_,
        uint8 threshold_,
        uint256 chainId_,
        string memory registry_
    ) BaseERC8183Hook(erc8183Contract_) Ownable(msg.sender) {
        if (oracle_ == address(0)) revert TrustGateHook__ZeroAddress();
        if (threshold_ == 0 || threshold_ > 100) revert TrustGateHook__InvalidThreshold(threshold_);
        oracle = IRNWYTrustOracle(oracle_);
        threshold = threshold_;
        defaultChainId = chainId_;
        defaultRegistry = registry_;
    }

    /*//////////////////////////////////////////////////////////////
                    BaseERC8183Hook overrides
    //////////////////////////////////////////////////////////////*/

    /// @dev Gates the fund transition by client trust score.
    function _preFund(
        uint256 jobId,
        address caller,
        bytes memory
    ) internal override {
        _checkTrust(jobId, caller);
    }

    /// @dev Gates the submit transition by provider trust score.
    function _preSubmit(
        uint256 jobId,
        address caller,
        bytes32,
        bytes memory
    ) internal override {
        _checkTrust(jobId, caller);
    }

    /// @dev Records completion outcome. Never reverts.
    function _postComplete(
        uint256 jobId,
        address,
        bytes32,
        bytes memory
    ) internal override {
        emit OutcomeRecorded(jobId, true);
    }

    /// @dev Records rejection outcome. Never reverts.
    function _postReject(
        uint256 jobId,
        address,
        bytes32,
        bytes memory
    ) internal override {
        emit OutcomeRecorded(jobId, false);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a wallet → agent ID mapping.
    function setAgentId(address wallet, uint256 agentId) external onlyOwner {
        if (agentIds[wallet] == agentId && registered[wallet]) revert TrustGateHook__SameValue();
        agentIds[wallet] = agentId;
        registered[wallet] = true;
        emit AgentIdSet(wallet, agentId);
    }

    /// @notice Batch-register wallet → agent ID mappings.
    function setAgentIds(address[] calldata wallets, uint256[] calldata ids) external onlyOwner {
        if (wallets.length != ids.length) revert TrustGateHook__ArrayLengthMismatch();
        for (uint256 i = 0; i < wallets.length; i++) {
            if (agentIds[wallets[i]] == ids[i] && registered[wallets[i]]) continue;
            agentIds[wallets[i]] = ids[i];
            registered[wallets[i]] = true;
            emit AgentIdSet(wallets[i], ids[i]);
        }
    }

    /// @notice Update the minimum trust score threshold.
    function setThreshold(uint8 threshold_) external onlyOwner {
        if (threshold_ == 0 || threshold_ > 100) revert TrustGateHook__InvalidThreshold(threshold_);
        if (threshold_ == threshold) revert TrustGateHook__SameValue();
        emit ThresholdUpdated(threshold, threshold_);
        threshold = threshold_;
    }

    /// @notice Update the oracle address (must implement IRNWYTrustOracle).
    function setOracle(address oracle_) external onlyOwner {
        if (oracle_ == address(0)) revert TrustGateHook__ZeroAddress();
        if (oracle_ == address(oracle)) revert TrustGateHook__SameValue();
        emit OracleUpdated(address(oracle), oracle_);
        oracle = IRNWYTrustOracle(oracle_);
    }

    /*//////////////////////////////////////////////////////////////
                    IERC8183HookMetadata
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the selectors this hook requires to function correctly.
    /// @dev Empty array — client trust (_preFund) and provider trust (_preSubmit)
    ///      are independent gates with no cross-selector dependency.
    function requiredSelectors() external pure returns (bytes4[] memory) {
        return new bytes4[](0);
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL
    //////////////////////////////////////////////////////////////*/

    function _checkTrust(uint256 jobId, address agent) internal {
        if (!registered[agent]) revert TrustGateHook__NoAgentId(agent);
        uint256 agentId = agentIds[agent];
        bool passes = oracle.meetsThreshold(agentId, defaultChainId, defaultRegistry, threshold);
        if (!passes) {
            revert TrustGateHook__BelowThreshold(jobId, agent, agentId, threshold);
        }
        emit TrustGated(jobId, agent, agentId, true);
    }
}
