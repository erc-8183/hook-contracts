// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title ITrustOracle
/// @notice Interface for agent-identity-based trust oracles.
/// @dev Lookup key is (agentId, chainId, registry) — supports multi-chain,
///      multi-registry agent identity resolution.
interface ITrustOracle {
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

/// @title TrustGateHook
/// @notice ERC-8183 hook that gates job lifecycle transitions by on-chain trust score.
///
/// USE CASE
/// --------
/// Score-based participant gating: verify the funding wallet (at fund) and
/// the providing wallet (at submit) meet a minimum reputation threshold before
/// the job can advance. The hook accepts any oracle implementing ITrustOracle;
/// the gate is keyed by (agentId, chainId, registry) so participants are
/// evaluated as registered agents rather than raw addresses.
///
/// FLOW
/// ----
/// 1. Off-chain: an oracle implementing ITrustOracle scores agents keyed by
///    (agentId, chainId, registry) and exposes meetsThreshold for on-chain
///    consumption.
/// 2. The hook owner registers wallet → agent ID mappings via setAgentId or
///    setAgentIds, binding each participating wallet to its scored identity.
/// 3. Client calls AgenticCommerce.fund(...) — the core invokes
///    beforeAction(jobId, fundSelector, data) on this hook, which routes to
///    _preFund. The hook resolves the caller's agent ID and reverts unless
///    the agent meets the configured threshold.
/// 4. Provider calls AgenticCommerce.submit(...) — same flow through
///    _preSubmit, gating the submit transition by provider trust score.
///
/// TRUST MODEL
/// -----------
/// - The hook trusts the injected ITrustOracle to return honest threshold
///   verdicts. Implementations are free to define their own scoring formula,
///   ceiling, and signal mix; the hook is indifferent to internal scoring
///   logic and only consumes meetsThreshold.
/// - Threshold is mutable by the owner within 1–100. The constructor and
///   setThreshold reject 0 (gate disabled) and values above 100 (unreachable
///   by convention).
/// - Wallet → agent ID registration is owner-managed. agentId == 0 is a valid
///   registered value because a separate registered mapping tracks existence.
/// - Job-lifecycle authorization is enforced by BaseERC8183Hook.onlyERC8183.
/// - The oracle does all scoring; the hook is a gate, not a judge.
contract TrustGateHook is BaseERC8183Hook, IERC8183HookMetadata, Ownable {

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    ITrustOracle public oracle;
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
     * @param erc8183Contract_ ERC-8183 core (AgenticCommerce)
     * @param oracle_          ITrustOracle implementation
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
        oracle = ITrustOracle(oracle_);
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
        uint8 oldThreshold = threshold;
        threshold = threshold_;
        emit ThresholdUpdated(oldThreshold, threshold_);
    }

    /// @notice Update the oracle address (must implement ITrustOracle).
    function setOracle(address oracle_) external onlyOwner {
        if (oracle_ == address(0)) revert TrustGateHook__ZeroAddress();
        if (oracle_ == address(oracle)) revert TrustGateHook__SameValue();
        address oldOracle = address(oracle);
        oracle = ITrustOracle(oracle_);
        emit OracleUpdated(oldOracle, oracle_);
    }

    /*//////////////////////////////////////////////////////////////
                    IERC8183HookMetadata
    //////////////////////////////////////////////////////////////*/

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
