// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../BaseACPHook.sol";

// ─────────────────────────────────────────────────────────────────────────────
// External dependency interfaces
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @notice Minimal ERC-8004 reputation registry interface.
 *         Implemented by CourtRegistry in the Jurex Network.
 *         Full source: https://github.com/med-amiine/jurex-network
 */
interface IReputationRegistry {
    /**
     * @param agentId   Agent identifier (uint256 cast of address for Jurex).
     * @param category  Signal category, e.g. "job" or "dispute".
     * @param tag       Outcome tag, e.g. "completed", "won", "lost".
     * @param value     Signed 1e18 fixed-point signal (positive = good signal).
     * @param evidence  Optional IPFS CID or empty string.
     */
    function giveFeedback(
        uint256 agentId,
        string  calldata category,
        string  calldata tag,
        int256  value,
        string  calldata evidence
    ) external;
}

/**
 * @notice Minimal interface over AgenticCommerceHooked used during appeal settlement
 *         to read job data and call back into the job contract with the court verdict.
 */
interface IACPJob {
    function getJob(uint256 jobId) external view returns (
        uint256 id,
        address client,
        address provider,
        address evaluator,
        address hook,
        string  memory description,
        uint256 budget,
        uint256 expiredAt,
        uint8   status
    );

    function complete(uint256 jobId, bytes32 reason, bytes calldata optParams) external;
    function reject  (uint256 jobId, bytes32 reason, bytes calldata optParams) external;
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * @title  AgentCourtHook
 * @author Jurex Network <https://jurex.network>
 *
 * @notice USE CASE
 *         Routes disputed ERC-8183 jobs to Agent Court — a decentralised
 *         judge-panel arbitration system — when a client rejects a provider's
 *         submission. Providers can appeal a rejection; three randomly-selected,
 *         JRX-staked judges vote on the dispute. The majority verdict is then
 *         applied back to the job contract via {settleAppeal}, and a portable
 *         ERC-8004 reputation signal is written for the provider so the outcome
 *         follows them across any ERC-8004-aware system.
 *
 * @notice FLOW
 *         1. Client calls AgenticCommerceHooked.complete()
 *            → _postComplete fires → +5 ERC-8004 signal written for provider.
 *         2. Client calls AgenticCommerceHooked.reject()
 *            → _postReject fires → appeal window opens (AppealWindowOpened).
 *            Reputation does NOT change yet; the provider has not had a chance
 *            to appeal.
 *         3. Provider calls CourtCaseFactory.fileAppeal(jobId, acpContract, hook)
 *            → a CourtCase contract is deployed and three judges are assigned.
 *         4. Owner calls hook.linkCase(jobId, caseAddress) to record the link.
 *            (linkCase is owner-only; an off-chain relay watches AppealFiled
 *            events from the factory and calls this automatically.)
 *         5. Judges vote. On a 2/3 majority the CourtCase reaches Resolved state.
 *         6. Either party calls hook.settleAppeal(jobId, providerWins):
 *            - providerWins=true  → job.complete() called + ERC-8004 +5 written.
 *            - providerWins=false → job.reject()   called + ERC-8004 −5 written.
 *
 * @notice TRUST MODEL
 *         - The hook never takes custody of job funds; all escrow stays in
 *           AgenticCommerceHooked.
 *         - settleAppeal() is permissionless — any address may call it once the
 *           CourtCase has reached Resolved state. It is idempotent after first call.
 *         - The registry (ERC-8004) is the only external write target besides the
 *           job contract itself. Registry writes cannot revert settleAppeal because
 *           the registry reverts are not caught — a misconfigured registry could
 *           block settlement. Deployers should verify registry correctness before
 *           attaching this hook.
 *         - linkCase() is owner-controlled. Until linkCase() is called, appeal
 *           status is readable via jobToCase (zero address = not yet linked).
 *         - acpContract is immutable; the hook must be redeployed to change it.
 *
 * @dev    Profile B — two-phase dispute settlement. The hook drives a second
 *         state transition on the job contract (via settleAppeal), making it
 *         more than a stateless policy layer.
 *
 *         Deployed on Arbitrum Sepolia:
 *           AgentCourtHook  0xD14a340F8C61A8F4D4269Ef7Ba8357cFD498925F
 *           CourtRegistry   0x2d02a6A204de958cFa6551710681f230043bF646
 *           AgenticCommerce 0xDd570A7d5018d81BED8C772903Cfd3b11669aA8F
 *
 *         Full source + tests: https://github.com/med-amiine/jurex-network
 */
contract AgentCourtHook is BaseACPHook, ERC165, Ownable {

    // =========================================================================
    // State
    // =========================================================================

    /// ERC-8004 reputation registry (CourtRegistry).
    IReputationRegistry public immutable registry;

    /// jobId → ACP contract address. Non-zero when the appeal window is open.
    mapping(uint256 => address) public jobContract;

    /// jobId → CourtCase address linked after the appeal is filed.
    mapping(uint256 => address) public jobToCase;

    /// jobId → true after settleAppeal() has been called.
    mapping(uint256 => bool) public settled;

    // =========================================================================
    // Events
    // =========================================================================

    /// @notice Emitted when a job is rejected and the appeal window opens.
    event AppealWindowOpened(uint256 indexed jobId, address indexed jobContract);

    /// @notice Emitted when a CourtCase is linked to a jobId.
    event CaseLinkSet(uint256 indexed jobId, address indexed caseContract);

    /// @notice Emitted when the Jurex verdict is applied back to the job.
    event AppealSettled(uint256 indexed jobId, bool providerWins);

    // =========================================================================
    // Constructor
    // =========================================================================

    /**
     * @param acp_       Address of the AgenticCommerceHooked contract.
     * @param registry_  Address of the ERC-8004 reputation registry.
     */
    constructor(address acp_, address registry_)
        BaseACPHook(acp_)
        Ownable(msg.sender)
    {
        require(registry_ != address(0), "AgentCourtHook: invalid registry");
        registry = IReputationRegistry(registry_);
    }

    // =========================================================================
    // BaseACPHook — overrides
    // =========================================================================

    /**
     * @dev Happy path — provider delivered. Write a small positive ERC-8004
     *      signal for the provider (+5 in 1e18 fixed-point).
     */
    function _postComplete(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory /* optParams */
    ) internal override {
        address provider = _getJobProvider(jobId);
        registry.giveFeedback(
            uint256(uint160(provider)),
            "job",
            "completed",
            5e18,
            ""
        );
    }

    /**
     * @dev Disputed path — open the appeal window. Reputation does NOT change
     *      here; it only moves after a Jurex judge panel renders a verdict.
     *      Idempotent: a second reject on the same job does nothing.
     */
    function _postReject(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory /* optParams */
    ) internal override {
        if (jobContract[jobId] == address(0)) {
            jobContract[jobId] = acpContract;
            emit AppealWindowOpened(jobId, acpContract);
        }
    }

    // =========================================================================
    // ERC165
    // =========================================================================

    /**
     * @notice Returns true for `IACPHook` and `IERC165` interface IDs so
     *         compliant ACP deployments can verify hook registration via
     *         ERC165Checker before dispatching callbacks.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC165)
        returns (bool)
    {
        return interfaceId == type(IACPHook).interfaceId
            || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    // Appeal settlement
    // =========================================================================

    /**
     * @notice Apply the Jurex verdict back to the ERC-8183 job contract.
     *
     *         Permissionless — any address may call once the linked CourtCase
     *         has reached Resolved state. Idempotent after first call.
     *
     *         providerWins=true  → job.complete() + ERC-8004 +5 ("dispute/won")
     *         providerWins=false → job.reject()   + ERC-8004 −5 ("dispute/lost")
     *
     * @param jobId        ERC-8183 job identifier.
     * @param providerWins True if the judge panel found in favour of the provider.
     */
    function settleAppeal(uint256 jobId, bool providerWins) external {
        require(!settled[jobId],                  "AgentCourtHook: already settled");
        require(jobContract[jobId] != address(0), "AgentCourtHook: no appeal window for this job");

        settled[jobId] = true;

        address    provider = _getJobProvider(jobId);
        uint256    agentId  = uint256(uint160(provider));
        IACPJob    job      = IACPJob(jobContract[jobId]);

        if (providerWins) {
            job.complete(jobId, bytes32(0), "");
            registry.giveFeedback(agentId, "dispute", "won",  5e18,  "");
        } else {
            job.reject(jobId, bytes32(0), "");
            registry.giveFeedback(agentId, "dispute", "lost", -5e18, "");
        }

        emit AppealSettled(jobId, providerWins);
    }

    // =========================================================================
    // Admin
    // =========================================================================

    /**
     * @notice Link a deployed CourtCase contract to a jobId.
     * @dev    Called by the owner after CourtCaseFactory.fileAppeal() because
     *         linkCase is owner-only and the factory cannot call it atomically.
     *         An off-chain relay watches for AppealFiled events and calls this.
     */
    function linkCase(uint256 jobId, address caseContract) external onlyOwner {
        require(caseContract != address(0), "AgentCourtHook: invalid case");
        jobToCase[jobId] = caseContract;
        emit CaseLinkSet(jobId, caseContract);
    }

    // =========================================================================
    // View
    // =========================================================================

    /// @notice Returns true if a rejection has opened an appeal window for this job.
    function hasAppealWindow(uint256 jobId) external view returns (bool) {
        return jobContract[jobId] != address(0);
    }

    /// @notice Returns the full appeal status for a job.
    function getAppealStatus(uint256 jobId) external view returns (
        address _jobContract,
        address _caseContract,
        bool    _settled
    ) {
        return (jobContract[jobId], jobToCase[jobId], settled[jobId]);
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// @dev Read the provider address from the ACP job contract.
    function _getJobProvider(uint256 jobId) internal view returns (address provider) {
        (bool ok, bytes memory data) = acpContract.staticcall(
            abi.encodeWithSignature("getJob(uint256)", jobId)
        );
        require(ok, "AgentCourtHook: getJob failed");
        (, , provider, , , , , , ) = abi.decode(
            data,
            (uint256, address, address, address, address, string, uint256, uint256, uint8)
        );
    }
}
