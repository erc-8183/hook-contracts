// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "@erc8183/AgenticCommerce.sol";

/**
 * @title AttestationHook
 * @notice Writes an immutable EAS attestation for every completed or rejected
 *         ACP job, creating an on-chain receipt that feeds reputation systems.
 *
 * USE CASE
 * --------
 * Off-chain trust scores and reputation graphs (e.g. ERC-8004) need a
 * verifiable, tamper-proof record of job outcomes. Without an attestation
 * layer, any reputation system must trust a centralised data source.
 * AttestationHook calls the Ethereum Attestation Service (EAS) after every
 * job completion or rejection, storing jobId, client, provider, evaluator,
 * budget, outcome reason, and a completed flag - permanently queryable by
 * anyone on-chain.
 *
 * FLOW (all interactions through core contract -> hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *  2. fund(jobId, optParams) - job moves to Funded.
 *  3. submit(jobId, deliverable, optParams) - job moves to Submitted.
 *  4. complete(jobId, reason, optParams)
 *     -> _postComplete (via afterAction): read job data from ERC-8183 core,
 *       call EAS.attest() with completed=true. Uses try/catch so EAS
 *       failures never revert the completion. Stores attestation UID.
 *  5. reject(jobId, reason, optParams) [alternative to step 4]
 *     -> _postReject (via afterAction): same as above with completed=false.
 *
 * TRUST MODEL
 * -----------
 * Attestations are non-revocable - job outcomes are facts. The hook never
 * intercepts beforeAction, so it can never block a job lifecycle transition.
 * Each jobId is attested exactly once (CEI sentinel guard). EAS contract
 * and schema UID are owner-updatable in case of re-registration, but the
 * already-written attestations on EAS are immutable.
 *
 * @custom:security-contact security@erc-8183.org
 */

/// @notice Minimal EAS interface (Base: 0x4200000000000000000000000000000000000021)
interface IEAS {
    struct AttestationRequestData {
        address recipient;
        uint64 expirationTime;
        bool revocable;
        bytes32 refUID;
        bytes data;
        uint256 value;
    }

    struct AttestationRequest {
        bytes32 schema;
        AttestationRequestData data;
    }

    function attest(AttestationRequest calldata request) external payable returns (bytes32);
}

contract AttestationHook is BaseERC8183Hook, IERC8183HookMetadata {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Sentinel value to mark in-progress attestation (CEI pattern)
    bytes32 private constant _PENDING_SENTINEL = bytes32(type(uint256).max);

    bytes4 private constant SEL_COMPLETE =
        bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_REJECT =
        bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice EAS contract (Base predeploy at 0x4200...0021)
    IEAS public eas;

    /// @notice Schema UID for the ACP job receipt schema
    bytes32 public schemaUID;

    /// @notice AgenticCommerce contract to read job details
    AgenticCommerce public immutable agenticCommerce;

    /// @notice Owner for admin functions
    address public owner;

    /// @notice Pending owner for two-step transfer
    address public pendingOwner;

    /// @notice Track attestation UIDs per job (for reference)
    mapping(uint256 => bytes32) public jobAttestations;

    /// @notice Counter for total attestations written
    uint256 public totalAttestations;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event AttestationCreated(
        uint256 indexed jobId,
        bytes32 indexed attestationUID,
        address indexed provider,
        bool completed
    );

    event AttestationFailed(uint256 indexed jobId, bytes reason);
    event SchemaUpdated(bytes32 indexed newSchemaUID);
    event EASUpdated(address indexed newEAS);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error AttestationHook__OnlyOwner();
    error AttestationHook__OnlyPendingOwner();
    error AttestationHook__ZeroAddress();
    error AttestationHook__ZeroSchemaUID();
    error AttestationHook__NotContract();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param erc8183Contract_  ERC-8183 core contract address
     * @param eas_              EAS contract address (Base: 0x4200000000000000000000000000000000000021)
     * @param schemaUID_        Pre-registered EAS schema UID for ACP receipts
     */
    constructor(
        address erc8183Contract_,
        address eas_,
        bytes32 schemaUID_
    ) BaseERC8183Hook(erc8183Contract_) {
        if (eas_ == address(0)) revert AttestationHook__ZeroAddress();
        if (schemaUID_ == bytes32(0)) revert AttestationHook__ZeroSchemaUID();

        eas = IEAS(eas_);
        schemaUID = schemaUID_;
        agenticCommerce = AgenticCommerce(erc8183Contract_);
        owner = msg.sender;

        emit OwnershipTransferred(address(0), msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: POST-COMPLETE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after a job is completed. Writes a positive attestation.
     * @param jobId The completed job ID
     * @param reason The evaluator's reason hash
     */
    function _postComplete(
        uint256 jobId,
        address, /* caller */
        bytes32 reason,
        bytes memory /* optParams */
    ) internal override {
        _writeAttestation(jobId, reason, true);
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: POST-REJECT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after a job is rejected. Writes a negative attestation.
     * @param jobId The rejected job ID
     * @param reason The evaluator's/client's reason hash
     */
    function _postReject(
        uint256 jobId,
        address, /* caller */
        bytes32 reason,
        bytes memory /* optParams */
    ) internal override {
        _writeAttestation(jobId, reason, false);
    }

    /*//////////////////////////////////////////////////////////////
                    CORE: WRITE ATTESTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Reads job data from ERC-8183 core and writes an EAS attestation.
     *      Uses try/catch - EAS failures NEVER revert the parent transaction.
     *      Idempotent - each jobId can only be attested once.
     *      Follows CEI pattern with a pending sentinel.
     *
     * Schema encoding:
     *   abi.encode(jobId, client, provider, evaluator, budget, reason, completed)
     *
     * Recipient = provider (they accumulate reputation from completed/rejected jobs)
     */
    function _writeAttestation(
        uint256 jobId,
        bytes32 reason,
        bool completed
    ) internal {
        // [ATH-02] Idempotency guard - each job attested once only
        if (jobAttestations[jobId] != bytes32(0)) return;

        // Read job data from ACP contract
        AgenticCommerce.Job memory job;
        try agenticCommerce.getJob(jobId) returns (AgenticCommerce.Job memory j) {
            job = j;
        } catch (bytes memory err) {
            emit AttestationFailed(jobId, err);
            return;
        }

        // Encode attestation data matching registered schema:
        // "uint256 jobId, address client, address provider, address evaluator,
        //  uint256 budget, bytes32 reason, bool completed"
        bytes memory attestationData = abi.encode(
            jobId,
            job.client,
            job.provider,
            job.evaluator,
            job.budget,
            reason,
            completed
        );

        // [ATH-05] CEI: Set sentinel BEFORE external call
        jobAttestations[jobId] = _PENDING_SENTINEL;

        // Write to EAS
        try eas.attest(
            IEAS.AttestationRequest({
                schema: schemaUID,
                data: IEAS.AttestationRequestData({
                    recipient: job.provider,   // Provider accumulates reputation
                    expirationTime: 0,         // Never expires (permanent record)
                    revocable: false,          // Job outcomes are facts, not opinions
                    refUID: bytes32(0),        // No reference (standalone receipt)
                    data: attestationData,
                    value: 0                   // No ETH value
                })
            })
        ) returns (bytes32 uid) {
            jobAttestations[jobId] = uid;
            totalAttestations++;
            emit AttestationCreated(jobId, uid, job.provider, completed);
        } catch (bytes memory err) {
            // Reset sentinel on failure
            jobAttestations[jobId] = bytes32(0);
            emit AttestationFailed(jobId, err);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner_() {
        if (msg.sender != owner) revert AttestationHook__OnlyOwner();
        _;
    }

    /**
     * @notice Update the EAS schema UID (e.g. if schema is re-registered)
     * @param schemaUID_ New schema UID (must be non-zero)
     */
    function setSchemaUID(bytes32 schemaUID_) external onlyOwner_ {
        if (schemaUID_ == bytes32(0)) revert AttestationHook__ZeroSchemaUID();
        schemaUID = schemaUID_;
        emit SchemaUpdated(schemaUID_);
    }

    /**
     * @notice Update the EAS contract address
     * @param eas_ New EAS address (must be non-zero contract)
     */
    function setEAS(address eas_) external onlyOwner_ {
        if (eas_ == address(0)) revert AttestationHook__ZeroAddress();
        eas = IEAS(eas_);
        emit EASUpdated(eas_);
    }

    /**
     * @notice Start two-step ownership transfer
     * @param newOwner Proposed new owner (must be non-zero)
     */
    function transferOwnership(address newOwner) external onlyOwner_ {
        if (newOwner == address(0)) revert AttestationHook__ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /**
     * @notice Accept ownership transfer (must be called by pending owner)
     */
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert AttestationHook__OnlyPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    /*//////////////////////////////////////////////////////////////
                    VIEW
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the EAS attestation UID for a given job
     * @param jobId The job ID
     * @return uid The attestation UID (bytes32(0) if not attested)
     */
    function getAttestation(uint256 jobId) external view returns (bytes32) {
        bytes32 uid = jobAttestations[jobId];
        // Don't expose the sentinel value
        return uid == _PENDING_SENTINEL ? bytes32(0) : uid;
    }

    /**
     * @notice ERC-165 support
     */
    function requiredSelectors() external pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](2);
        selectors[0] = SEL_COMPLETE;
        selectors[1] = SEL_REJECT;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(BaseERC8183Hook) returns (bool) {
        return interfaceId == type(IERC8183HookMetadata).interfaceId
            || super.supportsInterface(interfaceId);
    }
}
