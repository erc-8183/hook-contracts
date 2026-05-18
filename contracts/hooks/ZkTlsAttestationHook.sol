// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseERC8183Hook} from "../BaseERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @dev Generic network request captured by a zkTLS attestor.
struct AttNetworkRequest {
    string url;
    string header;
    string method;
    string body;
}

/// @dev Declaration of how a single response field was extracted (JSONPath / XPath).
struct AttNetworkResponseResolve {
    string keyName;
    string parseType;
    string parsePath;
}

/// @dev A zkTLS attestor that signed the attestation.
struct Attestor {
    address attestorAddr;
    string url;
}

/// @dev Generic zkTLS attestation. Field shape mirrors the de facto on-chain layout
///      used by existing zkTLS verifiers. The `reponseResolve` spelling is preserved
///      verbatim for ABI compatibility with verifiers already deployed in the wild.
struct Attestation {
    address recipient;
    AttNetworkRequest request;
    AttNetworkResponseResolve[] reponseResolve;
    string data;
    string attConditions;
    uint64 timestamp;
    string additionParams;
    Attestor[] attestors;
    bytes[] signatures;
}

/// @dev Pluggable zkTLS verifier. The verifier MUST revert on a failed verification
///      (return-on-success semantics break the staticcall pattern this hook uses).
interface IZkTlsVerifier {
    function verifyAttestation(Attestation calldata attestation) external view;
}

/// @dev Per-job, job-defined extension hook for business-level checks the generic
///      hook cannot express (price bands, multi-step aggregation, threshold logic).
///      Called via staticcall so it cannot mutate state regardless of its code.
interface IAttestationExtensionVerifier {
    function verify(
        uint256 jobId,
        bytes32 deliverable,
        Attestation[] calldata attestations,
        bytes calldata customCalldata
    ) external view;
}

/// @dev Timestamp unit used by the attestor for `att.timestamp` in this step.
///      Different zkTLS attestors disagree about whether timestamps are in seconds
///      or milliseconds; the spec author picks the right one per step.
enum TimeUnit { Seconds, Milliseconds }

/// @dev Pinned shape of one HTTPS call the provider must make. Every non-zero hash
///      field is enforced; the hook also enforces:
///        - the attestation's `additionParams` contains the hex of `expectedJobBinding`
///          (cross-job replay defense — see _verifyOneStep);
///        - the attestation's timestamp is within `maxAge` seconds of block.timestamp,
///          accounting for `timeUnit` and a small forward-skew tolerance;
///        - if `minAttestorsRequired > 0`, at least that many of the attestation's
///          signers fall inside `allowedAttestors`.
struct RequestStep {
    bytes32 methodHash;
    bytes32 urlHash;
    bytes32 bodyHash;
    bytes32 responseResolveHash;
    bytes32 additionParamsHash;
    /// @dev keccak256(abi.encode(jobId, address(hook), block.chainid)). Required to
    ///      appear as an ASCII-hex substring inside att.additionParams. Cross-job
    ///      replay defense.
    bytes32 expectedJobBinding;
    /// @dev Maximum acceptable age of the attestation in seconds, regardless of timeUnit.
    ///      Must satisfy [MIN_MAX_AGE, MAX_MAX_AGE].
    uint64  maxAge;
    /// @dev Unit of att.timestamp for this step. Hook converts to seconds before the
    ///      staleness compare.
    TimeUnit timeUnit;
    /// @dev Allowlist of acceptable attestor signing addresses. Empty = skip the
    ///      quorum check (relying on the upstream zkTLS verifier's own attestor set).
    address[] allowedAttestors;
    /// @dev Minimum number of `att.attestors` whose `attestorAddr` must lie in
    ///      `allowedAttestors`. 0 = skip the check.
    uint8 minAttestorsRequired;
}

/// @dev Cross-step data flow. Exactly one of {value, fromExtractKey} must be non-empty:
///        - value:           static byte string the spec author already knows (e.g.
///                           constant identifiers like "bitcoin")
///        - fromExtractKey:  dynamic — name a JSON key in atts[fromStep].data; the
///                           hook extracts its parsed value at submit time and uses
///                           that as the substring to check against the destination
struct DataBinding {
    uint8 fromStep;
    uint8 toStep;
    uint8 toLocation;        // 0=url, 1=header, 2=body
    bytes value;             // static value (used when fromExtractKey is empty)
    bytes fromExtractKey;    // dynamic-extract key (overrides value when non-empty)
}

/// @dev Full attestation spec for a job. Frozen at fund time and never mutated.
struct AttestationSpec {
    RequestStep[] steps;
    DataBinding[] bindings;
    uint8 deliverableSourceStep;
    address customVerifier;
    /// @dev Snapshot of the hook's `zkTlsVerifier` at fund time. The hook uses this
    ///      (not the live `zkTlsVerifier`) at submit time so an owner rotation does
    ///      not retroactively change the trust anchor of an in-flight job.
    address zkTlsVerifierSnapshot;
    bool configured;
}

/**
 * @title ZkTlsAttestationHook
 * @notice ERC-8183 hook that binds a job's deliverable to one or more zkTLS
 *         attestations of the off-chain HTTPS calls the provider promised to make.
 *
 * USE CASE
 * --------
 * When a provider's job involves fetching data from one or more Web2 APIs and
 * the client wants cryptographic evidence that the provider (a) actually made
 * those calls, (b) made them against the URLs / methods / bodies pinned in
 * the spec, (c) propagated values across multi-step pipelines as declared,
 * and (d) submitted a deliverable bound to the parsed response — without
 * trusting the provider, without modifying the ERC-8183 core, and without
 * coupling to any single zkTLS vendor.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this).
 *  2. setProvider / setBudget — normal flow (no hook logic here).
 *  3. fund(jobId, expectedBudget, optParams=abi.encode(AttestationSpec))
 *     → _postFund: validate + store the spec immutably. Snapshots the active
 *       `zkTlsVerifier` into the per-job spec so future rotations are
 *       backwards-compatible.
 *  4. Off-chain: provider drives each step's HTTPS call through a zkTLS
 *     attestor, embedding the per-job binding in `additionParams`, and
 *     collects one Attestation per step.
 *  5. submit(jobId, deliverable, optParams=abi.encode(Attestation[], bytes))
 *     → _preSubmit: unified-layer checks (per-step verifier call, hash equality,
 *       quorum, staleness, job binding, cross-step bindings, deliverable bind);
 *       then optional customVerifier dispatch.
 *  6. complete / reject — normal flow.
 *
 * TRUST MODEL
 * -----------
 * The hook validates attestation **shape, binding, freshness, and recipient** only.
 * The hook does NOT enforce semantic correctness of returned data — domain-level
 * invariants belong in an `IAttestationExtensionVerifier` from the owner-curated
 * `trustedExtensionVerifiers` allowlist.
 *
 * Per-job spec is frozen at fund time. The hook's verifier address is mutable
 * via a two-step Ownable rotation with a 7-day delay, but each in-flight job
 * uses its own snapshot, so an in-progress job's trust anchor is locked at
 * fund time.
 */
contract ZkTlsAttestationHook is BaseERC8183Hook, IERC8183HookMetadata, Ownable {
    // --- Storage -------------------------------------------------------------

    /// @notice Active zkTLS verifier; used by `_postFund` to snapshot into new jobs.
    address public zkTlsVerifier;
    /// @notice Pending verifier proposed by the owner; ready after `pendingVerifierActivationTime`.
    address public pendingZkTlsVerifier;
    /// @notice Earliest block.timestamp at which `activateZkTlsVerifier()` may succeed.
    uint256 public pendingVerifierActivationTime;

    mapping(uint256 => AttestationSpec) private _specs;
    mapping(uint256 => bytes32) public envelopeCommitments;

    /// @notice Owner-curated allowlist of customVerifier addresses. A spec's
    ///         `customVerifier` must be address(0) or appear here.
    mapping(address => bool) public trustedExtensionVerifiers;

    // --- Constants -----------------------------------------------------------

    /// @dev Spec author bounds. MAX_STEPS / MAX_BINDINGS guard gas at submit;
    ///      MAX_ATTESTORS_PER_STEP guards the O(N*M) quorum loop.
    uint256 public constant MAX_STEPS              = 16;
    uint256 public constant MAX_BINDINGS           = 32;
    uint256 public constant MAX_ATTESTORS_PER_STEP = 8;

    /// @dev maxAge must lie in [1, 24h]. Zero would silently disable freshness;
    ///      values larger than 24h widen replay windows unhelpfully.
    uint64  public constant MIN_MAX_AGE = 1;
    uint64  public constant MAX_MAX_AGE = 24 hours;

    /// @dev Two-step verifier rotation gives downstream clients seven days to
    ///      observe a proposed change before it lands.
    uint256 public constant VERIFIER_ROTATION_DELAY = 7 days;

    /// @dev Forward-skew tolerance for the freshness check. EVM clocks and zkTLS
    ///      attestor clocks can drift by a few seconds; this allows that.
    uint256 public constant FORWARD_SKEW_TOLERANCE = 30;

    // --- Errors --------------------------------------------------------------

    error InvalidZkTlsVerifier();
    error NotAContract();
    error InvalidAddress();
    error NoPendingVerifier();
    error RotationDelayNotElapsed();

    error SpecRequired();
    error SpecAlreadyConfigured();
    error SpecNotConfigured();
    error EmptySteps();
    error TooManySteps();
    error TooManyBindings();
    error TooManyAttestors();
    error InvalidDeliverableSourceStep();
    error InvalidBinding();
    error InvalidLocation();
    error InvalidMaxAge();
    error InvalidJobBinding();
    error UnsatisfiableStep();
    error ExtensionVerifierNotTrusted();

    error StepCountMismatch();
    error AttestationVerifierFailed();
    error MethodHashMismatch();
    error UrlHashMismatch();
    error BodyHashMismatch();
    error ResponseResolveHashMismatch();
    error AdditionParamsHashMismatch();
    error AttestationStale();
    error AttestorQuorumNotMet();
    error JobBindingMissing();
    error DataBindingViolated();
    error DeliverableMismatch();
    error ExtensionVerifierFailed();
    error ExtractKeyNotFound();
    error UnterminatedExtractValue();

    // --- Events --------------------------------------------------------------

    event SpecConfigured(
        uint256 indexed jobId,
        uint256 stepCount,
        uint256 bindingCount,
        address customVerifier,
        address zkTlsVerifierSnapshot
    );
    event AttestationsValidated(
        uint256 indexed jobId,
        bytes32 indexed deliverable,
        bytes32 envelope,
        uint256 stepCount
    );
    event VerifierProposed(address indexed newVerifier, uint256 activationTime);
    event VerifierActivated(address indexed newVerifier);
    event TrustedExtensionVerifierUpdated(address indexed verifier, bool trusted);

    /// @param erc8183Contract_ ERC-8183 core address.
    /// @param zkTlsVerifier_   Address of an IZkTlsVerifier implementation that reverts on bad attestations.
    /// @param owner_           Address that may rotate the verifier and curate the extension allowlist.
    constructor(
        address erc8183Contract_,
        address zkTlsVerifier_,
        address owner_
    ) BaseERC8183Hook(erc8183Contract_) Ownable(owner_) {
        if (zkTlsVerifier_ == address(0)) revert InvalidZkTlsVerifier();
        _requireContract(zkTlsVerifier_);
        zkTlsVerifier = zkTlsVerifier_;
    }

    // --- Owner: verifier rotation ---------------------------------------------

    /// @notice Propose a new zkTLS verifier address. Becomes activatable after
    ///         `VERIFIER_ROTATION_DELAY`. Replacing a pending proposal resets the timer.
    function proposeZkTlsVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert InvalidZkTlsVerifier();
        _requireContract(newVerifier);
        pendingZkTlsVerifier = newVerifier;
        pendingVerifierActivationTime = block.timestamp + VERIFIER_ROTATION_DELAY;
        emit VerifierProposed(newVerifier, pendingVerifierActivationTime);
    }

    /// @notice Activate the pending verifier after the rotation delay has elapsed.
    ///         New jobs (those funded from now on) snapshot the new verifier;
    ///         in-flight jobs keep their original snapshot.
    function activateZkTlsVerifier() external onlyOwner {
        address pending = pendingZkTlsVerifier;
        if (pending == address(0)) revert NoPendingVerifier();
        if (block.timestamp < pendingVerifierActivationTime) revert RotationDelayNotElapsed();
        zkTlsVerifier = pending;
        pendingZkTlsVerifier = address(0);
        pendingVerifierActivationTime = 0;
        emit VerifierActivated(pending);
    }

    // --- Owner: extension verifier allowlist ----------------------------------

    function setTrustedExtensionVerifier(address verifier, bool trusted) external onlyOwner {
        if (verifier == address(0)) revert InvalidAddress();
        if (trusted) _requireContract(verifier);
        trustedExtensionVerifiers[verifier] = trusted;
        emit TrustedExtensionVerifierUpdated(verifier, trusted);
    }

    // --- Hook callbacks -------------------------------------------------------

    /// @dev Store the per-job attestation spec from fund's optParams. Empty optParams
    ///      reverts SpecRequired — a silent no-op would brick the submit path and
    ///      lock the escrow until expiry.
    function _postFund(uint256 jobId, address, bytes memory optParams) internal override {
        if (optParams.length == 0) revert SpecRequired();

        AttestationSpec storage stored = _specs[jobId];
        if (stored.configured) revert SpecAlreadyConfigured();

        AttestationSpec memory s = abi.decode(optParams, (AttestationSpec));

        uint256 stepCount = s.steps.length;
        if (stepCount == 0) revert EmptySteps();
        if (stepCount > MAX_STEPS) revert TooManySteps();
        if (s.bindings.length > MAX_BINDINGS) revert TooManyBindings();
        if (s.deliverableSourceStep >= stepCount) revert InvalidDeliverableSourceStep();

        // customVerifier must be address(0) or on the owner-curated allowlist;
        // additionally, if non-zero, must be a contract.
        if (s.customVerifier != address(0)) {
            if (!trustedExtensionVerifiers[s.customVerifier]) revert ExtensionVerifierNotTrusted();
            _requireContract(s.customVerifier);
        }

        // Per-step validation.
        bytes32 expectedBinding = keccak256(abi.encode(jobId, address(this), block.chainid));
        for (uint256 i = 0; i < stepCount; ++i) {
            RequestStep memory step = s.steps[i];

            // At least one of methodHash / urlHash / bodyHash must be pinned, or
            // the step is essentially unconstrained — almost certainly a misconfig.
            if (step.methodHash == bytes32(0)
                && step.urlHash == bytes32(0)
                && step.bodyHash == bytes32(0)) {
                revert UnsatisfiableStep();
            }

            // Freshness window must be set and bounded.
            if (step.maxAge < MIN_MAX_AGE || step.maxAge > MAX_MAX_AGE) revert InvalidMaxAge();

            // Cross-job binding must equal what THIS hook computes for THIS job —
            // a defense in depth on top of the runtime `_contains` check.
            if (step.expectedJobBinding != expectedBinding) revert InvalidJobBinding();

            // Quorum allowlist must fit gas budget.
            if (step.allowedAttestors.length > MAX_ATTESTORS_PER_STEP) revert TooManyAttestors();
            if (step.minAttestorsRequired > step.allowedAttestors.length) revert AttestorQuorumNotMet();
        }

        // Per-binding validation.
        for (uint256 i = 0; i < s.bindings.length; ++i) {
            DataBinding memory b = s.bindings[i];
            if (b.fromStep >= b.toStep) revert InvalidBinding();
            if (b.toStep >= stepCount) revert InvalidBinding();
            if (b.toLocation > 2) revert InvalidLocation();
            // Exactly one of {value, fromExtractKey} must be non-empty.
            bool hasStatic = b.value.length > 0;
            bool hasDynamic = b.fromExtractKey.length > 0;
            if (hasStatic == hasDynamic) revert InvalidBinding();
        }

        // Persist into storage.
        for (uint256 i = 0; i < stepCount; ++i) {
            stored.steps.push(s.steps[i]);
        }
        for (uint256 i = 0; i < s.bindings.length; ++i) {
            stored.bindings.push(s.bindings[i]);
        }
        stored.deliverableSourceStep = s.deliverableSourceStep;
        stored.customVerifier = s.customVerifier;
        stored.zkTlsVerifierSnapshot = zkTlsVerifier;        // pin at fund time
        stored.configured = true;

        emit SpecConfigured(
            jobId,
            stepCount,
            s.bindings.length,
            s.customVerifier,
            stored.zkTlsVerifierSnapshot
        );
    }

    /// @dev Validate attestations bound to the deliverable. Reverts on any mismatch
    ///      so the submit transaction is rejected before state moves to Submitted.
    function _preSubmit(uint256 jobId, address, bytes32 deliverable, bytes memory optParams) internal override {
        AttestationSpec storage spec = _specs[jobId];
        if (!spec.configured) revert SpecNotConfigured();

        (Attestation[] memory atts, bytes memory customCalldata) =
            abi.decode(optParams, (Attestation[], bytes));

        uint256 stepCount = spec.steps.length;
        if (atts.length != stepCount) revert StepCountMismatch();

        address verifier = spec.zkTlsVerifierSnapshot;
        for (uint256 i = 0; i < stepCount; ++i) {
            _verifyOneStep(atts[i], spec.steps[i], verifier);
        }

        uint256 bindingCount = spec.bindings.length;
        for (uint256 i = 0; i < bindingCount; ++i) {
            DataBinding memory b = spec.bindings[i];
            bytes memory src = bytes(atts[b.fromStep].data);
            bytes memory dst = _locationBytes(atts[b.toStep].request, b.toLocation);
            bytes memory needle = b.fromExtractKey.length > 0
                ? _extractFieldValue(src, b.fromExtractKey)
                : b.value;
            if (!_containsBounded(src, needle)) revert DataBindingViolated();
            if (!_containsBounded(dst, needle)) revert DataBindingViolated();
        }

        if (keccak256(bytes(atts[spec.deliverableSourceStep].data)) != deliverable) {
            revert DeliverableMismatch();
        }

        address ext = spec.customVerifier;
        if (ext != address(0)) {
            (bool ok, ) = ext.staticcall(
                abi.encodeCall(
                    IAttestationExtensionVerifier.verify,
                    (jobId, deliverable, atts, customCalldata)
                )
            );
            if (!ok) revert ExtensionVerifierFailed();
        }

        // The core's state machine already prevents resubmission; the previous
        // explicit AlreadyValidated check has been removed. The envelope write
        // remains for off-chain indexing.
        bytes32 envelope = keccak256(abi.encode(jobId, deliverable, atts));
        envelopeCommitments[jobId] = envelope;
        emit AttestationsValidated(jobId, deliverable, envelope, stepCount);
    }

    // --- Internal verification -----------------------------------------------

    function _verifyOneStep(
        Attestation memory att,
        RequestStep memory step,
        address verifier
    ) internal view {
        // (a) The zkTLS verifier's signature check, by staticcall to its read-only
        //     entry point. The hook does not interpret the verifier's revert reason.
        (bool ok, ) = verifier.staticcall(
            abi.encodeCall(IZkTlsVerifier.verifyAttestation, (att))
        );
        if (!ok) revert AttestationVerifierFailed();

        // (b) Freshness.
        _checkStaleness(att.timestamp, step.timeUnit, step.maxAge);

        // (c) Cross-job binding. step.expectedJobBinding was constrained in
        //     _postFund to equal keccak256(jobId, address(this), block.chainid),
        //     so reading it from the spec is equivalent to recomputing.
        if (!_contains(
            bytes(att.additionParams),
            _bytes32ToHex(step.expectedJobBinding)
        )) revert JobBindingMissing();

        // (d) Pinned-field hash equality.
        if (step.methodHash != bytes32(0)
            && keccak256(bytes(att.request.method)) != step.methodHash) {
            revert MethodHashMismatch();
        }
        if (step.urlHash != bytes32(0)
            && keccak256(bytes(att.request.url)) != step.urlHash) {
            revert UrlHashMismatch();
        }
        if (step.bodyHash != bytes32(0)
            && keccak256(bytes(att.request.body)) != step.bodyHash) {
            revert BodyHashMismatch();
        }
        if (step.responseResolveHash != bytes32(0)
            && _hashResponseResolves(att.reponseResolve) != step.responseResolveHash) {
            revert ResponseResolveHashMismatch();
        }
        if (step.additionParamsHash != bytes32(0)
            && keccak256(bytes(att.additionParams)) != step.additionParamsHash) {
            revert AdditionParamsHashMismatch();
        }

        // (e) Attestor quorum.
        if (step.minAttestorsRequired > 0) {
            uint256 matched = 0;
            uint256 attestorCount = att.attestors.length;
            uint256 allowCount = step.allowedAttestors.length;
            for (uint256 i = 0; i < attestorCount; ++i) {
                address a = att.attestors[i].attestorAddr;
                for (uint256 j = 0; j < allowCount; ++j) {
                    if (a == step.allowedAttestors[j]) {
                        unchecked { ++matched; }
                        break;
                    }
                }
            }
            if (matched < step.minAttestorsRequired) revert AttestorQuorumNotMet();
        }
    }

    function _checkStaleness(uint64 timestamp, TimeUnit unit, uint64 maxAge) internal view {
        // Normalize the attestation timestamp into seconds.
        uint256 attTsSec = unit == TimeUnit.Milliseconds
            ? uint256(timestamp) / 1000
            : uint256(timestamp);

        // Tolerate a small forward skew: an attestor whose clock is slightly ahead
        // of the chain should not look "from the future".
        if (attTsSec > block.timestamp + FORWARD_SKEW_TOLERANCE) revert AttestationStale();

        // Past-direction: reject if older than maxAge. The subtraction is safe
        // because attTsSec <= block.timestamp + FORWARD_SKEW_TOLERANCE; combine
        // with maxAge >= MIN_MAX_AGE this never underflows.
        if (block.timestamp > attTsSec
            && block.timestamp - attTsSec > maxAge) revert AttestationStale();
    }

    function _hashResponseResolves(AttNetworkResponseResolve[] memory resolves) internal pure returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](resolves.length);
        for (uint256 i = 0; i < resolves.length; ++i) {
            leaves[i] = keccak256(abi.encode(
                resolves[i].keyName,
                resolves[i].parseType,
                resolves[i].parsePath
            ));
        }
        return keccak256(abi.encode(leaves));
    }

    function _locationBytes(AttNetworkRequest memory req, uint8 location) internal pure returns (bytes memory) {
        if (location == 0) return bytes(req.url);
        if (location == 1) return bytes(req.header);
        return bytes(req.body); // location == 2; bounded by _postFund guard
    }

    /// @dev Naive substring search. Used by the cross-job-binding check (against
    ///      a fixed-length ASCII-hex needle).
    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        uint256 nLen = needle.length;
        uint256 hLen = haystack.length;
        if (nLen == 0) return true;
        if (nLen > hLen) return false;
        uint256 last = hLen - nLen;
        for (uint256 i = 0; i <= last; ++i) {
            bool matched = true;
            for (uint256 j = 0; j < nLen; ++j) {
                if (haystack[i + j] != needle[j]) { matched = false; break; }
            }
            if (matched) return true;
        }
        return false;
    }

    /// @dev Substring search with delimiter boundaries. Used by data-binding
    ///      validation so e.g. `"price":"100"` is not mistakenly matched by
    ///      a search for `100` against `"price":"1000"`. The match must be
    ///      bracketed by one of  " , } : & =  (or by the haystack edges).
    function _containsBounded(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        uint256 nLen = needle.length;
        uint256 hLen = haystack.length;
        if (nLen == 0) return true;
        if (nLen > hLen) return false;
        uint256 last = hLen - nLen;
        for (uint256 i = 0; i <= last; ++i) {
            bool matched = true;
            for (uint256 j = 0; j < nLen; ++j) {
                if (haystack[i + j] != needle[j]) { matched = false; break; }
            }
            if (matched) {
                bool leftOk = (i == 0) || _isBoundary(haystack[i - 1]);
                bool rightOk = (i + nLen == hLen) || _isBoundary(haystack[i + nLen]);
                if (leftOk && rightOk) return true;
            }
        }
        return false;
    }

    function _isBoundary(bytes1 c) internal pure returns (bool) {
        // Reviewer's set: `" , } : & =`. Adding `/` so URL path segments
        // ("foo/bitcoin/bar") count as bounded contexts — important because
        // single-step `<<id>>`-style substitution lands binding values in
        // URL paths in the common case.
        return c == 0x22  // "
            || c == 0x2C  // ,
            || c == 0x7D  // }
            || c == 0x3A  // :
            || c == 0x26  // &
            || c == 0x3D  // =
            || c == 0x2F; // /
    }

    /// @dev Extract the JSON string value of `"<keyName>":"<value>"` from `dataStr`.
    ///      Backslash-escaped quotes inside the value are respected. Reverts on
    ///      key-not-found or unterminated string. Returns the raw bytes of the
    ///      value (including any escape sequences) so the downstream substring
    ///      check matches what the attestation surface actually contains.
    function _extractFieldValue(bytes memory dataStr, bytes memory keyName) internal pure returns (bytes memory) {
        bytes memory needle = abi.encodePacked('"', keyName, '":"');
        uint256 nLen = needle.length;
        uint256 hLen = dataStr.length;
        if (nLen > hLen) revert ExtractKeyNotFound();

        uint256 start = type(uint256).max;
        uint256 last = hLen - nLen;
        for (uint256 k = 0; k <= last; ++k) {
            bool matched = true;
            for (uint256 j = 0; j < nLen; ++j) {
                if (dataStr[k + j] != needle[j]) { matched = false; break; }
            }
            if (matched) { start = k + nLen; break; }
        }
        if (start == type(uint256).max) revert ExtractKeyNotFound();

        uint256 p = start;
        while (p < hLen) {
            bytes1 c = dataStr[p];
            if (c == 0x22) {
                // Found the closing quote.
                bytes memory out = new bytes(p - start);
                for (uint256 i = 0; i < p - start; ++i) {
                    out[i] = dataStr[start + i];
                }
                return out;
            }
            if (c == 0x5C) {
                if (p + 1 >= hLen) revert UnterminatedExtractValue();
                p += 2;
                continue;
            }
            unchecked { ++p; }
        }
        revert UnterminatedExtractValue();
    }

    /// @dev Render a bytes32 as 66 ASCII bytes: "0x" + 64 lowercase hex chars.
    function _bytes32ToHex(bytes32 v) internal pure returns (bytes memory) {
        bytes memory out = new bytes(66);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(v[i]);
            out[2 + 2 * i]     = _hexChar(b >> 4);
            out[2 + 2 * i + 1] = _hexChar(b & 0x0f);
        }
        return out;
    }

    function _hexChar(uint8 nibble) internal pure returns (bytes1) {
        return bytes1(nibble < 10 ? nibble + 0x30 : nibble + 0x57);
    }

    /// @dev Revert if `a` has no code. Static check — does not differentiate between
    ///      "EOA" and "self-destructed contract"; both look the same and both fail.
    function _requireContract(address a) internal view {
        uint256 size;
        assembly { size := extcodesize(a) }
        if (size == 0) revert NotAContract();
    }

    // --- Views ---------------------------------------------------------------

    function getSpec(uint256 jobId) external view returns (
        RequestStep[] memory steps,
        DataBinding[] memory bindings,
        uint8 deliverableSourceStep,
        address customVerifier,
        bool configured
    ) {
        AttestationSpec storage s = _specs[jobId];
        return (
            s.steps,
            s.bindings,
            s.deliverableSourceStep,
            s.customVerifier,
            s.configured
        );
    }

    /// @notice Returns the verifier address that was snapshotted into the job's
    ///         spec at fund time. Split from `getSpec` to keep stack pressure
    ///         on the latter manageable under the default solc settings.
    function getVerifierSnapshot(uint256 jobId) external view returns (address) {
        return _specs[jobId].zkTlsVerifierSnapshot;
    }

    function isValidated(uint256 jobId) external view returns (bool) {
        return envelopeCommitments[jobId] != bytes32(0);
    }

    /// @notice Compute the expected `RequestStep.expectedJobBinding` for a given
    ///         jobId. Helper for spec authors / SDKs.
    function jobBindingFor(uint256 jobId) external view returns (bytes32) {
        return keccak256(abi.encode(jobId, address(this), block.chainid));
    }

    // --- IERC8183HookMetadata ------------------------------------------------

    /// @dev Configuration on fund and validation on submit must be wired together.
    function requiredSelectors() external pure returns (bytes4[] memory) {
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = bytes4(keccak256("fund(uint256,uint256,bytes)"));
        sels[1] = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
        return sels;
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IERC8183HookMetadata).interfaceId
            || super.supportsInterface(interfaceId);
    }
}
