// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseERC8183Hook} from "../BaseERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";

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
///      MUST be view: a malicious verifier cannot mutate state because the call
///      goes through staticcall, but the interface is declared view to make the
///      contract author's intent explicit.
interface IAttestationExtensionVerifier {
    function verify(
        uint256 jobId,
        bytes32 deliverable,
        Attestation[] calldata attestations,
        bytes calldata customCalldata
    ) external view;
}

/// @dev Pinned shape of one HTTPS call the provider must make. Every non-zero hash
///      is enforced; setting a field's hash to bytes32(0) means "spec does not
///      pin this field" (used to allow flexibility in e.g. headers or additionParams).
///      pinnedAttestor == address(0) means "trust the verifier's own attestor set";
///      a non-zero value forbids attestor rotation for this step.
struct RequestStep {
    bytes32 methodHash;
    bytes32 urlHash;
    bytes32 bodyHash;
    bytes32 responseResolveHash;
    bytes32 additionParamsHash;
    uint64  maxAge;
    address pinnedAttestor;
}

/// @dev Cross-step data flow. The spec declares the exact bytes that must flow
///      from atts[fromStep].data into atts[toStep].request.{url|header|body}.
///      This is a static binding: the value is fixed in the spec, not extracted
///      per execution. Dynamic per-execution flows must be enforced via a
///      customVerifier instead.
struct DataBinding {
    uint8 fromStep;
    uint8 toStep;
    uint8 toLocation;    // 0=url, 1=header, 2=body
    bytes value;
}

/// @dev Full attestation spec for a job. Frozen at fund time and never mutated.
struct AttestationSpec {
    RequestStep[]  steps;
    DataBinding[]  bindings;
    uint8          deliverableSourceStep;
    address        customVerifier;
    bool           configured;
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
 *     → _postFund: store the spec immutably (client-only by core semantics).
 *  4. Off-chain: provider drives each step's HTTPS call through a zkTLS
 *     attestor and collects one Attestation per step.
 *  5. submit(jobId, deliverable, optParams=abi.encode(Attestation[], bytes))
 *     → _preSubmit:
 *        (a) for each step i, IZkTlsVerifier.verifyAttestation(atts[i]) via
 *            staticcall, then enforce every non-zero pinned-field hash plus
 *            timestamp window and pinnedAttestor (if set);
 *        (b) for each binding, assert the declared bytes appear as a
 *            substring of both atts[fromStep].data and
 *            atts[toStep].request.{url|header|body};
 *        (c) bind the deliverable:
 *            keccak256(bytes(atts[sourceStep].data)) == deliverable;
 *        (d) if customVerifier != 0, delegate to it for business-level
 *            checks via staticcall.
 *  6. complete / reject — normal flow.
 *
 * TRUST MODEL
 * -----------
 * The hook validates ATTESTATION SHAPE AND BINDING only:
 *  - Every step produced a valid zkTLS attestation per the pluggable verifier.
 *  - URLs, methods, bodies, response-resolve arrays, and additionParams hash
 *    to what the spec pinned (zero means "don't pin this field").
 *  - Static binding values declared in the spec appear in both source and
 *    destination attestations.
 *  - The deliverable hash binds to the source step's parsed data.
 *
 * The hook DOES NOT enforce:
 *  - Semantic correctness of returned data — use customVerifier for ranges,
 *    thresholds, or cross-field arithmetic.
 *  - Dynamic per-execution data flow — bindings carry static expected bytes.
 *  - Authentication of the external API beyond what the zkTLS verifier itself
 *    attests to (TLS PKI + the verifier's attestor set).
 *
 * The client must:
 *  - Choose a zkTLS verifier they trust; the verifier address is fixed at
 *    hook deployment, so trust is bounded to "this hook + that verifier".
 *  - Pin every per-step field that matters for the use case (URL, method,
 *    body, response shape, additionParams — the last carries algorithm-mode
 *    declarations so pinning it defends against algorithm downgrades).
 *  - Set pinnedAttestor on a step to forbid attestor rotation by the verifier
 *    owner for that step.
 *  - Provide a customVerifier for domain-level checks (price bands,
 *    multi-step aggregation, etc.).
 *
 * Per-job spec is frozen at fund time. The hook is immutable; to change
 * behaviour, deploy a new hook and rotate the whitelist.
 */
contract ZkTlsAttestationHook is BaseERC8183Hook, IERC8183HookMetadata {
    /// @notice Pluggable zkTLS verifier. Fixed at deployment.
    address public immutable zkTlsVerifier;

    mapping(uint256 => AttestationSpec) private _specs;
    mapping(uint256 => bytes32) public envelopeCommitments;

    error InvalidZkTlsVerifier();
    error SpecAlreadyConfigured();
    error SpecNotConfigured();
    error EmptySteps();
    error TooManySteps();
    error TooManyBindings();
    error InvalidDeliverableSourceStep();
    error InvalidBinding();
    error InvalidLocation();
    error StepCountMismatch();
    error AttestationVerifierFailed();
    error MethodHashMismatch();
    error UrlHashMismatch();
    error BodyHashMismatch();
    error ResponseResolveHashMismatch();
    error AdditionParamsHashMismatch();
    error AttestationStale();
    error PinnedAttestorMismatch();
    error DataBindingViolated();
    error DeliverableMismatch();
    error ExtensionVerifierFailed();
    error AlreadyValidated();

    /// @dev Bound to keep gas of a single submit tractable. Spec authors who
    ///      need wider pipelines should compose multiple jobs.
    uint256 public constant MAX_STEPS    = 16;
    uint256 public constant MAX_BINDINGS = 32;

    event SpecConfigured(uint256 indexed jobId, uint256 stepCount, uint256 bindingCount, address customVerifier);
    event AttestationsValidated(uint256 indexed jobId, bytes32 indexed deliverable, bytes32 envelope, uint256 stepCount);

    /// @param erc8183Contract_ ERC-8183 core address.
    /// @param zkTlsVerifier_   Address of an IZkTlsVerifier implementation that reverts on bad attestations.
    constructor(address erc8183Contract_, address zkTlsVerifier_) BaseERC8183Hook(erc8183Contract_) {
        if (zkTlsVerifier_ == address(0)) revert InvalidZkTlsVerifier();
        zkTlsVerifier = zkTlsVerifier_;
    }

    // --- Hook callbacks ------------------------------------------------------

    /// @dev Store the per-job attestation spec from fund's optParams. Empty optParams
    ///      is a no-op: a client that wants this hook with no zkTLS requirements
    ///      can leave it empty (in which case submit will revert SpecNotConfigured —
    ///      forcing the client to either configure it or rotate to a different hook).
    ///      Non-empty optParams locks the spec immutably; subsequent fund-with-spec
    ///      attempts are rejected (core only allows one fund per job, but the check
    ///      hardens against future protocol changes).
    function _postFund(uint256 jobId, address, bytes memory optParams) internal override {
        if (optParams.length == 0) return;

        AttestationSpec storage stored = _specs[jobId];
        if (stored.configured) revert SpecAlreadyConfigured();

        AttestationSpec memory s = abi.decode(optParams, (AttestationSpec));

        uint256 stepCount = s.steps.length;
        if (stepCount == 0) revert EmptySteps();
        if (stepCount > MAX_STEPS) revert TooManySteps();
        if (s.bindings.length > MAX_BINDINGS) revert TooManyBindings();
        if (s.deliverableSourceStep >= stepCount) revert InvalidDeliverableSourceStep();

        for (uint256 i = 0; i < s.bindings.length; ++i) {
            DataBinding memory b = s.bindings[i];
            // Forward-only ordering (fromStep < toStep) makes the static-value
            // semantics auditable; same-step or backward bindings would imply
            // a value flowing into a request that was already attested to.
            if (b.fromStep >= b.toStep) revert InvalidBinding();
            if (b.toStep >= stepCount) revert InvalidBinding();
            if (b.toLocation > 2) revert InvalidLocation();
            if (b.value.length == 0) revert InvalidBinding();
        }

        // Persist into storage. Copy the dynamic arrays element-by-element
        // because assigning a memory struct containing nested dynamic arrays
        // directly into a storage struct is not supported under all compiler
        // versions for arbitrarily nested types.
        for (uint256 i = 0; i < stepCount; ++i) {
            stored.steps.push(s.steps[i]);
        }
        for (uint256 i = 0; i < s.bindings.length; ++i) {
            stored.bindings.push(s.bindings[i]);
        }
        stored.deliverableSourceStep = s.deliverableSourceStep;
        stored.customVerifier = s.customVerifier;
        stored.configured = true;

        emit SpecConfigured(jobId, stepCount, s.bindings.length, s.customVerifier);
    }

    /// @dev Validate attestations bound to the deliverable. Reverts on any mismatch
    ///      so the submit transaction is rejected before state moves to Submitted.
    function _preSubmit(uint256 jobId, address, bytes32 deliverable, bytes memory optParams) internal override {
        AttestationSpec storage spec = _specs[jobId];
        if (!spec.configured) revert SpecNotConfigured();
        if (envelopeCommitments[jobId] != bytes32(0)) revert AlreadyValidated();

        (Attestation[] memory atts, bytes memory customCalldata) =
            abi.decode(optParams, (Attestation[], bytes));

        uint256 stepCount = spec.steps.length;
        if (atts.length != stepCount) revert StepCountMismatch();

        for (uint256 i = 0; i < stepCount; ++i) {
            _verifyOneStep(atts[i], spec.steps[i]);
        }

        uint256 bindingCount = spec.bindings.length;
        for (uint256 i = 0; i < bindingCount; ++i) {
            DataBinding memory b = spec.bindings[i];
            bytes memory src = bytes(atts[b.fromStep].data);
            bytes memory dst = _locationBytes(atts[b.toStep].request, b.toLocation);
            if (!_contains(src, b.value)) revert DataBindingViolated();
            if (!_contains(dst, b.value)) revert DataBindingViolated();
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

        bytes32 envelope = keccak256(abi.encode(jobId, deliverable, atts));
        envelopeCommitments[jobId] = envelope;
        emit AttestationsValidated(jobId, deliverable, envelope, stepCount);
    }

    // --- Internal verification ----------------------------------------------

    function _verifyOneStep(Attestation memory att, RequestStep memory step) internal view {
        // staticcall enforces the verifier's declared view-ness at the EVM level;
        // a malicious verifier cannot mutate state during attestation check.
        (bool ok, ) = zkTlsVerifier.staticcall(
            abi.encodeCall(IZkTlsVerifier.verifyAttestation, (att))
        );
        if (!ok) revert AttestationVerifierFailed();

        if (step.maxAge != 0) {
            // Use unchecked subtraction guarded by an explicit compare to avoid
            // tripping on attestations whose timestamp is somehow > block.timestamp;
            // those are stale-by-clock-skew and should also be rejected.
            if (block.timestamp < att.timestamp) revert AttestationStale();
            if (block.timestamp - att.timestamp > step.maxAge) revert AttestationStale();
        }

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

        if (step.pinnedAttestor != address(0)) {
            // Match the single-signer assumption of current zkTLS verifier
            // deployments: exactly one attestor signature is recognised.
            if (att.attestors.length != 1) revert PinnedAttestorMismatch();
            if (att.attestors[0].attestorAddr != step.pinnedAttestor) revert PinnedAttestorMismatch();
        }
    }

    function _hashResponseResolves(AttNetworkResponseResolve[] memory resolves) internal pure returns (bytes32) {
        // Encode each element distinctly so two arrays cannot collide by reordering
        // bytes across element boundaries.
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

    /// @dev Naive substring search. Bounded by MAX_STEPS * MAX_BINDINGS and the
    ///      practical size of HTTP requests / parsed JSON payloads; deliberate
    ///      simplicity over a Boyer-Moore for clarity in audit.
    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        uint256 nLen = needle.length;
        uint256 hLen = haystack.length;
        if (nLen == 0) return true;
        if (nLen > hLen) return false;
        uint256 last = hLen - nLen;
        for (uint256 i = 0; i <= last; ++i) {
            bool matched = true;
            for (uint256 j = 0; j < nLen; ++j) {
                if (haystack[i + j] != needle[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
        return false;
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
        return (s.steps, s.bindings, s.deliverableSourceStep, s.customVerifier, s.configured);
    }

    function isValidated(uint256 jobId) external view returns (bool) {
        return envelopeCommitments[jobId] != bytes32(0);
    }

    // --- IERC8183HookMetadata ------------------------------------------------

    /// @dev Configuration on fund and validation on submit must be wired together:
    ///      a router setup that runs us on submit but not on fund would leave the
    ///      submit path with no spec to validate against, silently bypassing the
    ///      contract's purpose.
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
