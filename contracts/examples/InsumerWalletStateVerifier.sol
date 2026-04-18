// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IWalletStateVerifier.sol";

/// @title InsumerWalletStateVerifier
/// @notice Reference IWalletStateVerifier implementation bridging off-chain wallet-state
///         attestations to on-chain lookups.
///
/// @dev Integration flow:
///   1. Off-chain: caller obtains a signed attestation for (wallet, conditionSet) from an
///      attestation service that returns per-condition pass/fail results plus an ECDSA
///      P-256 signature (ES256) over the payload, and publishes its JWKS.
///   2. A relayer pushes (wallet, conditionsHash, verified, validUntil) plus optionally
///      the P-256 signature components via submitAttestation().
///   3. If a public key is configured at construction, the service signature is verified
///      via the RIP-7212 P256VERIFY precompile. Otherwise the relayer is trusted.
///   4. Hooks (e.g. WalletStateHook) read checkWalletState() to gate job lifecycle actions.
///
///   RIP-7212 P256VERIFY availability: Base, Optimism, Arbitrum, Polygon, Scroll, ZKsync,
///   Celo, and other L2s — matches the typical ERC-8183 deployment footprint.
///
/// Getting credentials (free tier available, no credit card):
///
///   Developers (email-based):
///     POST https://api.insumermodel.com/v1/keys/create
///     body: {"email":"YOUR_EMAIL","appName":"erc8183-hooks","tier":"free"}
///     Free tier: 100 daily reads + 10 attestation credits.
///
///   Agents (wallet-based, no email):
///     POST https://api.insumermodel.com/v1/keys/buy
///     body: {"txHash":"0x...","chainId":8453,"amount":5,"appName":"my-agent"}
///     Agent sends USDC or USDT (Base/Optimism/Arbitrum/Polygon/Solana and more)
///     or BTC to the platform wallet, then POSTs the tx hash — the sending
///     wallet is the identity, no email needed. Stablecoin is auto-detected from
///     the transfer log. Minimum 5 stablecoin units; credits scale with amount.
///
///   API reference:      https://insumermodel.com/developers/api-reference/
///   Attestation:        POST https://api.insumermodel.com/v1/attest
///   JWKS (public key):  https://insumermodel.com/.well-known/jwks.json
/// @custom:audit status=unaudited
contract InsumerWalletStateVerifier is IWalletStateVerifier {
    struct Attestation {
        bool verified;
        uint256 validUntil;
    }

    error NotRelayer();
    error NotOwner();
    error ZeroAddress();
    error InvalidSignature();

    event AttestationSubmitted(
        address indexed wallet,
        bytes32 indexed conditionsHash,
        bool verified,
        uint256 validUntil
    );
    event RelayerUpdated(address indexed oldRelayer, address indexed newRelayer);

    /// @dev RIP-7212 P256VERIFY precompile address
    address constant P256_VERIFIER = address(0x0100);

    /// @dev Attestation service P-256 public key coordinates (0,0 to skip verification)
    uint256 public immutable pubKeyX;
    uint256 public immutable pubKeyY;

    /// @dev Whether on-chain signature verification is enabled
    bool public immutable verifySignatures;

    /// @dev Authorized relayer address
    address public relayer;

    /// @dev Contract owner (can update relayer)
    address public owner;

    /// @dev Stored attestations keyed by (wallet, conditionsHash)
    mapping(address => mapping(bytes32 => Attestation)) private _attestations;

    /// @param _relayer  Authorized relayer address
    /// @param _pubKeyX  X coordinate of attestation service public key (0 to skip verification)
    /// @param _pubKeyY  Y coordinate of attestation service public key (0 to skip verification)
    constructor(address _relayer, uint256 _pubKeyX, uint256 _pubKeyY) {
        if (_relayer == address(0)) revert ZeroAddress();
        relayer = _relayer;
        owner = msg.sender;
        pubKeyX = _pubKeyX;
        pubKeyY = _pubKeyY;
        verifySignatures = _pubKeyX != 0 && _pubKeyY != 0;
    }

    /// @inheritdoc IWalletStateVerifier
    function checkWalletState(address wallet, bytes32 conditionsHash)
        external
        view
        override
        returns (bool verified, uint256 validUntil)
    {
        Attestation memory a = _attestations[wallet][conditionsHash];
        return (a.verified, a.validUntil);
    }

    /// @notice Push an attestation result on-chain.
    /// @param wallet The wallet the attestation refers to.
    /// @param conditionsHash Hash identifying the condition set evaluated.
    /// @param verified Whether the wallet passed all conditions in the set.
    /// @param validUntil Unix timestamp when the attestation expires.
    /// @param r P-256 signature r component (ignored if !verifySignatures)
    /// @param s P-256 signature s component (ignored if !verifySignatures)
    /// @param messageHash SHA-256 of the signed attestation payload (ignored if !verifySignatures)
    function submitAttestation(
        address wallet,
        bytes32 conditionsHash,
        bool verified,
        uint256 validUntil,
        bytes32 r,
        bytes32 s,
        bytes32 messageHash
    ) external {
        if (msg.sender != relayer) revert NotRelayer();
        if (verifySignatures) {
            if (!_verifyP256(messageHash, r, s)) revert InvalidSignature();
        }
        _attestations[wallet][conditionsHash] = Attestation({
            verified: verified,
            validUntil: validUntil
        });
        emit AttestationSubmitted(wallet, conditionsHash, verified, validUntil);
    }

    /// @notice Update the authorized relayer address.
    function setRelayer(address _relayer) external {
        if (msg.sender != owner) revert NotOwner();
        if (_relayer == address(0)) revert ZeroAddress();
        emit RelayerUpdated(relayer, _relayer);
        relayer = _relayer;
    }

    /// @dev Verify P-256 signature using RIP-7212 precompile.
    ///      Input layout: messageHash || r || s || x || y (5 x 32 bytes).
    ///      Returns true iff the precompile returned 1.
    function _verifyP256(bytes32 messageHash, bytes32 r, bytes32 s) internal view returns (bool) {
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encodePacked(messageHash, r, s, pubKeyX, pubKeyY)
        );
        return success && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }
}
