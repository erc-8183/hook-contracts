# ERC-8183

**ERC-8183** — job escrow with evaluator attestation for trustless agent-to-agent commerce.

## Specification

- **[hook-profiles.md](./hook-profiles.md)** — Recommended hook profiles: A (Simple Policy), B (Advanced Escrow), C (Experimental).

## Hook Extension Contracts

| Contract | Description |
|----------|-------------|
| **[BaseERC8183Hook.sol](./contracts/BaseERC8183Hook.sol)** | Abstract base that routes `beforeAction`/`afterAction` to named virtual functions (`_preFund`, `_postComplete`, etc.). Inherit this and override only what you need. |
| **[IERC8183HookMetadata.sol](./contracts/interfaces/IERC8183HookMetadata.sol)** | Required metadata interface for MultiHookRouter compatibility. Declares which selectors a hook depends on. |
| **[MultiHookRouter.sol](./contracts/hooks/MultiHookRouter.sol)** | Composability layer. Fans `beforeAction`/`afterAction` out to an ordered list of sub-hooks per job, per selector. |

The hookable core protocol (`ERC8183`) and the base hook interface (`IERC8183Hook`) live in the [base-contracts submodule](./contracts/erc8183/).

## Hook Examples

| Contract | Profile | Description |
|----------|---------|-------------|
| [BiddingHook.sol](./contracts/hooks/BiddingHook.sol) | A — Simple Policy | Off-chain signed bidding for provider selection. Providers sign bid commitments; the hook verifies the winning signature on-chain via `setProvider`. Zero direct external calls — everything flows through core → hook callbacks. |
| [FundTransferHook.sol](./contracts/hooks/FundTransferHook.sol) | B — Advanced Escrow | Two-phase fund transfer for token conversion/bridging jobs. Client capital flows to provider at `fund`; provider deposits output tokens at `submit`; buyer receives them at `complete`. |
| [PrivacyHook.sol](./contracts/hooks/PrivacyHook.sol) | C — Experimental | Encrypted-envelope submissions. Providers encrypt deliverables off-chain with AES-256-GCM and submit an IPFS CID with ECDH-wrapped AES keys per recipient; the hook validates envelope structure on-chain and optionally verifies a ZK proof over the encrypted data. |
| [ZkTlsAttestationHook.sol](./contracts/hooks/ZkTlsAttestationHook.sol) | A — Simple Policy | zkTLS attestation binding for jobs whose deliverable is derived from off-chain HTTPS calls. The client pins each step's URL/method/body/response-shape and cross-step value bindings at `fund`; the provider attaches one zkTLS attestation per step at `submit`; the hook routes every attestation through a pluggable `IZkTlsVerifier`, enforces the pinned shape, and binds the deliverable to the parsed response. Optional `IAttestationExtensionVerifier` handles business-level checks. |

## Building a Hook

1. Inherit `BaseERC8183Hook` and override only the callbacks you need.
2. Implement `IERC8183HookMetadata` so the hook is MultiHookRouter-compatible.
3. Keep the hook in a single `.sol` file with any custom interfaces inlined.
4. Stay vendor-neutral — no specific token, exchange, or vendor names.
5. See [CONTRIBUTING.md](./CONTRIBUTING.md) for full PR guidelines.

## Contributing

Contributions, feedback, and discussion are welcome — please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to get started.

## License

MIT
