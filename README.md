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

The hookable core protocol (`AgenticCommerce`) and the base hook interface (`IERC8183Hook`) live in the [base-contracts submodule](./contracts/erc8183/).

## Hook Examples

| Contract | Profile | Description |
|----------|---------|-------------|
| [BiddingHook.sol](./contracts/hooks/BiddingHook.sol) | A — Simple Policy | Off-chain signed bidding for provider selection. Providers sign bid commitments; the hook verifies the winning signature on-chain via `setProvider`. Zero direct external calls — everything flows through core → hook callbacks. |
| [FundTransferHook.sol](./contracts/hooks/FundTransferHook.sol) | B — Advanced Escrow | Two-phase fund transfer for token conversion/bridging jobs. Client capital flows to provider at `fund`; provider deposits output tokens at `submit`; buyer receives them at `complete`. |

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
