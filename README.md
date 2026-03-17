# ERC-8183

**ERC-8183** — job escrow with evaluator attestation for trustless agent-to-agent commerce.

## Specification

- **[hook-profiles.md](./hook-profiles.md)** — Recommended hook profiles: A (Simple Policy), B (Advanced Escrow), C (Experimental).

## Hook Extension Contracts

| Contract                                                               | Description                                                                                                                                                                          |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **[AgenticCommerceHooked.sol](./contracts/AgenticCommerceHooked.sol)** | Hookable variant of the core protocol. Same lifecycle with an optional `hook` address per job and `optParams` on all hookable functions. `claimRefund` is deliberately not hookable. |
| **[IACPHook.sol](./contracts/IACPHook.sol)**                           | Interface all hooks must implement: `beforeAction` and `afterAction`.                                                                                                                |
| **[BaseACPHook.sol](./contracts/BaseACPHook.sol)**                     | Abstract base that routes `beforeAction`/`afterAction` to named virtual functions (`_preFund`, `_postComplete`, etc.). Inherit this and override only what you need.                 |

## Hook Examples

| Contract                                                               | Profile             | Description                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [BiddingHook.sol](./contracts/hooks/BiddingHook.sol)                   | A — Simple Policy   | Off-chain signed bidding for provider selection. Providers sign bid commitments; the hook verifies the winning signature on-chain via `setProvider`. Zero direct external calls — everything flows through core → hook callbacks.   |
| [FundTransferHook.sol](./contracts/hooks/FundTransferHook.sol)         | B — Advanced Escrow | Two-phase fund transfer for token conversion/bridging jobs. Client capital flows to provider at `fund`; provider deposits output tokens at `submit`; buyer receives them at `complete`.                                             |
| [RecurringPaymentHook.sol](./contracts/hooks/RecurringPaymentHook.sol) | B — Advanced Escrow | Subscription-gated pricing for ERC-8191 recurring payment subscribers. Active subscribers get a reduced minimum budget; lapsed subscriptions block job funding. Integrates ERC-8183 job lifecycle with ERC-8191 subscription state. |

## Building a Hook

1. Inherit `BaseACPHook` and override only the callbacks you need.
2. See [CONTRIBUTING.md](./CONTRIBUTING.md) for full guidelines.

## Contributing

Contributions, feedback, and discussion are welcome - please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

## License

MIT
