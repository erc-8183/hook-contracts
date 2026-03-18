# ERC-8183

**ERC-8183** — job escrow with evaluator attestation for trustless agent-to-agent commerce.

## Specification

- **[hook-profiles.md](./hook-profiles.md)** — Recommended hook profiles: A (Simple Policy), B (Advanced Escrow), C (Experimental).

## Hook Extension Contracts

| Contract | Description |
|----------|-------------|
| **[AgenticCommerceHooked.sol](./contracts/AgenticCommerceHooked.sol)** | Hookable variant of the core protocol. Same lifecycle with an optional `hook` address per job and `optParams` on all hookable functions. `claimRefund` is deliberately not hookable. |
| **[IACPHook.sol](./contracts/IACPHook.sol)** | Interface all hooks must implement: `beforeAction` and `afterAction`. |
| **[BaseACPHook.sol](./contracts/BaseACPHook.sol)** | Abstract base that routes `beforeAction`/`afterAction` to named virtual functions (`_preFund`, `_postComplete`, etc.). Inherit this and override only what you need. |

## Hook Examples

| Contract | Profile | Description |
|----------|---------|-------------|
| [BiddingHook.sol](./contracts/hooks/BiddingHook.sol) | A — Simple Policy | Off-chain signed bidding for provider selection. Providers sign bid commitments; the hook verifies the winning signature on-chain via `setProvider`. Zero direct external calls — everything flows through core → hook callbacks. |
| [FundTransferHook.sol](./contracts/hooks/FundTransferHook.sol) | B — Advanced Escrow | Two-phase fund transfer for token conversion/bridging jobs. Client capital flows to provider at `fund`; provider deposits output tokens at `submit`; buyer receives them at `complete`. |
| [ERC8001CoordinationHook.sol](./contracts/hooks/ERC8001CoordinationHook.sol) | B — Advanced Escrow | Multi-party coordination for job completion/rejection using ERC-8001 standard. Requires cryptographic consensus from all participants before `complete` or `reject` can execute. Delegates coordination logic to external ERC-8001 contract. |

## Building a Hook

1. Inherit `BaseACPHook` and override only the callbacks you need.
2. See [CONTRIBUTING.md](./CONTRIBUTING.md) for full guidelines.

## Testing

This project uses [Foundry](https://book.getfoundry.sh/) for testing.

### Setup

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
forge install
```

### Run Tests

```bash
# Run all tests
forge test

# Run with verbose output
forge test -vvv

# Run specific test file
forge test --match-path test/ERC8001.t.sol
forge test --match-path test/ERC8001CoordinationHook.t.sol

# Generate coverage report
forge coverage
```

See [test/README.md](./test/README.md) for detailed test documentation.

## Contributing

Contributions, feedback, and discussion are welcome - please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

## License

MIT
