# ERC-8001 Test Suite

This directory contains comprehensive tests for the ERC-8001 integration with ERC-8183 hooks.

## Test Files

### `ERC8001.t.sol`
Tests for the base ERC8001 coordination contract:
- **Propose Coordination**: Valid proposals, expired intents, nonce validation, participant canonicalization
- **Accept Coordination**: Single acceptance, all accepted, duplicate prevention, non-participant rejection
- **Execute Coordination**: Successful execution, not ready rejection
- **Cancel Coordination**: Proposer cancellation, non-proposer rejection, post-expiry cancellation
- **View Functions**: Intent hashing, required acceptances, expiry status

### `ERC8001CoordinationHook.t.sol`
Tests for the ERC-8183 hook integration:
- **Hook Callbacks**: `_preComplete` and `_preReject` validation
- **Coordination Flow**: Propose → Accept → Execute → Complete/Reject
- **Integration Tests**: Full end-to-end flows with AgenticCommerceHooked
- **Access Control**: Client/provider restrictions, evaluator permissions
- **State Management**: Job state validation, coordination lifecycle

## Running Tests

### Prerequisites

Install Foundry:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Install dependencies:
```bash
forge install
```

### Run All Tests

```bash
forge test
```

### Run Specific Test File

```bash
forge test --match-path test/ERC8001.t.sol
forge test --match-path test/ERC8001CoordinationHook.t.sol
```

### Run with Verbose Output

```bash
forge test -vvv
```

### Run with Gas Report

```bash
forge test --gas-report
```

### Run Coverage

```bash
forge coverage
```

## Test Structure

Each test follows the pattern:
1. **Setup**: Deploy contracts, create accounts, fund wallets
2. **Action**: Execute the function being tested
3. **Assertion**: Verify state changes, events, and reverts

## Key Test Scenarios

### Happy Path
- Create job with ERC8001CoordinationHook
- Provider submits work
- Client proposes coordination for complete
- All participants accept
- Coordination executed (Ready state)
- Evaluator completes job
- Payment released to provider

### Error Cases
- Complete without coordination → `CoordinationNotReady`
- Propose as non-client/provider → `OnlyClientOrProvider`
- Duplicate acceptance → `ERC8001_DuplicateAcceptance`
- Cancel before expiry as non-proposer → `ERC8001_NotProposer`

### Edge Cases
- Job without hook (no coordination required)
- Coordination for reject allows complete (and vice versa)
- Expired coordination status

## Gas Optimization Notes

The hook is designed to minimize gas usage:
- Only 3 storage slots per job coordination
- Complex logic delegated to external ERC-8001 contract
- View functions for off-chain status checks

## Security Considerations Tested

- **EIP-712 Signature Verification**: All signatures validated
- **Participant Canonicalization**: Sorted unique addresses enforced
- **Nonce Monotonicity**: Strictly increasing nonces per agent
- **Expiry Validation**: Both intent and acceptance expiries checked
- **Access Control**: Only authorized parties can propose/accept/execute
