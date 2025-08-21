# Chainwalker

Tests interop by transferring tokens across all available chain connections.

## Quickstart

Fund one account with the token(s) of chain in one chain.

### Test specific tokens only
```bash
chainwalker --private-key $PRIVATE_KEY --only-uids "tether,ethereum"
```

### Test all tokens except certain chains
```bash
chainwalker --private-key $PRIVATE_KEY --exclude-chains "1,137"
```

## Full Options

```bash
chainwalker --help
```

### Available Options

- `--private-key KEY` - Private key of test account (required, or set PRIVATE_KEY env var)
- `--no-run` - Plan and display test sequence without executing transfers
- `--only-uids UIDs` - Only test specific interop token UIDs (comma-separated)
- `--only-chains CHAIN_IDS` - Only test specific chains (comma-separated chain IDs)
- `--exclude-chains CHAIN_IDS` - Exclude specific chains from testing (comma-separated chain IDs)
- `--force` - Continue even if account has been used before
- `--transfer-percentage N` - Percentage of balance to transfer on each hop (default: 90)
- `--skip-settlement-wait` - Skip waiting for settlement completion
- `--relay-url URL` - Relay URL (default: https://stg-rpc.ithaca.xyz)

## How it Works

Chainwalker tests cross-chain interoperability by:

1. **Discovery** - Finds all available interop tokens and their chain connections
2. **Planning** - Creates an path to visit every connecting (bidirectional)
3. **Execution** - Transfers tokens along the planned path, validating each hop
4. **Reporting** - Generates a detailed JSON report with transfer results and quotes
