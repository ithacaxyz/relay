# Ithaca Relay

A transparent cross-chain transaction router for EIP-7702 accounts, specifically built for [Porto](https://github.com/ithacaxyz/porto).

## Table of Contents

- [Running](#running)
- [Testing](#testing)
    - [End-to-End](#end-to-end)
- [Deploying](#deploying)

## Running

To run the relay, you can either use Docker or run the binary directly.

1. Deploy the [delegation and orchestrator contracts](https://github.com/ithacaxyz/account) on the destination chain.
1. Deploy or identify at least one token to accept as fee token(s).
1. Generate two private keys, one for transaction signing, and one for quote signing. You can do this with `cast wallet new`.

Run the relay, passing in the following flags. In the example below, the binary will be run directly with `cargo`:

```sh
cargo run --bin relay -- \
    --endpoint $RPC_URL \ # You can pass this multiple times
    --fee-token $FEE_TOKEN_ADDR \ # You can pass this multiple times
    --signers-mnemonic $SIGNING_KEY_MNEMONIC \
    # --registry $REGISTRY_PATH  # Maps chain ids and token addresses to coins (eg. ETH, USDC, USDT).
    # --config $CONFIG_PATH
```

If no `--config` flag is given, a default `relay.yaml` is created in the working directory. In both cases, if the file doesn’t exist, it will be created from the CLI arguments; if it does, its values are loaded and overridden by any CLI flags, *without* updating the file.

Similarly, if no `--registry` flag is given, a default registry configuration file `registry.yaml` is created in the working directory.

Examples:

```yaml
# relay.yaml

server:
    address: "127.0.0.1"
    port: 8323

chain:
    endpoints:
        - "http://localhost:8545/"
    fee_tokens:
        - "0x706aa5c8e5cc2c67da21ee220718f6f6b154e75c"
quote:
    ttl: 5
    gas:
        intent_buffer: 25000
        tx_buffer: 1000000
```

## Testing

```sh
cargo test
```

### End-to-End

End-to-end tests use [ithacaxyz/account](https://github.com/ithacaxyz/account) under a git submodule located at `tests/account`. These tests depend on building certain these contracts.

#### Prerequisites

- Make sure [`forge`](https://getfoundry.sh/) is installed and available in your PATH.
- Make sure [`cargo-nextest`](https://nextest.rs) is installed an available in your PATH.
- Pull `ithacaxyz/account`

   ```bash
   git submodule update --init --recursive
   ```

#### Running

From the repository root, use the xtask command which automatically builds contracts and runs tests:

```bash
cargo e2e
```

You can pass additional arguments to `cargo test`:

```bash
cargo e2e -- --nocapture --test-threads=1
```

##### Environment Variables

Both approaches support the following environment variables with `.env` support:
- `TEST_CONTRACTS`: Directory for contract artifacts (defaults to `tests/account/out`).
- `TEST_EXTERNAL_ANVIL`: Use an external node for chain 0 instead of spawning Anvil (alias for `TEST_EXTERNAL_ANVIL_0`).
- `TEST_EXTERNAL_ANVIL_N`: Use an external node for chain N (e.g., `TEST_EXTERNAL_ANVIL_0`, `TEST_EXTERNAL_ANVIL_1`).
  - Note: `TEST_EXTERNAL_ANVIL_0` takes precedence over `TEST_EXTERNAL_ANVIL` if both are set.
- `TEST_FORK_URL` / `TEST_FORK_BLOCK_NUMBER`: Fork settings for locally spawned Anvil instances.
- `TEST_EOA_PRIVATE_KEY`: Private key for the EOA signer (defaults to `EOA_PRIVATE_KEY`).
- `TEST_ORCHESTRATOR`: Address for Orchestrator contract; deploys a mock if unset.
- `TEST_PROXY`: Address for proxy contract; deploys a mock if unset.
- `TEST_ERC20`: Address for the payment ERC20 token; deploys a mock if unset.
- `TEST_ERC721`: Address for the ERC721 token; deploys a mock if unset.

Example multi-chain test setup:
```bash
# Chain 0: External Anvil
TEST_EXTERNAL_ANVIL_0="http://localhost:8545" \
# Chain 1: Spawns locally (no external specified)
# Chain 2: Different external Anvil
TEST_EXTERNAL_ANVIL_2="http://localhost:8547" \
cargo test test_multichain
```

## Deploying

A docker image is built and pushed to GitHub Packages (`ghcr.io/ithacaxyz/relay`) when a git tag (`vx.y.z`) is pushed to the repository. For deployment details, see the [infrastructure repository](https://github.com/ithacaxyz/infrastructure).
