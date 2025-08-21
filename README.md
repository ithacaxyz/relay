# Ithaca Relay

A transparent cross-chain transaction router for EIP-7702 accounts, specifically built for [Porto](https://github.com/ithacaxyz/porto).

## Table of Contents

- [Running](#running)
- [Testing](#testing)
    - [End-to-End](#end-to-end)
- [Deploying](#deploying)

## Running

To run the relay, you can either use Docker or run the binary directly.

### Prerequisites

The relay depends on the following things being available on the chains it connects to:

- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) is enabled.
- [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) is enabled.
- [`eth_simulateV1`](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-eth#eth-simulate-v1) is enabled, *or* [`debug_traceCall`](https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug#debugtracecall) with log collection support.
- The [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) secp256r1 precompile is available, *or* a [shim](https://vectorized.github.io/solady/#/utils/p256?id=p256) is deployed[^1].
- [Multicall3](https://www.multicall3.com/)
- `PUSH0`

Additionally, the relay can also leverage several things for faster confirmations and increased reliability, including:

- [Flashblocks](https://docs.base.org/base-chain/flashblocks/apps)
- Using sequencer endpoints

These things must be enabled in the configuration.

[^1]: If the secp256r1 precompile is enabled, the address `0x0000000000001Ab2e8006Fd8B71907bf06a5BDEE` must additionally be a contract. This acts as a canary signalling the Solady P256 library that the precompile exists. If the canary is not deployed, the shim will be tried first. See [Solady's P256 library](https://github.com/Vectorized/solady/blob/a096f4fb0f65d1c6d6677ea6b13e9d41cb0bf798/src/utils/P256.sol#L19-L25).

### Deployment

1. Deploy the [delegation and orchestrator contracts](https://github.com/ithacaxyz/account) on the destination chain.
1. Deploy or identify at least one token to accept as fee token(s).
1. Generate two private keys, one for transaction signing, and one for quote signing. You can do this with `cast wallet new`.

Run the relay, passing in the following flags. In the example below, the binary will be run directly with `cargo`:

```sh
cargo run --bin relay -- \
    --endpoint $RPC_URL \ # You can pass this multiple times
    --fee-token $FEE_TOKEN_ADDR \ # You can pass this multiple times
    --signers-mnemonic $SIGNING_KEY_MNEMONIC \
    --config $CONFIG_PATH
```

The relay reads its configuration from the file located at `--config` (default `relay.yaml`). If it does not exist, it will be created from CLI arguments.

The precedence for config is: CLI > environment variables > configuration file.

#### Configuration examples

Below are some example configs with explanations on how they work. For a complete config for running the relay locally, see [`relay.example.yaml`](./relay.example.yaml).

##### Minimal

A minimal configuration for a single chain.

```yaml
fee_recipient: "0x0000000000000000000000000000000000000000"

orchestrator: "0x"
delegation_proxy: "0x"
simulator: "0x"
escrow: "0x"
funder: "0x"

chains:
  # The key is either a chain ID, or a chain name.
  ethereum:
    endpoint: "wss://eth.rpc.com/"
    assets:
      ethereum:
        # Address 0 denotes the native asset and it must be present, even if it is not a fee token.
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
      usd-coin:
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        fee_token: true
```

##### Interop

A minimal configuration for interop between two chains, i.e. liquidity can move between them.

```yaml
fee_recipient: "0x0000000000000000000000000000000000000000"

orchestrator: "0x"
delegation_proxy: "0x"
simulator: "0x"
escrow: "0x"
funder: "0x"

chains:
  ethereum:
    endpoint: "wss://eth.rpc.com/"
    # Settler address is required for chains with interop-enabled assets
    settler_address: "0x1234567890123456789012345678901234567890"
    assets:
      ethereum:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
        # Assets with this flag can be relayed across chains.
        interop: true
      usd-coin:
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        fee_token: true
        interop: true
  optimism:
    endpoint: "wss://op.rpc.com/"
    # Each chain can have its own settler address
    settler_address: "0x0987654321098765432109876543210987654321"
    assets:
      ethereum:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
        interop: true
      usd-coin:
        address: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"
        fee_token: true
        interop: true

# For interop to work, a settler must be configured. This example uses the simple settler.
interop:
  settler:
    wait_verification_timeout: 100000
    simple:
      # Note: settler_address has been moved to per-chain configuration
      private_key: "0x..."  # Optional: private key for simple settler
```

##### Cross environment

A minimal configuration where the relay supports two chains, but they are not interopable, i.e. liquidity cannot move between them. This is useful if you want to support the same accounts on two different environments (testnet and mainnet).

```yaml
fee_recipient: "0x0000000000000000000000000000000000000000"

orchestrator: "0x"
delegation_proxy: "0x"
simulator: "0x"
escrow: "0x"
funder: "0x"

pricefeed:
  coingecko:
    # Remaps asset UIDs to CoinGecko coin IDs.
    #
    # If not specified, the UID is used as the coin ID.
    #
    # See <https://docs.coingecko.com/reference/coins-list>
    remapping:
      teth: "ethereum"
      tusdc: "usd-coin"

chains:
  ethereum:
    endpoint: "wss://eth.rpc.com/"
    assets:
      ethereum:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
      usd-coin:
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        fee_token: true
  # Sepolia and Base Sepolia can still interop.
  # Notice how Ether and USDC have different identifiers. This prevents them from being
  # relayed across chains on different environments.
  sepolia:
    endpoint: "wss://sepolia.rpc.com/"
    # Settler address for Sepolia testnet
    settler_address: "0xabcdef1234567890abcdef1234567890abcdef12"
    assets:
      teth:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
        interop: true
      tusdc:
        address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
        fee_token: true
        interop: true
  base-sepolia:
    endpoint: "wss://base-sepolia.rpc.com/"
    # Settler address for Base Sepolia testnet
    settler_address: "0x1234567890abcdef1234567890abcdef12345678"
    assets:
      teth:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
        interop: true
      tusdc:
        address: "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"
        fee_token: true
        interop: true

interop:
  settler:
    wait_verification_timeout: 100000
    simple:
      # Note: settler_address has been moved to per-chain configuration
      private_key: "0x..."  # Optional: private key for simple settler
```

##### Chain-specific fee Configuration

A configuration which has different chain-specific fee settings

```yaml
fee_recipient: "0x0000000000000000000000000000000000000000"

orchestrator: "0x"
delegation_proxy: "0x"
simulator: "0x"
escrow: "0x"
funder: "0x"

chains:
  ethereum:
    endpoint: "wss://eth.rpc.com/"
    settler_address: "0x1234567890123456789012345678901234567890"
    assets:
      ethereum:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
        interop: true
      usd-coin:
        address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        fee_token: true
        interop: true
    fees:
        # This will be used to calculate the minimum signer balance, it represents the min gas the
        # signer should be able to pay for
        signer_balance_config: 
            type: gas
            value: 10000000
        minimum_fee: 100
  optimism:
    endpoint: "wss://op.rpc.com/"
    settler_address: "0x0987654321098765432109876543210987654321"
    assets:
      ethereum:
        address: "0x0000000000000000000000000000000000000000"
        fee_token: true
        interop: true
      usd-coin:
        address: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"
        fee_token: true
        interop: true
    fees:
        # If a signer balance is below this value, it will become paused. This is in wei
        signer_balance_config:
            type: balance
            value: 10000000000
        # optional, the minimum fee to set in wei
        minimum_fee: 100
        # optional, the amount to multiply the min signer balance when determining how much to fund
        # the account by when it is paused. The default is 3
        top_up_multiplier: 2

interop:
  settler:
    wait_verification_timeout: 100000
    simple:
      # Note: settler_address has been moved to per-chain configuration
      private_key: "0x..."  # Optional: private key for simple settler
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
