# Ithaca Relay

A transparent cross-chain transaction router for EIP-7702 accounts, specifically built for [Porto](https://github.com/ithacaxyz/porto).

## Table of Contents

- [Running](#running)
- [Testing](#testing)
    - [End-to-End](#end-to-end)
- [Deploying](#deploying)

## Running

To run the relay, you can either use Docker or run the binary directly.

1. Deploy the [delegation and entrypoint contracts](https://github.com/ithacaxyz/account) on the destination chain.
1. Deploy or identify at least one token to accept as fee token(s).
1. Generate two private keys, one for transaction signing, and one for quote signing. You can do this with `cast wallet new`.

Run the relay, passing in the following flags. In the example below, the binary will be run directly with `cargo`:

```sh
cargo run --bin relay -- \
    --endpoint $RPC_URL \ # You can pass this multiple times
    --fee-token $FEE_TOKEN_ADDR \ # You can pass this multiple times
    --secret-key $TX_SIGNING_PRIV_KEY \
    --quote-secret-key $QUOTE_SIGNING_PRIV_KEY
```

If no `--config` flag is given, a default `relay.toml` is created in the working directory. In both cases, if the file doesn’t exist, it will be created from the CLI arguments; if it does, its values are loaded and overridden by any CLI flags, *without* updating the file.

Example:
```toml
[server]
address = "127.0.0.1"
port = 8323

[chain]
endpoints = ["http://localhost:8545/"]
fee_tokens = ["0x706aa5c8e5cc2c67da21ee220718f6f6b154e75c"]

[quote]
ttl = 5
# constant_rate = 1.0 # should be used ONLY for testing

[quote.gas]
user_op_buffer = 25000
tx_buffer = 1000000

[coin_registry]
```


## Testing

```sh
cargo test
```

### End-to-End

End-to-end tests use [ithacaxyz/account](https://github.com/ithacaxyz/account) under a git submodule located at `tests/account`. These tests depend on building certain these contracts.


1. **Prerequisites**

   Make sure [Foundry](https://getfoundry.sh/) is installed and available in your PATH.

2. **Pull `ithacaxyz/account`**

   ```bash
   git submodule update --init --recursive
   ```

3. **Build the contracts**

   ```bash
   $ cd tests/account
   $ forge build && forge build lib/solady/test/utils/mocks/MockERC20.sol
   ```

4. **Run the Tests**

   You can run the tests still in the same directory as before.

   ```bash
    $ TEST_CONTRACTS=$(pwd)/out cargo test -- e2e
   ```

   More advanced options are available through the following environment variables with `.env` support.
   - `TEST_CONTRACTS`: Directory for contract artifacts (defaults to `tests/account/out`).
   - `TEST_EXTERNAL_ANVIL`: Use an external node instead of spawning Anvil.
   - `TEST_FORK_URL` / `TEST_FORK_BLOCK_NUMBER`: Fork settings for the Anvil spawned by the test.
   - `TEST_EOA_PRIVATE_KEY`: Private key for the EOA signer (defaults to `EOA_PRIVATE_KEY`).
   - `TEST_ENTRYPOINT`: Address for EntryPoint contract; deploys a mock if unset.
   - `TEST_DELEGATION`: Address for Delegation contract; deploys a mock if unset.
   - `TEST_ERC20`: Address for the payment ERC20 token; deploys a mock if unset.

## Deploying

A docker image is built and pushed to AWS ECR when a git tag (`vx.y.z`) is pushed to the repository. The image triggers an AWS AppRunner deployment.
