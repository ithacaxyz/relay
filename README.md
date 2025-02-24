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
    $ CONTRACTS=$(pwd)/out cargo test -- e2e
   ```

## Deploying

A docker image is built and pushed to AWS ECR when a git tag (`vx.y.z`) is pushed to the repository. The image triggers an AWS AppRunner deployment.
