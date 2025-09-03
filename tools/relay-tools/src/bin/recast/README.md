# recast

CLI tool for sending tokens via Ithaca relay.

## Quick Start

```bash
# Send 100 USDC (not wei) on Base
recast send --uid usdc --to 0xd8da6bf26964af9d7eed9e03e53415d37aa96045 --amount 100 --chain 8453

# Send 0.1 USDC (not wei) on Base with debug output
recast send --uid eth --to 0xd8da6bf26964af9d7eed9e03e53415d37aa96045 --amount 0.1 --chain 8453 --debug
```

## Help

```
$ recast send --help
Send tokens using the Ithaca relay

Usage: recast send [OPTIONS] --uid <UID> --to <ADDRESS> --amount <AMOUNT> --chain <CHAIN_ID>

Options:
      --uid <UID>              Token UID (e.g., "tether", "teth")
      --to <ADDRESS>           Recipient address
      --amount <AMOUNT>        Amount to send (in ether units, e.g., "1.5" for 1.5 ether)
      --chain <CHAIN_ID>       Chain ID
      --fee-uid <UID>          Fee token UID (defaults to the transfer token)
      --private-key <KEY>      Private key of the sender [env: PRIVATE_KEY]
      --relay-url <RELAY_URL>  Relay URL [default: https://stg-rpc.ithaca.xyz]
      --debug                  Enable debug output
  -h, --help                   Print help
```