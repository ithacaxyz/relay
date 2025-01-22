# Porto Relay

A transparent cross-chain transaction router for EIP-7702 accounts, specifically built for [Porto](https://github.com/ithacaxyz/porto).

## Testing

```sh
cargo test
```

## Deploying

A docker image is built and pushed to AWS ECR when a git tag (`vx.y.z`) is pushed to the repository. The image triggers an AWS AppRunner deployment.
