# Overview

## Servers

| Name    | URL                              | Description                             |
|---------|----------------------------------|-----------------------------------------|
| Staging | https://relay-staging.ithaca.xyz | The staging server for the Ithaca Relay |

## Methods

### `relay_estimateFee`

Lorem ipsum dolor sit amet.

#### Parameters

| Name          | Type                  | Description                                  |
|---------------|-----------------------|----------------------------------------------|
| action        | [`Action`](#action)   | The action to estimate the fee for           |
| token address | address               | The token address to pay the fee in          |
| auth address  | address               | The address to delegate the account to       |

#### Response

- [`SignedQuote`](#signedquote)

#### Errors

## Types

### `Action`

```typescript
type Action = {
    op: {
        eoa: address
        executionData: hex
        nonce: uint256
        payer: address
        paymentToken: address
        paymentRecipient: address
        paymentAmount: uint256
        paymentMaxAmount: uint256
        paymentPerGas: uint256
        combinedGas: uint256
        signature: hex
    }
    chainId: number
}
```

### `SignedQuote`

```typescript
type SignedQuote = {
    token: address
    amount: u256
    gasEstimate: u64
    nativeFeeEstimate: {
        
    }
    digest: bytes32
    ttl: u64
    authorizationAddress?: address
}
```
