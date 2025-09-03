//! Debugging utilities for cast call commands

use alloy::{
    primitives::{TxKind, hex},
    rpc::types::{TransactionRequest, state::StateOverride},
};
use std::fmt::Write;

/// Generates a cast call command string from a transaction request.
///
/// This function creates an executable cast call command that can be used
/// for debugging transaction failures. It includes all necessary parameters
/// including auth delegations and state overrides.
pub fn generate_cast_call_command(
    tx_request: &TransactionRequest,
    overrides: &StateOverride,
) -> String {
    let mut cmd = String::new();

    // Wrap in parentheses for easy copying
    write!(&mut cmd, "(cast call").unwrap();

    // Add the 'to' address
    if let Some(to) = tx_request.to {
        match to {
            TxKind::Call(addr) => write!(&mut cmd, " {}", addr).unwrap(),
            TxKind::Create => write!(&mut cmd, " --create").unwrap(),
        }
    }

    // Add the call data if present
    if let Some(data) = tx_request.input.input()
        && !data.is_empty()
    {
        write!(&mut cmd, " 0x{}", hex::encode(data)).unwrap();
    }

    // Add trace flag for better debugging
    write!(&mut cmd, " --trace").unwrap();

    // Add authorization list if present (EIP-7702 delegations)
    if let Some(auth_list) = &tx_request.authorization_list {
        for auth in auth_list {
            // RLP encode the authorization for cast
            let auth_bytes = alloy::rlp::encode(auth);
            write!(&mut cmd, " --auth 0x{}", hex::encode(auth_bytes)).unwrap();
        }
    }

    // Add other optional parameters
    if let Some(from) = tx_request.from {
        write!(&mut cmd, " --from {}", from).unwrap();
    }

    if let Some(value) = tx_request.value
        && !value.is_zero()
    {
        write!(&mut cmd, " --value {}", value).unwrap();
    }

    if let Some(gas) = tx_request.gas {
        write!(&mut cmd, " --gas-limit {}", gas).unwrap();
    }

    // Add state overrides
    for (addr, override_) in overrides {
        if let Some(balance) = &override_.balance {
            write!(&mut cmd, " --override-balance {}:{}", addr, balance).unwrap();
        }
        if let Some(nonce) = &override_.nonce {
            write!(&mut cmd, " --override-nonce {}:{}", addr, nonce).unwrap();
        }
        if let Some(code) = &override_.code {
            write!(&mut cmd, " --override-code {}:0x{}", addr, hex::encode(code)).unwrap();
        }
        if let Some(state) = &override_.state {
            for (slot, value) in state {
                write!(&mut cmd, " --override-state {}:{}:{}", addr, slot, value).unwrap();
            }
        }
        if let Some(state_diff) = &override_.state_diff {
            for (slot, value) in state_diff {
                write!(&mut cmd, " --override-state-diff {}:{}:{}", addr, slot, value).unwrap();
            }
        }
    }
    cmd
}
