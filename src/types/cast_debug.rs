//! Debugging utilities for cast call commands

use alloy::{
    primitives::{TxKind, hex},
    rpc::types::{TransactionRequest, state::StateOverride},
};

/// Generates a cast call command string from a transaction request.
///
/// This function creates an executable cast call command that can be used
/// for debugging transaction failures. It includes all necessary parameters
/// including auth delegations and state overrides.
pub fn generate_cast_call_command(
    tx_request: &TransactionRequest,
    overrides: &StateOverride,
) -> String {
    let mut cmd = String::from("(cast call");

    // Add the 'to' address
    if let Some(to) = tx_request.to {
        match to {
            TxKind::Call(addr) => cmd.push_str(&format!(" {}", addr)),
            TxKind::Create => cmd.push_str(" --create"),
        }
    }

    // Add the call data if present
    if let Some(data) = tx_request.input.input()
        && !data.is_empty()
    {
        cmd.push_str(&format!(" {}", data));
    }

    // Add trace flag for better debugging
    cmd.push_str(" --trace");

    // Add authorization list if present (EIP-7702 delegations)
    if let Some(auth_list) = &tx_request.authorization_list {
        for auth in auth_list {
            // RLP encode the authorization for cast
            let auth_bytes = alloy::rlp::encode(auth);
            cmd.push_str(&format!(" --auth 0x{}", hex::encode(auth_bytes)));
        }
    }

    // Add other optional parameters
    if let Some(from) = tx_request.from {
        cmd.push_str(&format!(" --from {}", from));
    }

    if let Some(value) = tx_request.value
        && !value.is_zero()
    {
        cmd.push_str(&format!(" --value {}", value));
    }

    if let Some(gas) = tx_request.gas {
        cmd.push_str(&format!(" --gas-limit {}", gas));
    }

    // Add state overrides
    for (addr, override_) in overrides {
        if let Some(balance) = &override_.balance {
            cmd.push_str(&format!(" --override-balance {}:{}", addr, balance));
        }
        if let Some(nonce) = &override_.nonce {
            cmd.push_str(&format!(" --override-nonce {}:{}", addr, nonce));
        }
        if let Some(code) = &override_.code {
            cmd.push_str(&format!(" --override-code {}:{}", addr, code));
        }
        if let Some(state) = &override_.state {
            for (slot, value) in state {
                cmd.push_str(&format!(" --override-state {}:{}:{}", addr, slot, value));
            }
        }
        if let Some(state_diff) = &override_.state_diff {
            for (slot, value) in state_diff {
                cmd.push_str(&format!(" --override-state-diff {}:{}:{}", addr, slot, value));
            }
        }
    }
    cmd
}
