//! Helpers for serialization and deserialization of entrypoint and delegation address pairs.

use crate::config::EntryWithDelegation;
use alloy::primitives::Address;
use eyre::WrapErr;
use std::str::FromStr;

/// Parse a string in the format "0xENTRYPOINT,0xDELEGATION" into an [`EntryWithDelegation`].
pub fn parse_entrypoint_with_delegation(s: &str) -> eyre::Result<EntryWithDelegation> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return Err(eyre::eyre!("Expected format ENTRYPOINT,DELEGATION"));
    }
    let entrypoint = Address::from_str(parts[0]).wrap_err("Entrypoint address parse failed.")?;
    let delegation = Address::from_str(parts[1]).wrap_err("Delegation address parse failed.")?;

    Ok(EntryWithDelegation { entrypoint, delegation })
}
