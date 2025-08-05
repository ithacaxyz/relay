//! RPC account-related request and response types.

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

use crate::types::Asset;

/// Address-based asset or native.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum AddressOrNative {
    /// Address.
    Address(Address),
    /// The special keyword `"native"`.
    #[serde(rename = "native")]
    Native,
}

impl AddressOrNative {
    /// Returns the address
    ///
    /// # Panics
    /// It will panic if self is of the native variant.
    pub fn address(&self) -> Address {
        match self {
            AddressOrNative::Address(address) => *address,
            AddressOrNative::Native => Address::ZERO,
        }
    }
}

impl From<AddressOrNative> for Asset {
    fn from(value: AddressOrNative) -> Self {
        match value {
            AddressOrNative::Address(address) => Asset::Token(address),
            AddressOrNative::Native => Asset::Native,
        }
    }
}

impl From<Address> for AddressOrNative {
    fn from(value: Address) -> Self {
        if value.is_zero() { Self::Native } else { Self::Address(value) }
    }
}
