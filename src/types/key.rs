use alloy::{
    primitives::{bytes::Buf, keccak256, map::B256Map, Bytes, FixedBytes, Keccak256, B256, U256},
    sol,
    sol_types::SolValue,
};

sol! {
    /// The type of key.
    enum KeyType {
        P256,
        WebAuthnP256,
        Secp256k1
    }

    /// A key that can be used to authorize call.
    struct Key {
        /// Unix timestamp at which the key expires (0 = never).
        uint40 expiry;
        /// Type of key. See the {KeyType} enum.
        KeyType keyType;
        /// Whether the key is a super admin key.
        /// Super admin keys are allowed to call into super admin functions such as
        /// `authorize` and `revoke` via `execute`.
        bool isSuperAdmin;
        /// Public key in encoded form.
        bytes publicKey;
    }

    /// The data layout of a key for packed ABI encoding. This is the field order in storage.
    ///
    /// # Note
    ///
    /// This has the same fields as [`Key`], just in a different order.
    struct PackedKey {
        /// Public key in encoded form.
        bytes publicKey;
        /// Unix timestamp at which the key expires (0 = never).
        uint40 expiry;
        /// Type of key. See the {KeyType} enum.
        KeyType keyType;
        /// Whether the key is a super admin key.
        /// Super admin keys are allowed to call into super admin functions such as
        /// `authorize` and `revoke` via `execute`.
        bool isSuperAdmin;
    }
}

impl From<Key> for PackedKey {
    fn from(Key { publicKey, expiry, keyType, isSuperAdmin }: Key) -> Self {
        Self { publicKey, expiry, keyType, isSuperAdmin }
    }
}

impl Key {
    /// The key hash.
    ///
    /// The hash is computed as `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
    pub fn key_hash(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(B256::with_last_byte(self.keyType as u8));
        hasher.update(keccak256(self.publicKey.as_ref()));
        hasher.finalize()
    }

    /// Get the storage slots and storage values for this key as it would be encoded in the
    /// delegation contract.
    ///
    /// The derivation is a bit involved:
    ///
    /// 1. Compute the offset for the contract storage, which is given by
    ///    `uint72(bytes9(keccak256("PORTO_DELEGATION_STORAGE")))`
    ///    ([`PORTO_DELEGATION_STORAGE_SLOT`]).
    /// 1. Compute the storage slot for `keyStorage` in the contract, which is at
    ///    `PORTO_DELEGATION_STORAGE_SLOT + 4` (`key_storage_slot`).
    /// 1. Find the seed slot of `LibBytes.BytesStorage`, which is given by
    ///
    ///    ```ignore
    ///    keccak256(abi.encode(
    ///      uint256(keyStorageMappingSlot),
    ///      keccak256(abi.encode(uint256(keyType), keccak256(publicKey)))
    ///    ))
    ///    ```
    ///
    /// If the encoded key (`key_data`) is less than 255 bytes (which is usually the case), the
    /// value of this slot will be `abi.encodePacked(key_data[0..31], uint8(key_data.length))`.
    ///
    /// Otherwise, the value at this computed slot will be
    /// `abi.encodePacked(uint248(key_data.length), uint8(0xff))`.
    ///
    /// The remaining data that does not fit into the packed representation (i.e. when the encoded
    /// key is more than 31 bytes) can be found in the extension slot onwards.
    ///
    /// The extension slot can be computed by `keccak256(abi.encode(key_bytes_slot))`.
    ///
    /// The key data is given by
    ///
    /// ```ignore
    /// abi.encodePacked(
    ///   key.publicKey, // variable bytes. length can be computed by `key_data.length - 5 - 1 - 1`.
    ///   key.expiry, // 5 bytes, big endian
    ///   key.keyType, // 1 byte
    ///   key.isSuperAdmin, // 1 byte
    /// )
    /// ```
    pub fn storage_slots(&self) -> B256Map<B256> {
        let key_storage_slot = B256::left_padding_from(
            &(PORTO_DELEGATION_STORAGE_SLOT + PORTO_KEY_STORAGE_SLOT_OFFSET).to_be_bytes(),
        );
        let bytes_seed_slot = seed_slot_for_key(key_storage_slot, self.keyType, &self.publicKey);
        let mut encoded = &PackedKey::from(self.clone()).abi_encode()[..];

        let mut slots = B256Map::default();
        slots.insert(
            bytes_seed_slot,
            if encoded.len() <= 31 {
                let value = FixedBytes::<31>::right_padding_from(&encoded[..])
                    .concat_const(FixedBytes::<1>::with_last_byte(encoded.len() as u8));
                encoded.advance(encoded.len());
                value
            } else if encoded.len() < 255 {
                // the key is less than 255 bytes, so the first slot is encoded as
                // `abi.encodePacked(encoded[0..31], encoded.length)`
                let value = FixedBytes::<31>::right_padding_from(&encoded[0..31])
                    .concat_const(FixedBytes::<1>::with_last_byte(encoded.len() as u8));
                encoded.advance(31);
                value
            } else {
                // the key is 255 bytes or more, so the first slot is encoded as
                // `abi.encodePacked(uint248(encoded.length), 0xff)`
                FixedBytes::<31>::right_padding_from(&encoded.len().to_be_bytes())
                    .concat_const(FixedBytes::<1>::with_last_byte(0xff))
            },
        );

        // the rest of the data is in the extension slot onwards
        let mut extension_slot: U256 = keccak256(bytes_seed_slot).into();
        while encoded.has_remaining() {
            let cnt = encoded.remaining().min(32);
            slots.insert(B256::from(extension_slot), B256::right_padding_from(&encoded[0..cnt]));
            encoded.advance(cnt);
            extension_slot += U256::from(1);
        }

        slots
    }
}

/// The offset for storage slots in the Porto delegation contract.
///
/// Equivalent to `uint72(bytes9(keccak256("PORTO_DELEGATION_STORAGE")))`
pub const PORTO_DELEGATION_STORAGE_SLOT: u128 = 2015112712752093870099;

/// The offset for the `keyStorage` variable in the `DelegationStorage` struct in the delegation
/// contract.
pub const PORTO_KEY_STORAGE_SLOT_OFFSET: u128 = 4;

/// Get the seed slot for the given key.
///
/// This is given by:
///
/// ```ignore
/// keyBytesSlot = keccak256(abi.encode(
///     uint256(keyStorageMappingSlot),
///     keccak256(abi.encode(uint256(keyType), keccak256(publicKey))),
/// ))
/// ```
fn seed_slot_for_key(key_storage_slot: B256, key_type: KeyType, public_key: &Bytes) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(B256::with_last_byte(key_type as u8));
    hasher.update(keccak256(public_key));
    let subkey = hasher.finalize();

    let mut hasher = Keccak256::new();
    hasher.update(key_storage_slot);
    hasher.update(subkey);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{Key, KeyType};
    use crate::types::U40;
    use alloy::{
        hex,
        primitives::{b256, Bytes},
    };

    #[test]
    fn key_hash() {
        let key = Key {
            expiry: U40::ZERO,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: true,
            publicKey: hex!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe" // 31 bytes
            )
            .into(),
        };

        assert_eq!(
            key.key_hash(),
            b256!("0xee2e71f3d36446d9154925a4d494f827bf48cb0e6badea1b2ca5620e523ad03a")
        )
    }

    #[test]
    fn storage_slots_tiny_key() {
        let key = Key {
            expiry: U40::ZERO,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: true,
            publicKey: hex!(
                "deadbeef" // 4 bytes
            )
            .into(),
        };
        let slots = key.storage_slots();

        assert_eq!(slots.len(), 1);
        // todo this should be packed
        assert_eq!(
            slots[&b256!("605fde1c52dbae8aaeafbff03828efbad65bf9f6e5fc303a738f314f8a93c677")],
            b256!("0000000000000000000000000000000000000000deadbeef000000000002010b")
        );
    }

    #[test]
    fn storage_slots_short_key() {
        let key = Key {
            expiry: U40::ZERO,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: true,
            publicKey: hex!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe" // 31 bytes
            )
            .into(),
        };
        let slots = key.storage_slots();

        assert_eq!(slots.len(), 2);
        // todo this should be packed
        assert_eq!(
            slots[&b256!("a9919a9d198a69368df813d4ace48b06d5f01e02b1ecb122cecb090a7969f9c7")],
            b256!("0000000000020100000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            slots[&b256!("1f31a7e9332a6aee0653f4e62f01461643310d7aabbb39e494a18c309ddbe00d")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe26")
        );
    }

    #[test]
    fn storage_slots_huge_key() {
        let key = Key {
            expiry: U40::ZERO,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: true,
            publicKey: hex!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 32 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 64 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 96 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 128 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 160 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 192 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 224 bytes
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" // 256 bytes
            )
            .into(),
        };
        let slots = key.storage_slots();

        assert_eq!(slots.len(), 10);
        // todo this should be packed
        assert_eq!(
            slots[&b256!("92240ffab5baf5ca6d8e63c3703089ab0ada064a2a2db6be7e97b53ab29a8a0e")],
            b256!("00000000000001070000000000000000000000000000000000000000000000ff")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f1630a")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f1630b")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f1630c")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f1630d")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f1630e")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f1630f")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f16310")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f16311")],
            b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert_eq!(
            slots[&b256!("4b6c783599a2273db37a37a7fa31a88f03b1debf725bf3f1e123557e08f16312")],
            b256!("0000000000020100000000000000000000000000000000000000000000000000")
        );
    }
}
