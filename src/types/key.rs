use alloy::{
    primitives::{
        bytes::Buf, keccak256, map::B256Map, Address, Bytes, FixedBytes, Keccak256, B256, U256,
    },
    sol,
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};

use super::U40;

sol! {
    /// The type of key.
    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum KeyType {
        /// A P256 key.
        P256,
        /// A passkey.
        WebAuthnP256,
        /// An Ethereum key.
        Secp256k1
    }

    /// A key that can be used to authorize call.
    #[derive(Debug)]
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

    /// The signature of a [`UserOp`].
    struct Signature {
        bytes innerSignature;
        bytes32 keyHash;
        bool prehash;
    }

    /// Delegation interface.
    interface IDelegation {
        /// Authorizes the key.
        function authorize(Key memory key) public virtual returns (bytes32 keyHash);
        /// (GuardedExecutor) Sets the ability of a key hash to execute a call with a function selector.
        function setCanExecute(bytes32 keyHash, address target, bytes4 fnSel, bool can);
    }
}

impl KeyType {
    /// Whether it is [`Self::Secp256k1`].
    pub fn is_secp256k1(&self) -> bool {
        matches!(self, Self::Secp256k1)
    }
}

impl From<Key> for PackedKey {
    fn from(Key { publicKey, expiry, keyType, isSuperAdmin }: Key) -> Self {
        Self { publicKey, expiry, keyType, isSuperAdmin }
    }
}

impl Key {
    /// Create a new key secp256k1 key.
    pub fn secp256k1(address: Address, expiry: U40, super_admin: bool) -> Self {
        Self {
            publicKey: address.abi_encode().into(),
            expiry,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: super_admin,
        }
    }

    /// Create a new key p256 key.
    pub fn p256(public_key: Bytes, expiry: U40, super_admin: bool) -> Self {
        Self { publicKey: public_key, expiry, keyType: KeyType::P256, isSuperAdmin: super_admin }
    }

    /// The key hash.
    ///
    /// The hash is computed as `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
    pub fn key_hash(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(B256::with_last_byte(self.keyType as u8));
        hasher.update(keccak256(self.publicKey.as_ref()));
        hasher.finalize()
    }

    /// Get the seed slot for the given key.
    ///
    /// This is given by:
    ///
    /// ```ignore
    /// keyBytesSlot = keccak256(abi.encode(
    ///     keccak256(abi.encode(uint256(keyType), keccak256(publicKey))),
    ///     uint256(keyStorageMappingSlot),
    /// ))
    /// ```
    fn seed_slot_for_key(&self, key_storage_slot: B256) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.key_hash());
        hasher.update(key_storage_slot);
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
        let bytes_seed_slot = self.seed_slot_for_key(key_storage_slot);
        let mut encoded = &PackedKey::from(self.clone()).abi_encode_packed()[..];

        let mut slots = B256Map::default();
        slots.insert(
            bytes_seed_slot,
            if encoded.len() <= 31 {
                let value = FixedBytes::<31>::right_padding_from(encoded)
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
                FixedBytes::<31>::left_padding_from(&encoded.len().to_be_bytes())
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

#[cfg(test)]
mod tests {
    use super::{Key, KeyType};
    use crate::types::U40;
    use alloy::{
        hex,
        primitives::{b256, map::HashMap, B256},
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

        assert_eq!(
            key.storage_slots(),
            HashMap::from_iter([(
                b256!("0x1e260793a6006dc7ff4e003f7855f86b42eafb769191a50456b8eef0a9fbec8d"),
                b256!("0xdeadbeef0000000000020100000000000000000000000000000000000000000b")
            ),])
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

        assert_eq!(
            key.storage_slots(),
            HashMap::from_iter([
                (
                    b256!("66660046373aa54db720a1e783350b8b72164124dec4ac0f440c8280fa5cab06"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe26")
                ),
                (
                    b256!("f8ae8897de7599677a07b826c5e75519342a40c2478792c35966af4e7ac921eb"),
                    b256!("0000000000020100000000000000000000000000000000000000000000000000")
                ),
            ])
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

        assert_eq!(
            key.storage_slots(),
            HashMap::from_iter([
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a18"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("68a02f4387b8eb2b560b17dd43f66a22b7800a81babf3c2b943967ae533a7cdd"),
                    B256::left_padding_from(&67583u64.to_be_bytes())
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a1d"),
                    b256!("0000000000020100000000000000000000000000000000000000000000000000")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a19"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a1a"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a1c"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a17"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a1b"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a16"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("1610841431194ef3ae25b820417d532867656a25f8a6b7d60f407be1302a0a15"),
                    b256!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                )
            ])
        );
    }
}
