use super::{
    super::signers::{DynSigner, Eip712PayLoadSigner, P256Key, P256Signer, WebAuthnSigner},
    U40,
    rpc::{AuthorizeKey, CallKey, Permission, RevokeKey},
};
use IDelegation::getKeysReturn;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{
        Address, B256, Bytes, FixedBytes, Keccak256, U256, bytes::Buf, keccak256, map::B256Map,
    },
    signers::local::LocalSigner,
    sol,
    sol_types::{SolStruct, SolValue},
};
use serde::{Deserialize, Serialize};
use std::{ops::Deref, sync::Arc};

/// Alias type for key hash.
pub type KeyHash = B256;

/// Alias type for key id.
pub type KeyID = Address;

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
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct Key {
        /// Unix timestamp at which the key expires (0 = never).
        #[serde(default)]
        uint40 expiry;
        /// Type of key. See the {KeyType} enum.
        #[serde(rename = "type")]
        KeyType keyType;
        /// Whether the key is a super admin key.
        /// Super admin keys are allowed to call into super admin functions such as
        /// `authorize` and `revoke` via `execute`.
        #[serde(rename = "role", with = "crate::serde::key_role")]
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

    /// The signature of a [`Intent`].
    struct Signature {
        bytes innerSignature;
        bytes32 keyHash;
        bool prehash;
    }

    /// Delegation interface.
    interface IDelegation {
        /// Authorizes the key.
        function authorize(Key memory key) public virtual returns (bytes32 keyHash);

        /// Revokes the key.
        function revoke(bytes32 keyHash) public virtual onlyThis;

        /// Returns arrays of all (non-expired) authorized keys and their hashes.
        function getKeys() returns (Key[] memory keys, bytes32[] memory keyHashes);
    }
}

impl getKeysReturn {
    /// Converts [`getKeysReturn`] into a list of tuples: `Vec<(B256, Key)>`
    pub fn into_tuples(self) -> impl Iterator<Item = (B256, Key)> {
        self.keyHashes.into_iter().zip(self.keys)
    }
}

impl KeyType {
    /// Whether it is [`Self::Secp256k1`].
    pub fn is_secp256k1(&self) -> bool {
        matches!(self, Self::Secp256k1)
    }

    /// Whether it is [`Self::P256`].
    pub fn is_p256(&self) -> bool {
        matches!(self, Self::P256)
    }

    /// Whether it is [`Self::WebAuthnP256`].
    pub fn is_webauthn(&self) -> bool {
        matches!(self, Self::WebAuthnP256)
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

    /// Create a new key webauthn key.
    pub fn webauthn(public_key: Bytes, expiry: U40, super_admin: bool) -> Self {
        Self {
            publicKey: public_key,
            expiry,
            keyType: KeyType::WebAuthnP256,
            isSuperAdmin: super_admin,
        }
    }

    /// The key hash.
    ///
    /// The hash is computed as `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
    pub fn hash(key_type: KeyType, public_key: &[u8]) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(B256::with_last_byte(key_type as u8));
        hasher.update(keccak256(public_key));
        hasher.finalize()
    }

    /// The key hash.
    ///
    /// The hash is computed as `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
    pub fn key_hash(&self) -> B256 {
        Self::hash(self.keyType, &self.publicKey)
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
    ///    `uint72(bytes9(keccak256("PORTO_ACCOUNT_STORAGE")))` ([`PORTO_ACCOUNT_STORAGE_SLOT`]).
    /// 1. Compute the storage slot for `keyStorage` in the contract, which is at
    ///    `PORTO_ACCOUNT_STORAGE_SLOT + 4` (`key_storage_slot`).
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
            &(PORTO_ACCOUNT_STORAGE_SLOT + PORTO_KEY_STORAGE_SLOT_OFFSET).to_be_bytes(),
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

/// Helper type that contains a [`Key`] and its [`Eip712PayLoadSigner`] signer.
#[derive(Debug, Clone)]
pub struct KeyWith712Signer {
    /// A key that can be used to authorize call.
    key: Key,
    /// Signer associated with the key that signs eip712
    signer: Arc<dyn Eip712PayLoadSigner>,
    /// Key permissions in case it's not an admin key.
    permissions: Vec<Permission>,
}

impl KeyWith712Signer {
    /// Returns a random non admin [`Self`] from a [`KeyType`].
    pub fn random_session(key_type: KeyType) -> eyre::Result<Option<Self>> {
        let mut key = Self::random_admin(key_type)?.unwrap();
        key.key.isSuperAdmin = false;
        Ok(Some(key))
    }

    /// Returns a random admin [`Self`] from a [`KeyType`].
    pub fn random_admin(key_type: KeyType) -> eyre::Result<Option<Self>> {
        Self::mock_admin_with_key(key_type, B256::random())
    }

    /// Returns a admin [`Self`] from a [`KeyType`].
    ///
    /// This is intended for testing.
    pub fn mock_admin_with_key(key_type: KeyType, mock_key: B256) -> eyre::Result<Option<Self>> {
        let expiry = U40::ZERO;
        let super_admin = true;

        let (key, signer) = match key_type {
            KeyType::P256 => {
                let signer = P256Signer::load(&mock_key)?;
                (
                    Key::p256(signer.public_key(), expiry, super_admin),
                    Arc::new(signer) as Arc<dyn Eip712PayLoadSigner>,
                )
            }
            KeyType::WebAuthnP256 => {
                let signer = WebAuthnSigner::load(&mock_key)?;
                (
                    Key::webauthn(signer.public_key(), expiry, super_admin),
                    Arc::new(signer) as Arc<dyn Eip712PayLoadSigner>,
                )
            }
            KeyType::Secp256k1 => {
                let signer = DynSigner(Arc::new(LocalSigner::from_bytes(&mock_key)?));
                (
                    Key::secp256k1(signer.address(), expiry, super_admin),
                    Arc::new(signer.clone()) as Arc<dyn Eip712PayLoadSigner>,
                )
            }
            _ => return Ok(None),
        };

        Ok(Some(KeyWith712Signer { key, signer, permissions: vec![] }))
    }

    /// Returns [`KeyWith712Signer`] with additional permissions.
    pub fn with_permissions(mut self, permissions: Vec<Permission>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Encodes and signs the typed data according to [EIP-712].
    ///
    /// [EIP-712]: https://eips.ethereum.org/EIPS/eip-712
    pub async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> eyre::Result<Bytes> {
        self.signer.sign_payload_hash(payload.eip712_signing_hash(domain)).await
    }

    /// Returns a reference to the inner [`Key`].
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Returns a [`CallKey`].
    pub fn to_call_key(&self) -> CallKey {
        CallKey { key_type: self.keyType, public_key: self.publicKey.clone(), prehash: false }
    }

    /// Returns a [`AuthorizeKey`] equivalent.
    pub fn to_authorized(&self) -> AuthorizeKey {
        AuthorizeKey { key: self.key.clone(), permissions: self.permissions.clone() }
    }

    /// Returns its [`RevokeKey`].
    pub fn to_revoked(&self) -> RevokeKey {
        RevokeKey { hash: self.key_hash() }
    }
}

#[async_trait::async_trait]
impl Eip712PayLoadSigner for KeyWith712Signer {
    async fn sign_payload_hash(&self, payload_hash: B256) -> eyre::Result<Bytes> {
        Ok(self.signer.sign_payload_hash(payload_hash).await?)
    }
}

impl Deref for KeyWith712Signer {
    type Target = Key;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

/// The offset for storage slots in the Porto delegation contract.
///
/// Equivalent to `uint72(bytes9(keccak256("PORTO_ACCOUNT_STORAGE")))`
pub const PORTO_ACCOUNT_STORAGE_SLOT: u128 = 1293779133171170665679;

/// The offset for the `keyStorage` variable in the `DelegationStorage` struct in the delegation
/// contract.
pub const PORTO_KEY_STORAGE_SLOT_OFFSET: u128 = 4;

#[cfg(test)]
mod tests {
    use super::{Key, KeyType};
    use crate::types::U40;
    use alloy::{
        hex,
        primitives::{b256, map::HashMap},
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
                b256!("0x22e9b02827ae1b9352e2477471a8eba480f98ced116c8ef37c042c3a95d13a24"),
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
                    b256!("0x7e8bef5aab303a0f409ba1799a7b87091449f8d19d9d67b94db017e2e516dddc"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe26")
                ),
                (
                    b256!("0x87722af65ab80f4e75613cd2f3adde1844853f8a17c3fc8bde542c0f34ab61f2"),
                    b256!("0x0000000000020100000000000000000000000000000000000000000000000000")
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
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da99419e"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da99419b"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da99419d"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da99419a"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da99419f"),
                    b256!("0x0000000000020100000000000000000000000000000000000000000000000000")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da99419c"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da994197"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x001d224e9921f1f32ba73624ac02453ab8f2fa6f2bbac3e1a15846a89eaaa410"),
                    b256!("0x00000000000000000000000000000000000000000000000000000000000107ff")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da994198"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                ),
                (
                    b256!("0x5bc8e0a914ee7aea266bca0eb7c8c9354e5c3905c6a292c44a5b0f38da994199"),
                    b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                )
            ])
        );
    }

    #[test]
    fn serialize_admin_key() {
        let key = Key {
            expiry: U40::ZERO,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: true,
            publicKey: hex!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe" // 31 bytes
            )
            .into(),
        };

        let serialized = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serialized,
            r#"{"expiry":"0x0","type":"secp256k1","role":"admin","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"}"#
        );
    }

    #[test]
    fn serialize_normal_key() {
        let key = Key {
            expiry: U40::ZERO,
            keyType: KeyType::Secp256k1,
            isSuperAdmin: false,
            publicKey: hex!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe" // 31 bytes
            )
            .into(),
        };

        let serialized = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serialized,
            r#"{"expiry":"0x0","type":"secp256k1","role":"normal","publicKey":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe"}"#
        );
    }
}
