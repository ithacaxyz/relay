use crate::error::RelayError;
use alloy::{primitives::Address, providers::DynProvider, sol};

use super::KeyHash;

sol! {
    #[sol(rpc)]
    contract AccountRegistry {
        /// Returns the state of a given ID, including the data and accounts.
        #[derive(Debug)]
        function idInfos(address[] calldata ids) returns (bytes[] memory keyhashes, address[][] memory accounts);

        /// Registers a new ID with the given `data` and `account`.
        ///
        /// * `signature`: Signature over `keccak256(abi.encode(data, account))`. The recovered signer is the ID.
        /// * `data`: Arbitrary data blob to associate with the ID.
        /// * `account`: First account to associate with the ID.
        function register(bytes calldata signature, bytes calldata data, address account);

        /// Appends a new account to the ID. This is useful when a user wants to associate a key with multiple accounts.
        ///
        /// We require the caller of this method to be an already registered account.
        /// * `id`: Inititalized ID to append the account to.
        /// * `account`: Account to append to the ID.
        function appendAccount(address id, address account) external;

        /// Removes the account from the ID. This is useful when a user wants to disassociate a key from an account.
        ///
        /// Must be invoked by the account itself.
        function removeAccount(address id) external;
    }
}

impl AccountRegistry::AccountRegistryCalls {
    /// Returns all accounts with these IDs in a list of tuples: `Option<(KeyHash, Vec<Address>)>`.
    ///
    /// Note: the returned list will always have the same length as `ids`. If any ID does not exist,
    /// it's returned as `None`.
    pub async fn id_infos(
        ids: Vec<Address>,
        entrypoint: Address,
        provider: DynProvider,
    ) -> Result<Vec<Option<(KeyHash, Vec<Address>)>>, RelayError> {
        AccountRegistry::AccountRegistryInstance::new(entrypoint, provider)
            .idInfos(ids.clone())
            .call()
            .await
            .map_err(|err| RelayError::InternalError(err.into()))
            .map(|res| {
                res.keyhashes
                    .into_iter()
                    .zip(res.accounts)
                    .map(|(key_hash, accounts)| {
                        if key_hash.len() != 32 {
                            return None;
                        }
                        Some((KeyHash::from_slice(&key_hash), accounts))
                    })
                    .collect()
            })
    }
}
