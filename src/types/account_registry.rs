use AccountRegistry::idInfoReturn;
use alloy::{
    primitives::{Address, B256},
    sol,
};

sol! {
    #[sol(rpc)]
    contract AccountRegistry {
        /// Returns the state of a given ID, including the data and accounts.
        #[derive(Debug)]
        function idInfo(address id) returns (bytes memory data, address[] memory accounts);

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

impl idInfoReturn {
    /// Attempts to decode response into `(B256, Vec<Address>)`, where [`B256`] is the key hash.
    pub fn try_decode(self) -> Option<(B256, Vec<Address>)> {
        if self.data.len() < 32 {
            return None;
        }
        Some((B256::from_slice(&self.data), self.accounts))
    }
}
