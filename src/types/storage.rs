use crate::types::{KeyHashWithID, PREPAccount};

/// CreateAccount request that can be reused across chains.
#[derive(Debug, Clone)]
pub struct CreatableAccount {
    /// PREP account.
    pub prep: PREPAccount,
    /// Admin key identifiers with the signature over the PREP account address.
    pub id_signatures: Vec<KeyHashWithID>,
}

impl CreatableAccount {
    /// Return a new [`CreateAccount`].
    pub fn new(account: PREPAccount, id_signatures: Vec<KeyHashWithID>) -> Self {
        Self { prep: account, id_signatures }
    }
}
