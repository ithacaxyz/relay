//! EIP-712 related helpers.

use crate::types::{Account, Entry, UserOp};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, B256, Bytes},
    providers::DynProvider,
    rpc::types::state::{AccountOverride, StateOverridesBuilder},
    sol_types::SolStruct,
};
use tracing::error;

/// Computes the EIP-712 digest that the user must sign.
///
/// If a delegation is passed it will override the EOA account and manually etch the 7702
/// designator. Otherwise, it will assumed it's already delegated.
///
/// Returns the eip712 digest that user will need to sign.
pub async fn compute_eip712_digest(
    op: &UserOp,
    provider: &DynProvider,
    delegation: Option<Address>,
) -> eyre::Result<B256> {
    // Create the account override mapping.
    let overrides = StateOverridesBuilder::default()
        .apply(|overrides| {
            let Some(delegation) = delegation else { return overrides };
            overrides.append(
                op.eoa,
                AccountOverride::default()
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    .with_code(Bytes::from(
                        [&EIP7702_DELEGATION_DESIGNATOR, delegation.as_slice()].concat(),
                    )),
            )
        })
        .build();

    // Create an account instance with the provided overrides.
    let account = Account::new(op.eoa, provider).with_overrides(overrides.clone());

    // Retrieve the entrypoint address.
    let entrypoint_address = account.entrypoint().await.inspect_err(|err| {
        error!(%err, "Failed to obtain entrypoint from account.");
    })?;

    // Create the entrypoint instance with the same overrides.
    let entrypoint = Entry::new(entrypoint_address, provider).with_overrides(overrides);

    // Prepare the EIP-712 payload and domain
    let payload = op.as_eip712()?;
    let domain = entrypoint.eip712_domain(op.is_multichain()).await?;

    // Return the computed signing hash (digest).
    Ok(payload.eip712_signing_hash(&domain))
}
