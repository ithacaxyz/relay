//! EIP-712 related helpers.

use crate::types::{Account, Entry, UserOp};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, B256, Bytes, map::AddressMap},
    providers::DynProvider,
    rpc::types::state::AccountOverride,
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
    let overrides = delegation
        .map(|delegation| {
            AddressMap::from_iter([(
                op.eoa,
                // TODO: We can't use the builder API here because we only conditionally set the
                // code.
                AccountOverride {
                    // Manually etch the 7702 designator as we do not have a signed auth item.
                    code: Some(delegation).map(|addr| {
                        Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat())
                    }),
                    ..Default::default()
                },
            )])
        })
        .unwrap_or_default();

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
