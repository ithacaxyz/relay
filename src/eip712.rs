//! EIP-712 related helpers.

use crate::types::{Entry, UserOp};
use alloy::{
    primitives::{Address, B256},
    providers::DynProvider,
    sol_types::SolStruct,
};

/// Computes the EIP-712 digest that the user must sign.
///
/// If a delegation is passed it will override the EOA account and manually etch the 7702
/// designator. Otherwise, it will assumed it's already delegated.
///
/// Returns the eip712 digest that user will need to sign.
pub async fn compute_eip712_digest(
    op: &UserOp,
    entrypoint_address: Address,
    provider: &DynProvider,
) -> eyre::Result<B256> {
    // Create the entrypoint instance with the same overrides.
    let entrypoint = Entry::new(entrypoint_address, provider);

    // Prepare the EIP-712 payload and domain
    let payload = op.as_eip712()?;
    let domain = entrypoint.eip712_domain(op.is_multichain()).await?;

    // Return the computed signing hash (digest).
    Ok(payload.eip712_signing_hash(&domain))
}
