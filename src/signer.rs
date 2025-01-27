use alloy::{
    primitives::PrimitiveSignature,
    signers::{
        k256::ecdsa::{self, signature::hazmat::PrehashSigner, RecoveryId},
        local::LocalSigner,
    },
};
use jsonrpsee::core::async_trait;

use crate::types::Quote;

#[async_trait]
pub trait QuoteSigner<Signature> {
    async fn sign_quote(&self, quote: &Quote) -> alloy::signers::Result<Signature>;
}

#[async_trait]
impl<C> QuoteSigner<PrimitiveSignature> for LocalSigner<C>
where
    C: PrehashSigner<(ecdsa::Signature, RecoveryId)> + Send + Sync,
{
    async fn sign_quote(&self, quote: &Quote) -> alloy::signers::Result<PrimitiveSignature> {
        todo!()
    }
}
