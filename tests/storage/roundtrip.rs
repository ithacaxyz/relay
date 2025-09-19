//! Storage roundtrip compatibility tests.
//!
//! CI safeguard:
//! 1. The **base** branch should run `storage::roundtrip::write`, seeding a fresh Postgres database
//!    with rows produced by the OLD code.
//! 2. The PR branch should run `storage::roundtrip::read`, which must successfully deserialize
//!    those same rows with the NEW code.
//!
//! If any migration is missing, the read step fails.

use crate::e2e::SIGNERS_MNEMONIC;
use alloy::{
    eips::{eip1559::Eip1559Estimation, eip7702::SignedAuthorization},
    network::{Ethereum, EthereumWallet, NetworkWallet},
    primitives::{Address, B256, ChainId, U256, bytes},
    rpc::types::Authorization,
};
use chrono::Utc;
use opentelemetry::Context;
use relay::{
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{PendingTransaction, RelayTransaction, RelayTransactionKind, TxId},
    types::{CreatableAccount, Intent, Quote, SignedCall, rpc::BundleId},
};
use sqlx::PgPool;
use std::ops::Not;

async fn storage() -> eyre::Result<RelayStorage> {
    // Set up storage
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("set DATABASE_URL")).await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(RelayStorage::pg(pool))
}

#[tokio::test]
#[ignore]
async fn write() -> eyre::Result<()> {
    let storage = storage().await?;
    let Fixtures { account, signer: _, chain_id: _, queued_tx, pending_tx, bundle_id, email } =
        Fixtures::generate().await?;

    // Account & Keys
    storage.write_account(account.clone()).await?;

    // Queued & Pending txs
    storage.queue_transaction(&queued_tx).await?;
    storage.replace_queued_tx_with_pending(&pending_tx).await?;

    // Create a new queued transaction with different ID and NO authorization
    let mut queued_tx_no_auth = queued_tx.clone();
    queued_tx_no_auth.id = TxId(B256::with_last_byte(3));
    if let RelayTransactionKind::Intent { authorization, .. } = &mut queued_tx_no_auth.kind {
        *authorization = None; // Set authorization to None
    }
    storage.queue_transaction(&queued_tx_no_auth).await?;

    // Create another queued transaction with Some authorization (to test both cases)
    let mut queued_tx_with_auth = queued_tx.clone();
    queued_tx_with_auth.id = TxId(B256::with_last_byte(4));
    // This one already has Some(authorization) from the clone
    storage.queue_transaction(&queued_tx_with_auth).await?;

    // Bundle status
    storage.add_bundle_tx(bundle_id, queued_tx.id).await?;

    // Email
    storage.add_unverified_email(email.0, &email.1, &email.2).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn read() -> eyre::Result<()> {
    let storage = storage().await?;
    let Fixtures { account, signer, chain_id, queued_tx: _, pending_tx: _, bundle_id, email } =
        Fixtures::generate().await?;

    // Account & Keys
    assert!(storage.read_account(&account.address).await?.is_some());

    // Queued & Pending txs
    assert!(storage.read_queued_transactions(chain_id).await?.is_empty().not());
    assert!(storage.read_pending_transactions(signer, chain_id).await?.is_empty().not());

    // Bundle status
    assert!(storage.get_bundle_transactions(bundle_id).await?.is_empty().not());

    // Email
    storage.verify_email(email.0, &email.1, &email.2).await?;
    storage.verified_email_exists(&email.2).await?;

    Ok(())
}

struct Fixtures {
    pub account: CreatableAccount,
    pub signer: Address,
    pub chain_id: ChainId,
    pub queued_tx: RelayTransaction,
    pub pending_tx: PendingTransaction,
    pub bundle_id: BundleId,
    pub email: (Address, String, String),
}

impl Fixtures {
    async fn generate() -> eyre::Result<Self> {
        let signer = DynSigner::derive_from_mnemonic(SIGNERS_MNEMONIC.parse()?, 1)?.pop().unwrap();
        let r_address = signer.address();

        let signer = EthereumWallet::new(signer.0);
        let r_u256 = U256::MAX;
        let r_b256 = B256::ZERO;
        let r_u64 = u64::MAX;
        let r_bytes = bytes!("aaaaaaaaaa");
        let r_fee = Eip1559Estimation { max_fee_per_gas: 1, max_priority_fee_per_gas: 1 };
        let authorization = SignedAuthorization::new_unchecked(
            Authorization { chain_id: r_u256, address: r_address, nonce: r_u64 },
            1,
            r_u256,
            r_u256,
        );
        let pre_call = SignedCall {
            eoa: r_address,
            executionData: r_bytes.clone(),
            nonce: r_u256,
            signature: r_bytes.clone(),
        };
        let account = CreatableAccount::new(r_address, pre_call, authorization.clone());
        let intent = Intent::latest()
            .with_eoa(r_address)
            .with_execution_data(r_bytes.clone())
            .with_nonce(r_u256)
            .with_payer(r_address)
            .with_payment_token(r_address)
            .with_pre_payment_max_amount(r_u256)
            .with_total_payment_max_amount(r_u256)
            .with_combined_gas(r_u256)
            .with_encoded_pre_calls(vec![r_bytes.clone()])
            .with_pre_payment_amount(r_u256)
            .with_total_payment_amount(r_u256)
            .with_payment_recipient(r_address)
            .with_signature(r_bytes.clone())
            .with_payment_signature(r_bytes.clone())
            .with_supported_account_implementation(r_address)
            .with_encoded_fund_transfers(vec![r_bytes.clone()])
            .with_funder(r_address)
            .with_funder_signature(r_bytes.clone())
            .with_settler(r_address)
            .with_expiry(r_u256)
            .with_settler_context(r_bytes.clone());
        let quote = Quote {
            chain_id: r_u64,
            intent,
            extra_payment: r_u256,
            eth_price: r_u256,
            payment_token_decimals: 1,
            tx_gas: r_u64,
            native_fee_estimate: r_fee,
            authorization_address: Some(r_address),
            additional_authorization: None,
            orchestrator: r_address,
            fee_token_deficit: r_u256,
            asset_deficits: Default::default(),
        };
        let queued_id = B256::with_last_byte(1);
        let queued_tx = RelayTransaction {
            id: TxId(queued_id),
            kind: RelayTransactionKind::Intent {
                quote: Box::new(quote),
                authorization: vec![authorization.clone()],
                eip712_digest: r_b256,
            },
            trace_context: Context::current(),
            received_at: Utc::now(),
        };

        let pending_id = B256::with_last_byte(2);
        let pending_tx = {
            let mut tx = queued_tx.clone();
            tx.id = TxId(pending_id);
            tx
        };
        let pending_tx = PendingTransaction {
            sent: vec![
                NetworkWallet::<Ethereum>::sign_transaction_from(
                    &signer,
                    r_address,
                    queued_tx.build(r_u64, r_fee),
                )
                .await?,
            ],
            tx: pending_tx,
            signer: r_address,
            sent_at: Utc::now(),
        };

        Ok(Self {
            account,
            signer: r_address,
            chain_id: r_u64,
            queued_tx,
            pending_tx,
            bundle_id: BundleId(r_b256),
            email: (r_address, "hello@there.all".to_string(), "12345678".to_string()),
        })
    }
}
