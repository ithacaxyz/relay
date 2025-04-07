use crate::e2e::{
    MockErc20,
    environment::{Environment, EnvironmentConfig},
    send_prepared_calls,
};
use alloy::{
    consensus::Transaction,
    primitives::{Address, B256, U256},
    providers::{PendingTransactionBuilder, Provider, ext::AnvilApi},
    sol_types::{SolCall, SolValue},
};
use eyre::Context;
use futures_util::future::{join_all, try_join_all};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    transactions::{RelayTransaction, TransactionStatus},
    types::{
        Call, KeyType, KeyWith712Signer, Signature,
        rpc::{
            CreateAccountParameters, KeySignature, Meta, PrepareCallsCapabilities,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCreateAccountCapabilities,
            PrepareCreateAccountParameters, PrepareCreateAccountResponse,
        },
    },
};
use std::time::Duration;
use tokio::sync::mpsc;

/// An account that can be used to send userops.
struct MockAccount {
    address: Address,
    key: KeyWith712Signer,
}

impl MockAccount {
    /// Creates a new account by going through PREP flow.
    async fn new(env: &Environment) -> eyre::Result<Self> {
        let key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256).unwrap().unwrap();

        let PrepareCreateAccountResponse { context, address, .. } = env
            .relay_endpoint
            .prepare_create_account(PrepareCreateAccountParameters {
                capabilities: PrepareCreateAccountCapabilities {
                    authorize_keys: vec![key.to_authorized(None).await?],
                    delegation: env.delegation,
                },
                chain_id: env.chain_id,
            })
            .await
            .unwrap();

        // Using ETH for payments
        env.provider.anvil_set_balance(address, U256::from(100e18)).await?;

        let signature = key.id_sign(address).await.unwrap();

        env.relay_endpoint
            .create_account(CreateAccountParameters {
                context,
                signatures: vec![KeySignature {
                    public_key: key.publicKey.clone(),
                    key_type: key.keyType,
                    value: signature.as_bytes().into(),
                    prehash: false,
                }],
            })
            .await
            .unwrap();

        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![Call {
                    to: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::mintCall { a: address, val: U256::from(100e18) }
                        .abi_encode()
                        .into(),
                }],
                chain_id: env.chain_id,
                from: address,
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_token: Address::ZERO, key_hash: key.key_hash(), nonce: None },
                    pre_ops: vec![],
                    pre_op: false,
                    revoke_keys: vec![],
                },
            })
            .await
            .unwrap();

        let signature = key.sign_payload_hash(digest).await?;

        let tx_hash = send_prepared_calls(env, &key, signature, context).await.unwrap();

        let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
            .get_receipt()
            .await
            .wrap_err("Failed to get receipt")?;

        assert!(receipt.status());

        Ok(MockAccount { address, key })
    }

    /// Prepares a simple transaction from the account which is ready to be sent to the transacton
    /// service.
    async fn prepare_tx(&self, env: &Environment) -> RelayTransaction {
        let PrepareCallsResponse { mut context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![],
                chain_id: env.chain_id,
                from: self.address,
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta {
                        fee_token: Address::ZERO,
                        key_hash: self.key.key_hash(),
                        nonce: None,
                    },
                    pre_ops: vec![],
                    pre_op: false,
                    revoke_keys: vec![],
                },
            })
            .await
            .unwrap();

        context.ty_mut().op.signature = Signature {
            innerSignature: self.key.sign_payload_hash(digest).await.unwrap(),
            keyHash: self.key.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into();

        RelayTransaction::new(context, env.entrypoint, None)
    }
}

/// Waits for a final transaction status.
async fn wait_for_tx(mut events: mpsc::UnboundedReceiver<TransactionStatus>) -> TransactionStatus {
    while let Some(status) = events.recv().await {
        if status.is_final() {
            return status;
        }
    }

    panic!("Transaction did not complete");
}

async fn wait_for_tx_hash(events: &mut mpsc::UnboundedReceiver<TransactionStatus>) -> B256 {
    while let Some(status) = events.recv().await {
        match status {
            TransactionStatus::Pending(hash) => return hash,
            TransactionStatus::Failed(err) => panic!("transacton failed {err}"),
            _ => {}
        }
    }

    panic!("failed to get tx hash")
}

/// Asserts that transaction was confirmed.
async fn assert_failed(events: mpsc::UnboundedReceiver<TransactionStatus>, error: &str) {
    match wait_for_tx(events).await {
        TransactionStatus::Failed(err) => {
            assert!(err.to_string().contains(error));
        }
        TransactionStatus::Confirmed(_) => panic!("expected failure"),
        _ => unreachable!(),
    }
}

/// Asserts that transaction was confirmed.
async fn assert_confirmed(events: mpsc::UnboundedReceiver<TransactionStatus>) -> B256 {
    match wait_for_tx(events).await {
        TransactionStatus::Confirmed(hash) => hash,
        TransactionStatus::Failed(err) => panic!("transacton failed {err}"),
        _ => unreachable!(),
    }
}

/// Asserts that metrics match the expected values.
fn assert_metrics(sent: usize, confirmed: usize, failed: usize, env: &Environment) {
    let output = env.relay_handle.metrics.render();
    let chain_id = env.chain_id;
    assert!(output.contains(&format!(r#"transactions_sent{{chain_id="{chain_id}"}} {sent}"#)));
    assert!(
        output.contains(&format!(r#"transactions_confirmed{{chain_id="{chain_id}"}} {confirmed}"#))
    );
    assert!(output.contains(&format!(r#"transactions_failed{{chain_id="{chain_id}"}} {failed}"#)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_concurrent() -> eyre::Result<()> {
    let env =
        Environment::setup(EnvironmentConfig { is_prep: true, block_time: Some(1) }).await.unwrap();
    let tx_service_handle = env.relay_handle.chains.get(env.chain_id).unwrap().transactions.clone();

    // setup accounts
    let num_accounts = 5;
    let accounts = try_join_all((0..num_accounts).map(|_| MockAccount::new(&env))).await?;
    // wait a bit to make sure all tasks see the tx confirmation
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_metrics(num_accounts, num_accounts, 0, &env);

    // send `num_accounts` transactions and assert all of them are confirmed
    let transactions = join_all(accounts.iter().map(|acc| acc.prepare_tx(&env))).await;
    let handles = transactions
        .into_iter()
        .map(|tx| tx_service_handle.send_transaction(tx))
        .collect::<Vec<_>>();
    for handle in handles {
        assert_confirmed(handle).await;
    }
    assert_metrics(num_accounts * 2, num_accounts * 2, 0, &env);

    // send `num_accounts` more transactions some of which are failing
    let transactions = join_all(accounts.iter().map(|acc| acc.prepare_tx(&env))).await;
    let mut invalid = 0;
    let handles = transactions
        .into_iter()
        .map(|mut tx| {
            // Set invalid signature for some of the transactions
            if rand::random_bool(0.5) {
                tx.quote.ty_mut().op.signature = Default::default();
                invalid += 1;
            }

            tx_service_handle.send_transaction(tx)
        })
        .collect::<Vec<_>>();

    for handle in handles {
        wait_for_tx(handle).await;
    }

    assert_metrics(num_accounts * 3, num_accounts * 3 - invalid, invalid, &env);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_transaction() -> eyre::Result<()> {
    let env =
        Environment::setup(EnvironmentConfig { is_prep: true, block_time: Some(1) }).await.unwrap();
    let tx_service_handle = env.relay_handle.chains.get(env.chain_id).unwrap().transactions.clone();

    // setup account
    let account = MockAccount::new(&env).await.unwrap();
    // prepare transaction to send
    let tx = account.prepare_tx(&env).await;

    // send transaction and get its hash
    let mut events = tx_service_handle.send_transaction(tx);
    let tx_hash = wait_for_tx_hash(&mut events).await;

    // drop the transaction from txpool
    env.drop_transaction(tx_hash).await;

    // assert that transaction is still getting resent and confirmed
    let confirmed_hash = assert_confirmed(events).await;

    assert_eq!(tx_hash, confirmed_hash);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fee_bump() -> eyre::Result<()> {
    let env =
        Environment::setup(EnvironmentConfig { is_prep: true, block_time: Some(1) }).await.unwrap();
    let tx_service_handle = env.relay_handle.chains.get(env.chain_id).unwrap().transactions.clone();

    // setup account
    let account = MockAccount::new(&env).await.unwrap();

    env.disable_mining().await;

    // prepare transaction to send
    let tx = account.prepare_tx(&env).await;

    // send transaction and get its hash
    let mut events = tx_service_handle.send_transaction(tx);
    let tx_hash = wait_for_tx_hash(&mut events).await;

    // drop the transaction from txpool to ensure it won't get mined
    let dropped = env.drop_transaction(tx_hash).await.unwrap();

    // mine blocks with higher priority fee
    env.mine_blocks_with_priority_fee(dropped.max_priority_fee_per_gas().unwrap() * 2).await;

    // wait for new transaction to be sent
    let new_tx_hash = wait_for_tx_hash(&mut events).await;
    let new_tx = env.provider.get_transaction_by_hash(new_tx_hash).await.unwrap().unwrap();

    // assert that new transaction has higher priority fee
    assert!(new_tx_hash != *dropped.hash());
    assert!(
        new_tx.max_priority_fee_per_gas().unwrap() > dropped.max_priority_fee_per_gas().unwrap()
    );

    // mine a block with the new transaction
    env.mine_block().await;
    let confirmed_hash = assert_confirmed(events).await;
    // assert that the transaction that got landed is the one we've seen before
    assert_eq!(confirmed_hash, new_tx_hash);

    Ok(())
}

/// Asserts that on fee growth, we can successfully drop an underpriced transaction, and handle
/// nonce gap caused by it.
#[tokio::test(flavor = "multi_thread")]
async fn fee_growth_nonce_gap() -> eyre::Result<()> {
    let env =
        Environment::setup(EnvironmentConfig { is_prep: true, block_time: Some(1) }).await.unwrap();
    let tx_service_handle = env.relay_handle.chains.get(env.chain_id).unwrap().transactions.clone();

    // setup 2 accounts
    let account_0 = MockAccount::new(&env).await.unwrap();
    let account_1 = MockAccount::new(&env).await.unwrap();

    env.disable_mining().await;

    // prepare and send first transaction
    let tx_0 = account_0.prepare_tx(&env).await;
    let mut events_0 = tx_service_handle.send_transaction(tx_0.clone());
    let hash_0 = wait_for_tx_hash(&mut events_0).await;

    // drop the transaction to make sure it's not mined
    let dropped = env.drop_transaction(hash_0).await.unwrap();

    // randomly choose whether we are increasing basefee or inflating priority fee market
    if rand::random_bool(0.5) {
        // set next block base fee to a high value to make it look like tx is underpriced
        env.provider
            .anvil_set_next_block_base_fee_per_gas(dropped.max_fee_per_gas() * 2)
            .await
            .unwrap();
        env.mine_block().await;
    } else {
        // mine blocks with priority fee set to max_fee of dropped tx
        env.mine_blocks_with_priority_fee(dropped.max_fee_per_gas()).await;
    }

    // prepare and send second transaction
    let tx_1 = account_1.prepare_tx(&env).await;
    let events_1 = tx_service_handle.send_transaction(tx_1.clone());

    // we should see the fee increase and account for it
    assert!(
        tx_1.quote.ty().native_fee_estimate.max_fee_per_gas
            > tx_0.quote.ty().native_fee_estimate.max_fee_per_gas
    );

    // assert that first transaction fails
    assert_failed(events_0, "transaction underpriced").await;

    // enable block mining and assert that second transaction succeeds
    env.enable_mining().await;
    assert_confirmed(events_1).await;

    Ok(())
}
