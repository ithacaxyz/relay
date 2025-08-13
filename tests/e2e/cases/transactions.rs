use crate::e2e::{
    FIRST_RELAY_SIGNER, SIGNERS_MNEMONIC,
    environment::{Environment, EnvironmentConfig},
    eoa::MockAccount,
};
use alloy::{
    consensus::Transaction,
    eips::Encodable2718,
    primitives::{B256, U256},
    providers::{Provider, ext::AnvilApi},
    signers::local::{
        PrivateKeySigner,
        coins_bip39::{English, Mnemonic},
    },
};
use futures_util::{
    StreamExt, TryStreamExt,
    future::{JoinAll, TryJoinAll, join_all, try_join_all},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use relay::{
    config::TransactionServiceConfig,
    signers::DynSigner,
    storage::StorageApi,
    transactions::{MIN_SIGNER_GAS, RelayTransactionKind, TransactionService, TransactionStatus},
};
use std::{collections::HashSet, time::Duration};
use tokio::sync::broadcast;

/// A Seed used to derive random accounts from
const KEY_SEED: u64 = 1337;

/// The pinned block number used for heavier fork tests.
/// By pinning the number we can re-use the cached rpc read-only data via foundry.
fn pinned_test_fork_block_number() -> Option<i64> {
    std::env::var("TEST_FORK_BLOCK_NUMBER_PINNED").ok().and_then(|s| s.parse().ok())
}

/// Waits for a final transaction status.
async fn wait_for_tx(mut events: broadcast::Receiver<TransactionStatus>) -> TransactionStatus {
    while let Ok(status) = events.recv().await {
        if status.is_final() {
            return status;
        }
    }

    panic!("Transaction did not complete");
}

async fn wait_for_tx_hash(events: &mut broadcast::Receiver<TransactionStatus>) -> B256 {
    while let Ok(status) = events.recv().await {
        match status {
            TransactionStatus::Pending(hash) => return hash,
            TransactionStatus::Failed(err) => panic!("transacton failed {err}"),
            _ => {}
        }
    }

    panic!("failed to get tx hash")
}

/// Asserts that transaction was confirmed.
async fn assert_failed(events: broadcast::Receiver<TransactionStatus>, error: &str) {
    match wait_for_tx(events).await {
        TransactionStatus::Failed(err) => {
            assert!(err.to_string().contains(error), "tx failed with different error: {err}");
        }
        TransactionStatus::Confirmed(_) => panic!("expected failure"),
        _ => unreachable!(),
    }
}

/// Asserts that transaction was confirmed.
async fn assert_confirmed(events: broadcast::Receiver<TransactionStatus>) -> B256 {
    match wait_for_tx(events).await {
        TransactionStatus::Confirmed(receipt) => receipt.transaction_hash,
        TransactionStatus::Failed(err) => panic!("transacton failed {err}"),
        _ => unreachable!(),
    }
}

/// Asserts that metrics match the expected values.
fn assert_metrics(sent: usize, confirmed: usize, failed: usize, env: &Environment) {
    let output = env.relay_handle.metrics.render();
    let chain_id = env.chain_id();
    assert!(output.contains(&format!(r#"transactions_sent{{chain_id="{chain_id}"}} {sent}"#)));
    assert!(
        output.contains(&format!(r#"transactions_confirmed{{chain_id="{chain_id}"}} {confirmed}"#))
    );
    assert!(output.contains(&format!(r#"transactions_failed{{chain_id="{chain_id}"}} {failed}"#)));
}

/// Asserts that metrics match the expected values.
fn assert_signer_metrics(paused: usize, active: usize, env: &Environment) {
    let output = env.relay_handle.metrics.render();
    let chain_id = env.chain_id();
    assert!(
        output
            .contains(&format!(r#"transactions_active_signers{{chain_id="{chain_id}"}} {active}"#))
    );
    assert!(
        output
            .contains(&format!(r#"transactions_paused_signers{{chain_id="{chain_id}"}} {paused}"#))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_basic_concurrent() -> eyre::Result<()> {
    let env = Environment::setup_with_config(EnvironmentConfig {
        block_time: Some(1.0),
        fork_block_number: pinned_test_fork_block_number(),
        ..Default::default()
    })
    .await
    .unwrap();
    // use a consistent seed
    let mut rng = StdRng::seed_from_u64(KEY_SEED);

    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    // setup accounts
    let num_accounts = 100;
    let keys = (&mut rng).random_iter().take(num_accounts).collect::<Vec<B256>>();
    let accounts =
        futures_util::stream::iter(keys.into_iter().map(|key| MockAccount::with_key(&env, key)))
            .buffered(1)
            .try_collect::<Vec<_>>()
            .await?;
    // wait a bit to make sure all tasks see the tx confirmation
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_metrics(num_accounts, num_accounts, 0, &env);

    // send `num_accounts` transactions and assert all of them are confirmed
    let transactions = futures_util::stream::iter(accounts.iter().map(|acc| acc.prepare_tx(&env)))
        .buffered(1)
        .collect::<Vec<_>>()
        .await;
    let handles = transactions
        .into_iter()
        .map(|tx| tx_service_handle.send_transaction(tx))
        .collect::<TryJoinAll<_>>()
        .await
        .unwrap();
    for handle in handles {
        assert_confirmed(handle).await;
    }
    assert_metrics(num_accounts * 2, num_accounts * 2, 0, &env);

    // send `num_accounts` more transactions some of which are failing
    let transactions = futures_util::stream::iter(accounts.iter().map(|acc| acc.prepare_tx(&env)))
        .buffered(1)
        .collect::<Vec<_>>()
        .await;
    let mut invalid = 0;
    let handles = transactions
        .into_iter()
        .map(|mut tx| {
            // Set invalid signature for some of the transactions
            if rng.random_bool(0.5) {
                let RelayTransactionKind::Intent { quote, .. } = &mut tx.kind else {
                    unreachable!()
                };
                quote.intent.signature = Default::default();
                invalid += 1;
            }

            tx_service_handle.send_transaction(tx)
        })
        .collect::<TryJoinAll<_>>()
        .await?;

    for handle in handles {
        wait_for_tx(handle).await;
    }

    assert_metrics(num_accounts * 3, num_accounts * 3 - invalid, invalid, &env);

    // otherwise it will be marked as LEAK.
    drop(env);
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_transaction() -> eyre::Result<()> {
    let env = Environment::setup_with_config(EnvironmentConfig {
        block_time: Some(1.0),
        ..Default::default()
    })
    .await
    .unwrap();
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    // setup account
    let account = MockAccount::new(&env).await.unwrap();
    // prepare transaction to send
    let tx = account.prepare_tx(&env).await;

    // send transaction and get its hash
    let mut events = tx_service_handle.send_transaction(tx).await?;
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
    let config = EnvironmentConfig { block_time: Some(1.0), ..Default::default() };
    let signer = PrivateKeySigner::from_bytes(&FIRST_RELAY_SIGNER)?;
    let env = Environment::setup_with_config(config).await.unwrap();
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    // setup account
    let account = MockAccount::new(&env).await.unwrap();

    env.disable_mining().await;

    // set priority fee to be ~basefee for deterministic gas estimation
    let base_fee = env
        .provider()
        .get_block(Default::default())
        .await?
        .unwrap()
        .header
        .base_fee_per_gas
        .unwrap();
    env.mine_blocks_with_priority_fee(base_fee as u128).await;

    // prepare transaction to send
    let tx = account.prepare_tx(&env).await;

    // send transaction and get its hash
    let mut events = tx_service_handle.send_transaction(tx).await?;
    let tx_hash = wait_for_tx_hash(&mut events).await;

    // drop the transaction from txpool to ensure it won't get mined
    let dropped = env.drop_transaction(tx_hash).await.unwrap();

    // mine blocks with higher priority fee
    env.mine_blocks_with_priority_fee(dropped.max_priority_fee_per_gas().unwrap() * 2).await;

    // submit the transaction again to make sure it's not treated as dropped.
    let _ = env.provider().send_raw_transaction(&dropped.encoded_2718()).await.unwrap();

    // wait for new transaction to be sent
    let new_tx_hash = wait_for_tx_hash(&mut events).await;
    let new_tx = env.provider().get_transaction_by_hash(new_tx_hash).await.unwrap().unwrap();

    // assert that new transaction has higher priority fee
    assert!(new_tx_hash != *dropped.hash());
    assert!(
        new_tx.max_priority_fee_per_gas().unwrap() > dropped.max_priority_fee_per_gas().unwrap()
    );
    let pending_txs = env
        .relay_handle
        .storage
        .read_pending_transactions(signer.address(), env.chain_id())
        .await
        .unwrap();
    assert_eq!(pending_txs.len(), 1);
    assert_eq!(pending_txs.first().unwrap().sent.len(), 2);

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
    let env = Environment::setup_with_config(EnvironmentConfig {
        block_time: Some(1.0),
        ..Default::default()
    })
    .await
    .unwrap();
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    // set priority fee to be ~basefee for deterministic gas estimation
    let base_fee = env
        .provider()
        .get_block(Default::default())
        .await?
        .unwrap()
        .header
        .base_fee_per_gas
        .unwrap();
    env.mine_blocks_with_priority_fee(base_fee as u128).await;

    // setup 2 accounts
    let account_0 = MockAccount::new(&env).await.unwrap();
    let account_1 = MockAccount::new(&env).await.unwrap();

    env.disable_mining().await;

    // prepare and send first transaction
    let tx_0 = account_0.prepare_tx(&env).await;
    let mut events_0 = tx_service_handle.send_transaction(tx_0.clone()).await?;
    let hash_0 = wait_for_tx_hash(&mut events_0).await;

    // drop the transaction to make sure it's not mined
    env.drop_transaction(hash_0).await.unwrap();

    let max_fee = tx_0.quote().unwrap().native_fee_estimate.max_fee_per_gas;

    // set next block base fee to a high value to make it look like tx is underpriced
    env.provider().anvil_set_next_block_base_fee_per_gas(max_fee * 2).await.unwrap();
    env.mine_block().await;

    // prepare and send second transaction
    let tx_1 = account_1.prepare_tx(&env).await;
    let events_1 = tx_service_handle.send_transaction(tx_1.clone()).await?;

    // we should see the fee increase and account for it
    assert!(
        tx_1.quote().unwrap().native_fee_estimate.max_fee_per_gas
            > tx_0.quote().unwrap().native_fee_estimate.max_fee_per_gas
    );

    // enable block mining
    env.enable_mining().await;

    // assert that first transaction fails
    assert_failed(events_0, "transaction underpriced").await;
    assert_confirmed(events_1).await;

    Ok(())
}

/// Asserts that on fee growth, we can successfully drop an underpriced transaction, and handle
/// nonce gap caused by it.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn pause_out_of_funds() -> eyre::Result<()> {
    let num_signers = 3;
    let env = Environment::setup_with_config(EnvironmentConfig {
        block_time: Some(0.2),
        transaction_service_config: TransactionServiceConfig {
            num_signers,
            // set lower interval to make sure that we hit the pause logic
            balance_check_interval: Duration::from_millis(100),
            // set lower throughput to make sure that transactions are not getting included too
            // quickly
            max_transactions_per_signer: 5,
            ..Default::default()
        },
        fork_block_number: pinned_test_fork_block_number(),
        ..Default::default()
    })
    .await
    .unwrap();
    let signers = DynSigner::derive_from_mnemonic(SIGNERS_MNEMONIC.parse()?, num_signers)?;
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    // use a consistent seed
    let rng = StdRng::seed_from_u64(KEY_SEED);
    // setup accounts
    let num_accounts = 30;
    let keys = rng.random_iter().take(num_accounts).collect::<Vec<B256>>();
    let accounts =
        futures_util::stream::iter(keys.into_iter().map(|key| MockAccount::with_key(&env, key)))
            .buffered(10)
            .try_collect::<Vec<_>>()
            .await?;

    // send transactions for each account
    let transactions = futures_util::stream::iter(accounts.iter().map(|acc| acc.prepare_tx(&env)))
        .buffered(1)
        .collect::<Vec<_>>()
        .await;
    let handles = futures_util::stream::iter(
        transactions.into_iter().map(|tx| tx_service_handle.send_transaction(tx)),
    )
    .buffered(num_accounts)
    .try_collect::<Vec<_>>()
    .await?;

    // Now set balances of all signers except the last one to a low value that is enough to pay for
    // the pending transactions but is low enough for signer to get paused.
    let fees = env.provider().estimate_eip1559_fees().await.unwrap();
    let new_balance = U256::from(10_000_000 * fees.max_fee_per_gas);

    try_join_all(
        signers
            .iter()
            .take(signers.len() - 1)
            .map(|signer| env.provider().anvil_set_balance(signer.address(), new_balance)),
    )
    .await
    .unwrap();

    // fix the basefee to avoid it going down and signers getting resumed
    env.freeze_basefee().await;

    // assert that all transactions are confirmed
    for handle in handles {
        assert_confirmed(handle).await;
    }

    // assert that signers were actually paused according to metrics
    assert_signer_metrics(signers.len() - 1, 1, &env);

    let last_signer = signers.last().unwrap();
    let last_signer_nonce =
        env.provider().get_transaction_count(last_signer.address()).await.unwrap();

    // assert that last signer processed more transactions than others
    for signer in &signers[..signers.len() - 1] {
        let nonce = env.provider().get_transaction_count(signer.address()).await.unwrap();
        assert!(nonce < last_signer_nonce);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn resume_paused() -> eyre::Result<()> {
    let num_signers = 5;
    let env = Environment::setup_with_config(EnvironmentConfig {
        block_time: Some(0.2),
        transaction_service_config: TransactionServiceConfig {
            num_signers,
            // set lower interval to make sure that we hit the pause logic
            balance_check_interval: Duration::from_millis(100),
            // set lower throughput to make sure that transactions are not getting included too
            // quickly
            max_transactions_per_signer: 5,
            ..Default::default()
        },
        fork_block_number: pinned_test_fork_block_number(),
        ..Default::default()
    })
    .await
    .unwrap();
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    let signers = DynSigner::derive_from_mnemonic(SIGNERS_MNEMONIC.parse()?, num_signers)?;

    // setup 10 accounts
    let num_accounts = 10;
    let accounts = try_join_all((0..num_accounts).map(|_| MockAccount::new(&env))).await?;

    // set funder balance to 0, so signers cant pull gas money
    env.provider().anvil_set_balance(env.funder, U256::ZERO).await?;

    // set balances of all signers except the last one to 0 and wait for them to get paused
    try_join_all(
        signers
            .iter()
            .take(signers.len() - 1)
            .map(|signer| env.provider().anvil_set_balance(signer.address(), U256::ZERO)),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_signer_metrics(signers.len() - 1, 1, &env);

    let last_signer = signers.last().unwrap();

    // send a batch of transactions and assert that all of them are handled by the last signer
    futures_util::stream::iter(accounts.iter().map(|acc| async {
        let tx = acc.prepare_tx(&env).await;
        let handle = tx_service_handle.send_transaction(tx).await.unwrap();
        let hash = assert_confirmed(handle).await;
        let signer =
            env.provider().get_transaction_by_hash(hash).await.unwrap().unwrap().inner.signer();
        assert_eq!(signer, last_signer.address());
    }))
    .buffered(10)
    .collect::<Vec<_>>()
    .await;

    // set balances back to high values
    try_join_all(signers.iter().take(signers.len() - 1).map(|signer| {
        env.provider().anvil_set_balance(signer.address(), U256::MAX / U256::from(2))
    }))
    .await
    .unwrap();

    // sleep for a bit to let the task fetch the new balances
    tokio::time::sleep(Duration::from_millis(500)).await;

    // assert that signers are no longer paused
    assert_signer_metrics(0, signers.len(), &env);

    // send a batch of transactions again and assert that all of them complete
    let seen_signers = join_all(accounts.iter().map(|acc| async {
        let tx = acc.prepare_tx(&env).await;
        let handle = tx_service_handle.send_transaction(tx).await.unwrap();
        let hash = assert_confirmed(handle).await;
        env.provider().get_transaction_by_hash(hash).await.unwrap().unwrap().inner.signer()
    }))
    .await
    .into_iter()
    .collect::<HashSet<_>>();

    // assert that all signers participated in processing the transactions this time
    assert!(seen_signers.len() == signers.len());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn diverged_nonce() -> eyre::Result<()> {
    let config = EnvironmentConfig {
        block_time: Some(1.0),
        transaction_service_config: TransactionServiceConfig {
            nonce_check_interval: Duration::from_millis(100),
            ..Default::default()
        },
        ..Default::default()
    };
    let signer = PrivateKeySigner::from_bytes(&FIRST_RELAY_SIGNER)?;
    let env = Environment::setup_with_config(config.clone()).await.unwrap();
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();

    // alter signer nonce to invalidate the nonce cached by service
    let nonce = env.provider().get_transaction_count(signer.address()).await.unwrap();
    env.provider().anvil_set_nonce(signer.address(), nonce + 10).await.unwrap();

    // give the service some time
    tokio::time::sleep(config.transaction_service_config.nonce_check_interval * 2).await;

    // assert the service is functioning by spamming some transactions
    let num_accounts = 10;
    let transactions = futures_util::stream::iter((0..num_accounts).map(|_| async {
        let account = MockAccount::new(&env).await.unwrap();
        account.prepare_tx(&env).await
    }))
    .buffered(5)
    .collect::<Vec<_>>()
    .await;
    let handles = transactions
        .into_iter()
        .map(|tx| tx_service_handle.send_transaction(tx))
        .collect::<TryJoinAll<_>>()
        .await?;

    for handle in handles {
        assert_confirmed(handle).await;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_with_pending() -> eyre::Result<()> {
    let mut config = EnvironmentConfig {
        block_time: Some(1.0),
        transaction_service_config: TransactionServiceConfig {
            max_transactions_per_signer: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let signers = DynSigner::derive_from_mnemonic(
        SIGNERS_MNEMONIC.parse()?,
        config.transaction_service_config.num_signers,
    )
    .unwrap();
    let env = Environment::setup_with_config(config.clone()).await.unwrap();
    let tx_service_handle =
        env.relay_handle.chains.get(env.chain_id()).unwrap().transactions.clone();
    let storage = env.relay_handle.storage.clone();
    let provider = env.provider().clone();

    // spam some transactions
    let num_accounts = 10;
    let transactions = futures_util::stream::iter((0..num_accounts).map(|_| async {
        let account = MockAccount::new(&env).await.unwrap();
        account.prepare_tx(&env).await
    }))
    .buffered(10)
    .collect::<Vec<_>>()
    .await;

    // send transactions to the tx service
    let mut handles = transactions
        .iter()
        .map(|tx| tx_service_handle.send_transaction(tx.clone()))
        .collect::<TryJoinAll<_>>()
        .await?;

    // wait for the first transactions to be sent
    let sent = handles[..config.transaction_service_config.max_transactions_per_signer]
        .iter_mut()
        .map(wait_for_tx_hash)
        .collect::<JoinAll<_>>()
        .await;

    drop(tx_service_handle);
    drop(env.relay_handle);

    // drop one of the transactions
    provider.anvil_drop_transaction(sent[1]).await.unwrap();

    // restart the service
    // increase signers capacity to make sure transactions are getting included quickly
    config.transaction_service_config.max_transactions_per_signer = 10;
    let (service, _handle) = TransactionService::new(
        provider,
        None,
        signers,
        storage.clone(),
        config.transaction_service_config.clone(),
        env.funder,
    )
    .await
    .unwrap();
    tokio::spawn(service);

    // ensure that all transactions are getting confirmed after restart
    'outer: loop {
        tokio::time::sleep(Duration::from_millis(100)).await;

        for tx in &transactions {
            let (_, status) = storage.read_transaction_status(tx.id).await.unwrap().unwrap();
            match status {
                TransactionStatus::Pending(_) | TransactionStatus::InFlight => continue 'outer,
                TransactionStatus::Failed(err) => panic!("transaction {} failed: {err}", tx.id),
                TransactionStatus::Confirmed(_) => continue,
            }
        }

        break;
    }

    Ok(())
}

/// Ensures that when a signer can no longer execute MIN_SIGNER_GAS gas units, it will pull funds
/// from the funder contract.
#[tokio::test(flavor = "multi_thread")]
async fn test_signer_pull_gas() -> eyre::Result<()> {
    let env = Environment::setup_with_config(EnvironmentConfig {
        block_time: Some(0.5),
        transaction_service_config: TransactionServiceConfig {
            balance_check_interval: Duration::from_millis(100), // Check balance every 100ms
            num_signers: 1,
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;

    let provider = env.providers[0].clone();
    let mnemonic = Mnemonic::<English>::new_from_phrase(SIGNERS_MNEMONIC)?;
    let signers = DynSigner::derive_from_mnemonic(mnemonic, 1)?;
    let signer_address = signers.into_iter().next().unwrap().address();

    // set signer balance below threshold, and wait for it to pull it from the contract
    let fees = provider.estimate_eip1559_fees().await?;
    let min_balance = MIN_SIGNER_GAS * U256::from(fees.max_fee_per_gas);
    let low_balance = min_balance.div_ceil(U256::from(2));
    provider.anvil_set_balance(signer_address, low_balance).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(provider.get_balance(signer_address).await? > min_balance);

    Ok(())
}
