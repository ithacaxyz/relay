//! Intents merkle tree end-to-end test cases

use crate::e2e::Environment;
use alloy::{
    primitives::{Address, B256, Bytes, U256, bytes, uint},
    sol_types::SolValue,
};
use relay::types::{Call, Intent, Intents, LazyMerkleTree, VersionedContract};

/// Creates a test intent with specified nonce and payment token
fn create_test_intent(eoa: Address, nonce: U256, payment_token: Address) -> Intent {
    Intent::latest()
        .with_eoa(eoa)
        .with_execution_data(Vec::<Call>::new().abi_encode().into())
        .with_nonce(nonce)
        .with_payer(Address::ZERO)
        .with_payment_token(payment_token)
        .with_pre_payment_max_amount(U256::ZERO)
        .with_total_payment_max_amount(U256::ZERO)
        .with_combined_gas(uint!(500000_U256))
        .with_encoded_pre_calls(vec![])
        .with_encoded_fund_transfers(vec![])
        .with_pre_payment_amount(U256::ZERO)
        .with_total_payment_amount(U256::ZERO)
        .with_payment_recipient(Address::ZERO)
        .with_signature(Bytes::default())
        .with_payment_signature(Bytes::default())
        .with_supported_account_implementation(Address::ZERO)
        .with_funder(Address::ZERO)
        .with_funder_signature(Bytes::default())
        .with_settler(Address::ZERO)
        .with_expiry(U256::ZERO)
        .with_settler_context(bytes!(""))
}

/// Test merkle root calculation for a batch of intents
pub async fn test_intents_merkle_root(env: &Environment) -> eyre::Result<()> {
    // Create orchestrator VersionedContract
    let orchestrator = VersionedContract::new(env.orchestrator, env.provider().clone()).await?;

    // Create a batch of test intents
    let chain_id = env.chain_id();
    let intents_vec = vec![
        (
            create_test_intent(env.eoa.address(), uint!(1_U256), env.fee_token),
            orchestrator.clone(),
            chain_id,
        ),
        (
            create_test_intent(env.eoa.address(), uint!(2_U256), env.erc20),
            orchestrator.clone(),
            chain_id,
        ),
        (
            create_test_intent(env.eoa.address(), uint!(3_U256), env.fee_token),
            orchestrator.clone(),
            chain_id,
        ),
        (
            create_test_intent(env.eoa.address(), uint!(4_U256), env.erc20),
            orchestrator.clone(),
            chain_id,
        ),
    ];

    let mut intents = Intents::new(intents_vec.clone());

    // Calculate merkle root using EIP-712 signing hashes
    let root = intents.root()?;

    // Verify root is not zero for non-empty batch
    assert_ne!(root, B256::ZERO, "Merkle root should not be zero for non-empty batch");

    Ok(())
}

/// Test merkle proof generation and verification
pub async fn test_intents_merkle_proofs(env: &Environment) -> eyre::Result<()> {
    use relay::types::MULTICHAIN_NONCE_PREFIX;

    // Create orchestrator VersionedContract
    let orchestrator = VersionedContract::new(env.orchestrator, env.provider().clone()).await?;
    let chain_id = env.chain_id();

    // Create a mix of single-chain and multi-chain intents
    let intents_vec = vec![
        // Single-chain intent
        (
            create_test_intent(env.eoa.address(), uint!(1_U256), env.fee_token),
            orchestrator.clone(),
            chain_id,
        ),
        // Multi-chain intent
        (
            create_test_intent(
                env.eoa.address(),
                (MULTICHAIN_NONCE_PREFIX << 240) | uint!(100_U256),
                env.fee_token,
            ),
            orchestrator.clone(),
            chain_id,
        ),
        // Another single-chain intent
        (
            create_test_intent(env.eoa.address(), uint!(2_U256), env.erc20),
            orchestrator.clone(),
            chain_id,
        ),
        // Another multi-chain intent
        (
            create_test_intent(
                env.eoa.address(),
                (MULTICHAIN_NONCE_PREFIX << 240) | uint!(200_U256),
                env.erc20,
            ),
            orchestrator.clone(),
            chain_id,
        ),
    ];

    let mut intents = Intents::new(intents_vec.clone());
    let leaves = intents.compute_leaf_hashes()?;
    let root = intents.root()?;

    // Generate and verify proof for each intent
    for (i, leaf) in leaves.into_iter().enumerate() {
        let proof = intents.get_proof(i)?;

        // Verify proof
        assert!(
            LazyMerkleTree::verify_proof(&root, &proof, &leaf),
            "Proof for intent {i} should be valid"
        );
    }

    // Test invalid index - should return an error
    let invalid_result = intents.get_proof(100);
    assert!(invalid_result.is_err(), "Should return error for invalid index");

    Ok(())
}

/// Test empty intents batch
pub fn test_empty_intents_batch() -> eyre::Result<()> {
    let mut intents = Intents::new(vec![]);

    // Empty batch should have zero root
    let root = intents.root()?;
    assert_eq!(root, B256::ZERO, "Empty batch should have zero root");

    // Should return error for any index on empty batch
    let proof_result = intents.get_proof(0);
    assert!(proof_result.is_err(), "Empty batch should return error for any proof index");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn intents_merkle() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    tokio::try_join!(test_intents_merkle_root(&env), test_intents_merkle_proofs(&env),)?;

    test_empty_intents_batch()
}
