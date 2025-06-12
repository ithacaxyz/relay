//! Intents merkle tree end-to-end test cases

use crate::e2e::Environment;
use alloy::{
    primitives::{Address, B256, Bytes, U256, uint},
    sol_types::SolValue,
};
use alloy_merkle_tree::tree::MerkleTree;
use relay::types::{Call, Intent, Intents};

/// Creates a test intent with specified nonce and payment token
fn create_test_intent(eoa: Address, nonce: U256, payment_token: Address) -> Intent {
    Intent {
        eoa,
        executionData: Vec::<Call>::new().abi_encode().into(),
        nonce,
        payer: Address::ZERO,
        paymentToken: payment_token,
        prePaymentMaxAmount: U256::ZERO,
        totalPaymentMaxAmount: U256::ZERO,
        combinedGas: uint!(500000_U256),
        encodedPreCalls: vec![],
        encodedFundTransfers: Bytes::default(),
        prePaymentAmount: U256::ZERO,
        totalPaymentAmount: U256::ZERO,
        paymentRecipient: Address::ZERO,
        signature: Bytes::default(),
        paymentSignature: Bytes::default(),
        supportedAccountImplementation: Address::ZERO,
    }
}

/// Test merkle root calculation for a batch of intents
pub async fn test_intents_merkle_root(env: &Environment) -> eyre::Result<()> {
    // Create a batch of test intents
    let intents_vec = vec![
        (
            create_test_intent(env.eoa.address(), uint!(1_U256), env.fee_token),
            env.provider.clone(),
            env.orchestrator,
        ),
        (
            create_test_intent(env.eoa.address(), uint!(2_U256), env.erc20),
            env.provider.clone(),
            env.orchestrator,
        ),
        (
            create_test_intent(env.eoa.address(), uint!(3_U256), env.fee_token),
            env.provider.clone(),
            env.orchestrator,
        ),
        (
            create_test_intent(env.eoa.address(), uint!(4_U256), env.erc20),
            env.provider.clone(),
            env.orchestrator,
        ),
    ];

    let mut intents = Intents::new(intents_vec.clone());

    // Calculate merkle root using EIP-712 signing hashes
    let root = intents.root().await?;

    // Verify root is not zero for non-empty batch
    assert_ne!(root, B256::ZERO, "Merkle root should not be zero for non-empty batch");

    Ok(())
}

/// Test merkle proof generation and verification
pub async fn test_intents_merkle_proofs(env: &Environment) -> eyre::Result<()> {
    use relay::types::MULTICHAIN_NONCE_PREFIX;

    // Create a mix of single-chain and multi-chain intents
    let intents_vec = vec![
        // Single-chain intent
        (
            create_test_intent(env.eoa.address(), uint!(1_U256), env.fee_token),
            env.provider.clone(),
            env.orchestrator,
        ),
        // Multi-chain intent
        (
            create_test_intent(
                env.eoa.address(),
                (MULTICHAIN_NONCE_PREFIX << 240) | uint!(100_U256),
                env.fee_token,
            ),
            env.provider.clone(),
            env.orchestrator,
        ),
        // Another single-chain intent
        (
            create_test_intent(env.eoa.address(), uint!(2_U256), env.erc20),
            env.provider.clone(),
            env.orchestrator,
        ),
        // Another multi-chain intent
        (
            create_test_intent(
                env.eoa.address(),
                (MULTICHAIN_NONCE_PREFIX << 240) | uint!(200_U256),
                env.erc20,
            ),
            env.provider.clone(),
            env.orchestrator,
        ),
    ];

    let mut intents = Intents::new(intents_vec.clone());
    let root = intents.root().await?;

    // Generate and verify proof for each intent
    for i in 0..intents.len() {
        let proof = intents.get_proof(i).await?.expect("Should get proof for valid index");

        // Verify proof using alloy-merkle-tree
        assert!(MerkleTree::verify_proof(&proof), "Proof for intent {i} should be valid");

        // Verify the proof root matches our calculated root
        assert_eq!(proof.root, root, "Proof root should match calculated root for intent {i}");
    }

    // Test invalid index
    let invalid_proof = intents.get_proof(100).await?;
    assert!(invalid_proof.is_none(), "Should return None for invalid index");

    Ok(())
}

/// Test empty intents batch
pub async fn test_empty_intents_batch() -> eyre::Result<()> {
    let mut intents = Intents::new(vec![]);

    // Empty batch should have zero root
    let root = intents.root().await?;
    assert_eq!(root, B256::ZERO, "Empty batch should have zero root");

    // Should return None for any index
    let proof = intents.get_proof(0).await?;
    assert!(proof.is_none(), "Empty batch should return None for any proof index");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn intents_merkle() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    tokio::try_join!(
        test_intents_merkle_root(&env),
        test_intents_merkle_proofs(&env),
        test_empty_intents_batch()
    )?;

    Ok(())
}
