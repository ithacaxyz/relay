#![allow(missing_docs)]

use alloy::{
    hex,
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{address, bytes, Address, Bytes, TxKind, U256},
    providers::{ext::AnvilApi, PendingTransactionBuilder, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::Signer,
    sol,
    sol_types::{SolCall, SolConstructor, SolValue},
};
use alloy_chains::NamedChain;
use jsonrpsee::http_client::HttpClientBuilder;
use relay::{
    cli::Args,
    rpc::RelayApiClient,
    signer::LocalOrAws,
    types::{
        Action, Call, CoinKind, IDelegation::authorizeCall, Key, KeyType, PartialAction,
        PartialUserOp, Signature, UserOp,
    },
};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::sleep;

sol! {
    #[sol(rpc)]
    interface MockErc20 {
        constructor(string memory name_, string memory symbol_, uint8 decimals_) {
            _name = name_;
            _symbol = symbol_;
            _decimals = decimals_;
            _nameHash = keccak256(bytes(name_));
        }
        function mint(address a, uint256 val) external;
    }
}

async fn setup_contract<P: Provider>(
    provider: &P,
    artifact_path: &Path,
    args: Option<Bytes>,
) -> Address {
    let artifact_str = std::fs::read_to_string(artifact_path).unwrap();
    let artifact: serde_json::Value = serde_json::from_str(&artifact_str).unwrap();
    let bytecode = artifact
        .get("bytecode")
        .and_then(|b| b.get("object"))
        .map(|b| b.as_str().unwrap())
        .ok_or("No bytecode found")
        .unwrap();

    let mut input = hex::decode(bytecode).unwrap();
    input.extend_from_slice(&args.unwrap_or_default());

    provider
        .send_transaction(TransactionRequest {
            input: input.into(),
            to: Some(TxKind::Create),
            ..Default::default()
        })
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap()
}

#[tokio::test]
async fn e2e() {
    // Start Anvil
    let anvil = Anvil::new().args(["--odyssey", "--host", "0.0.0.0"]).try_spawn().unwrap();
    let upstream = anvil.endpoint_url();

    let entrypoint = address!("307AF7d28AfEE82092aA95D35644898311CA5360");
    let relay_key =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
    let eoa_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string();

    let relay_signer = LocalOrAws::load(&relay_key, None).await.unwrap();
    let eoa_signer = LocalOrAws::load(&eoa_key, None).await.unwrap();

    let anvil_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(relay_signer.clone()))
        .on_http(upstream.clone());

    // Deploy contracts: Entrypoint, Delegation and FakeERC20
    let contracts_path = PathBuf::from(std::env::var("CONTRACTS").unwrap_or("out/".to_string()));
    let mock_entrypoint = setup_contract(
        &anvil_provider,
        &contracts_path.join("EntryPoint.sol/EntryPoint.json"),
        None,
    )
    .await;
    let delegation = setup_contract(
        &anvil_provider,
        &contracts_path.join("Delegation.sol/Delegation.json"),
        None,
    )
    .await;
    let erc20 = setup_contract(
        &anvil_provider,
        &contracts_path.join("MockERC20.sol/MockERC20.json"),
        Some(
            MockErc20::constructorCall {
                name_: Default::default(),
                symbol_: Default::default(),
                decimals_: Default::default(),
            }
            .abi_encode()
            .into(),
        ),
    )
    .await;

    // Entrypoint address is hardcoded into delegation, so need to etch.
    anvil_provider
        .anvil_set_code(entrypoint, anvil_provider.get_code_at(mock_entrypoint).await.unwrap())
        .await
        .unwrap();

    // Fund FakeERC20
    for signer in [&relay_signer, &eoa_signer] {
        MockErc20::new(erc20, &anvil_provider)
            .mint(signer.address(), U256::from(100e18))
            .call()
            .await
            .unwrap();
    }

    // Temporary assertion until we can dynamically initialize COINS_CONFIG
    assert!(CoinKind::get_token(NamedChain::AnvilHardhat.into(), erc20).is_some());

    tokio::spawn(async move {
        let cli = Args {
            address: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 3131,
            upstream,
            entrypoint,
            quote_ttl: Duration::from_secs(60),
            quote_secret_key: relay_key.clone(),
            fee_tokens: vec![erc20],
            secret_key: relay_key,
        };
        cli.run().await
    });

    // Let relay boot
    sleep(Duration::from_secs(1)).await;

    let relay_endpoint = HttpClientBuilder::default().build("http://localhost:3131").unwrap();

    // Prepare 7702 auth to be sent with the first transaction
    let auth = alloy::eips::eip7702::Authorization {
        chain_id: U256::from(0),
        address: delegation,
        nonce: 0,
    };
    let auth_hash = auth.signature_hash();
    let auth = auth.into_signed(eoa_signer.sign_hash(&auth_hash).await.unwrap());

    // Prepare "passkey" to be authorized with the first transaction
    let pass_key = Key {
        expiry: Default::default(),
        keyType: KeyType::Secp256k1,
        isSuperAdmin: true,
        publicKey: eoa_signer.address().abi_encode().into(),
    };

    let txs_calls: [Bytes; 2] = [
        // 1st Transaction: authorize(key)
        vec![Call {
            target: eoa_signer.address(),
            value: U256::ZERO,
            data: authorizeCall { key: pass_key.clone() }.abi_encode().into(),
        }]
        .abi_encode()
        .into(),
        // 2nd Transaction UserOp calls totalSupply on erc20
        vec![Call {
            target: erc20,
            value: U256::ZERO,
            data: Bytes::from(hex::decode("0x18160ddd").unwrap()),
        }]
        .abi_encode()
        .into(),
    ];

    let chain_id = anvil_provider.get_chain_id().await.unwrap();
    for (nonce, execution_data) in txs_calls.into_iter().enumerate() {
        let res = relay_endpoint
            .estimate_fee(
                PartialAction {
                    op: PartialUserOp {
                        eoa: eoa_signer.address(),
                        executionData: execution_data.clone(),
                        nonce: U256::from(nonce),
                    },
                    auth: (nonce == 0).then_some(delegation),
                },
                erc20,
            )
            .await
            .unwrap();
        println!("Estimated call with nonce {nonce} to be {res:?}");

        // This would be done by the frontend. eg. Porto
        let op = {
            let mut op = UserOp {
                eoa: eoa_signer.address(),
                executionData: execution_data,
                nonce: U256::from(nonce),
                payer: Address::ZERO,
                paymentToken: erc20,
                paymentRecipient: Address::ZERO,
                paymentAmount: U256::ZERO,
                paymentMaxAmount: U256::ZERO,
                paymentPerGas: U256::ZERO,
                combinedGas: U256::from(res.ty().gas_estimate),
                signature: bytes!(""),
            };

            let signature = eoa_signer
                .sign_hash(&op.eip712_digest(entrypoint, chain_id, U256::ZERO).unwrap())
                .await
                .unwrap();

            op.signature = if nonce == 0 {
                // The first authorize should be done from the root key
                signature.as_bytes().into()
            } else {
                // Second action can be done with the alternative key_scheme that we authorized
                Signature {
                    innerSignature: signature.as_bytes().into(),
                    keyHash: pass_key.key_hash(),
                    prehash: false,
                }
                .abi_encode_packed()
                .into()
            };
            op
        };

        // Send to relay
        let tx_hash = relay_endpoint
            .send_action(Action { op, auth: (nonce == 0).then_some(auth.clone()) }, res)
            .await
            .unwrap();

        // Verify that transaction has succeeded.
        let receipt = PendingTransactionBuilder::new(anvil_provider.root().clone(), tx_hash)
            .get_receipt()
            .await
            .unwrap();

        if !receipt.status() {
            panic!("Failed tx {nonce} receipt {receipt:?}");
        }
    }
}
