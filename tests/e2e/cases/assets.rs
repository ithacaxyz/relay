use crate::e2e::config::AccountConfig;
use relay::{asset::AssetInfoService, types::Asset};

#[tokio::test(flavor = "multi_thread")]
async fn asset_info() -> eyre::Result<()> {
    // Setup environment
    let env = AccountConfig::Prep.setup_environment().await?;
    let assets = vec![Asset::Native, Asset::Token(env.erc20), Asset::Token(env.erc20s[1])];
    let provider = env.provider.clone();

    // Spawn AssetInfoService
    let service = AssetInfoService::new(10);
    let handle = service.handle();
    tokio::spawn(service);

    let assets = handle.get_asset_info_list(&provider, assets).await?;

    assert_eq!(assets.len(), 3);
    for (_, asset) in assets {
        assert!(asset.decimals.is_some());
        assert!(asset.symbol.is_some());
    }

    Ok(())
}
