#![allow(clippy::missing_errors_doc)]

use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use anyhow::{anyhow, Context};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use lwk_test_util::{TestEnv, TestEnvBuilder};
use serde_json::Value;
use simplicityhl::elements::AssetId;
use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::Network;

const DEFAULT_FUND_AMOUNT_SAT: u64 = 1_000_000;

static TEST_ENV: OnceLock<Arc<RwLock<TestEnv>>> = OnceLock::new();
static TEST_ENV_INIT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFundingAsset {
    Lbtc,
    NewAsset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeIssuedTokenPair {
    pub asset_id: AssetId,
    pub token_id: AssetId,
    pub entropy: [u8; 32],
}

pub fn ensure_node_running() -> anyhow::Result<()> {
    if TEST_ENV.get().is_some() {
        return Ok(());
    }

    let _init_guard = TEST_ENV_INIT_LOCK
        .lock()
        .map_err(|_| anyhow!("test env init lock poisoned"))?;
    if TEST_ENV.get().is_some() {
        return Ok(());
    }

    for var in ["ELEMENTSD_EXEC", "ELECTRS_LIQUID_EXEC", "WATERFALLS_EXEC"] {
        if std::env::var(var)
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(anyhow!("{var} must be set"));
        }
    }

    let env = std::panic::catch_unwind(|| {
        TestEnvBuilder::from_env()
            .with_esplora()
            .with_waterfalls()
            .build()
    })
    .map_err(|panic| {
        panic.downcast_ref::<String>().map_or_else(
            || anyhow!("failed to start regtest test environment"),
            |message| anyhow!("failed to start regtest test environment: {message}"),
        )
    })?;

    let _ = TEST_ENV.set(Arc::new(RwLock::new(env)));

    Ok(())
}

fn test_env() -> anyhow::Result<Arc<RwLock<TestEnv>>> {
    ensure_node_running()?;
    TEST_ENV
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("test env failed to initialize"))
}

#[allow(clippy::cast_precision_loss)]
fn sat_to_btc(satoshi: u64) -> f64 {
    satoshi as f64 / 100_000_000.0
}

fn issue_asset_with_token(env: &TestEnv, amount_sat: u64) -> anyhow::Result<(AssetId, AssetId)> {
    let rpc_url = env.elements_rpc_url();
    let (rpc_user, rpc_password) = env.elements_rpc_credentials();
    let client = Client::new(&rpc_url, Auth::UserPass(rpc_user, rpc_password))
        .context("failed to connect to elements RPC")?;

    let issued: Value = client
        .call("issueasset", &[sat_to_btc(amount_sat).into(), 0.into()])
        .context("issueasset RPC failed")?;

    let asset_id = issued
        .get("asset")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issueasset response missing 'asset'"))?;
    let token_id = issued
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issueasset response missing 'token'"))?;

    let asset_id = AssetId::from_str(asset_id).context("invalid issued asset id")?;
    let token_id = AssetId::from_str(token_id).context("invalid issued token id")?;

    Ok((asset_id, token_id))
}

pub fn issue_and_fund_runtime_token(
    runtime: &mut WalletRuntimeConfig,
    token_amount_sat: u64,
) -> anyhow::Result<RuntimeIssuedTokenPair> {
    if runtime.network != Network::LocaltestLiquid {
        return Err(anyhow!(
            "issue_and_fund_runtime_token supports only Network::LocaltestLiquid"
        ));
    }

    if token_amount_sat == 0 {
        return Err(anyhow!("token_amount_sat must be > 0"));
    }

    let test_env = test_env()?;
    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    let signer_address = runtime.signer_receive_address()?;

    let rpc_url = env.elements_rpc_url();
    let (rpc_user, rpc_password) = env.elements_rpc_credentials();
    let client = Client::new(&rpc_url, Auth::UserPass(rpc_user, rpc_password))
        .context("failed to connect to elements RPC")?;

    let issued: Value = client
        .call(
            "issueasset",
            &[sat_to_btc(1).into(), sat_to_btc(token_amount_sat).into()],
        )
        .context("issueasset RPC failed")?;

    let asset_id = issued
        .get("asset")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issueasset response missing 'asset'"))?;
    let token_id = issued
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issueasset response missing 'token'"))?;
    let entropy_hex = issued
        .get("entropy")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issueasset response missing 'entropy'"))?;

    let asset_id = AssetId::from_str(asset_id).context("invalid issued asset id")?;
    let token_id = AssetId::from_str(token_id).context("invalid issued token id")?;

    let entropy_vec = hex::decode(entropy_hex).context("invalid issued entropy hex")?;
    if entropy_vec.len() != 32 {
        return Err(anyhow!(
            "issued entropy must be 32 bytes, got {}",
            entropy_vec.len()
        ));
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&entropy_vec);

    env.elementsd_generate(1);
    env.elementsd_sendtoaddress(&signer_address, token_amount_sat, Some(token_id));
    env.elementsd_generate(1);
    drop(env);

    Ok(RuntimeIssuedTokenPair {
        asset_id,
        token_id,
        entropy,
    })
}

pub fn fund_runtime(
    runtime: &mut WalletRuntimeConfig,
    asset: RuntimeFundingAsset,
) -> anyhow::Result<(AssetId, Option<AssetId>, u64)> {
    fund_runtime_with_amount(runtime, asset, DEFAULT_FUND_AMOUNT_SAT)
}

pub fn fund_runtime_with_amount(
    runtime: &mut WalletRuntimeConfig,
    asset: RuntimeFundingAsset,
    amount_sat: u64,
) -> anyhow::Result<(AssetId, Option<AssetId>, u64)> {
    if runtime.network != Network::LocaltestLiquid {
        return Err(anyhow!(
            "fund_runtime supports only Network::LocaltestLiquid"
        ));
    }

    if amount_sat == 0 {
        return Err(anyhow!("amount_sat must be > 0"));
    }

    let test_env = test_env()?;
    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    let signer_address = runtime.signer_receive_address()?;

    let (asset_id, token_id) = match asset {
        RuntimeFundingAsset::Lbtc => {
            let lbtc = *runtime.network.policy_asset();
            env.elementsd_sendtoaddress(&signer_address, amount_sat, Some(lbtc));
            env.elementsd_generate(1);
            drop(env);
            (lbtc, None)
        }
        RuntimeFundingAsset::NewAsset => {
            let (issued_asset, token_id) = issue_asset_with_token(&env, amount_sat)?;
            env.elementsd_generate(1);
            env.elementsd_sendtoaddress(&signer_address, amount_sat, Some(issued_asset));
            env.elementsd_generate(1);
            drop(env);
            (issued_asset, Some(token_id))
        }
    };

    Ok((asset_id, token_id, amount_sat))
}

pub fn get_esplora_url() -> anyhow::Result<String> {
    let test_env = test_env()?;
    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    Ok(env.esplora_url())
}

pub fn mine_blocks(blocks: usize) -> anyhow::Result<()> {
    let test_env = test_env()?;
    {
        let env = test_env
            .read()
            .map_err(|_| anyhow!("test env lock poisoned"))?;

        for _ in 0..blocks {
            env.elementsd_generate(1);
        }
    }

    Ok(())
}
