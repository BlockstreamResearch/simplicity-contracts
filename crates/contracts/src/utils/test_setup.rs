#![allow(clippy::missing_errors_doc)]

use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};

use anyhow::{Context, anyhow};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use lwk_test_util::{TestEnv, TestEnvBuilder};
use serde_json::Value;
use simplicityhl::elements::AssetId;
use wallet_abi::Network;
use wallet_abi::runtime::WalletRuntimeConfig;

const DEFAULT_FUND_AMOUNT_SAT: u64 = 1_000_000;

static TEST_ENV: LazyLock<Mutex<Option<Arc<RwLock<TestEnv>>>>> = LazyLock::new(|| Mutex::new(None));
static TEST_ENV_INIT_LOCK: Mutex<()> = Mutex::new(());
static SHUTDOWN_HOOK_REGISTRATION: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFundingAsset {
    Lbtc,
    NewAsset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFundingResult {
    pub funded_asset_id: AssetId,
    pub issued_token_id: Option<AssetId>,
    pub funded_amount_sat: u64,
}

#[cfg(unix)]
extern "C" fn shutdown_node_running_on_exit() {
    let _ = shutdown_node_running();
}

fn ensure_shutdown_hook_registered() -> anyhow::Result<()> {
    let registration = SHUTDOWN_HOOK_REGISTRATION.get_or_init(|| {
        #[cfg(unix)]
        {
            // SAFETY: The callback uses C ABI and takes no arguments as required by `atexit`.
            let status = unsafe { libc::atexit(shutdown_node_running_on_exit) };
            if status != 0 {
                return Err("failed to register regtest shutdown hook".to_string());
            }
        }

        Ok(())
    });

    registration
        .as_ref()
        .map(|_| ())
        .map_err(|message| anyhow!("{message}"))
}

fn test_env_slot() -> anyhow::Result<Option<Arc<RwLock<TestEnv>>>> {
    let slot = TEST_ENV
        .lock()
        .map_err(|_| anyhow!("test env slot lock poisoned"))?;
    Ok(slot.clone())
}

pub fn ensure_node_running() -> anyhow::Result<()> {
    ensure_shutdown_hook_registered()?;

    if test_env_slot()?.is_some() {
        return Ok(());
    }

    let _init_guard = TEST_ENV_INIT_LOCK
        .lock()
        .map_err(|_| anyhow!("test env init lock poisoned"))?;
    if test_env_slot()?.is_some() {
        return Ok(());
    }

    for var in ["ELEMENTSD_EXEC", "ELECTRS_LIQUID_EXEC"] {
        if std::env::var(var)
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(anyhow!("{var} must be set"));
        }
    }

    let env = std::panic::catch_unwind(|| TestEnvBuilder::from_env().with_esplora().build())
        .map_err(|panic| {
            panic.downcast_ref::<String>().map_or_else(
                || anyhow!("failed to start regtest test environment"),
                |message| anyhow!("failed to start regtest test environment: {message}"),
            )
        })?;

    {
        let mut slot = TEST_ENV
            .lock()
            .map_err(|_| anyhow!("test env slot lock poisoned"))?;
        *slot = Some(Arc::new(RwLock::new(env)));
    }

    Ok(())
}

pub fn shutdown_node_running() -> anyhow::Result<()> {
    let test_env = {
        let mut slot = TEST_ENV
            .lock()
            .map_err(|_| anyhow!("test env slot lock poisoned"))?;
        slot.take()
    };
    drop(test_env);
    Ok(())
}

/// Return the wallet data root path for integration tests.
///
/// Uses `SIMPLICITY_CLI_WALLET_DATA_DIR` if set; otherwise falls back to a
/// deterministic workspace-relative path rooted at `CARGO_MANIFEST_DIR`.
pub fn wallet_data_root() -> std::path::PathBuf {
    std::env::var_os("SIMPLICITY_CLI_WALLET_DATA_DIR").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.cache/wallet"),
        std::path::PathBuf::from,
    )
}

fn test_env() -> anyhow::Result<Arc<RwLock<TestEnv>>> {
    ensure_node_running()?;
    test_env_slot()?.ok_or_else(|| anyhow!("test env failed to initialize"))
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

pub fn fund_runtime(
    runtime: &WalletRuntimeConfig,
    asset: RuntimeFundingAsset,
) -> anyhow::Result<RuntimeFundingResult> {
    fund_runtime_with_amount(runtime, asset, DEFAULT_FUND_AMOUNT_SAT)
}

pub fn fund_runtime_with_amount(
    runtime: &WalletRuntimeConfig,
    asset: RuntimeFundingAsset,
    amount_sat: u64,
) -> anyhow::Result<RuntimeFundingResult> {
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

    Ok(RuntimeFundingResult {
        funded_asset_id: asset_id,
        issued_token_id: token_id,
        funded_amount_sat: amount_sat,
    })
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
