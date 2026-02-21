use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use anyhow::{Context, anyhow};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use lwk_test_util::{TestEnv, TestEnvBuilder};
use serde_json::Value;
use simplicityhl::elements::{Address, AssetId, Txid};

pub struct NodeContext {
    pub test_env: Arc<RwLock<TestEnv>>,
    pub esplora_url: String,
}

static TEST_ENV: LazyLock<Mutex<Option<Arc<RwLock<TestEnv>>>>> = LazyLock::new(|| Mutex::new(None));
static TEST_ENV_INIT_LOCK: Mutex<()> = Mutex::new(());
const TARGET_NOFILE_LIMIT: u64 = 8_192;

#[cfg(unix)]
pub fn ensure_finite_nofile_limit() -> anyhow::Result<()> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: `getrlimit` writes to a valid pointer to `rlimit`.
    let read_result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut current) };
    if read_result != 0 {
        return Err(anyhow!(
            "failed to read RLIMIT_NOFILE: {}",
            std::io::Error::last_os_error()
        ));
    }

    if current.rlim_cur != libc::RLIM_INFINITY && current.rlim_max != libc::RLIM_INFINITY {
        return Ok(());
    }

    let target_cap = TARGET_NOFILE_LIMIT as libc::rlim_t;
    let capped_max = if current.rlim_max == libc::RLIM_INFINITY {
        target_cap
    } else {
        current.rlim_max.min(target_cap)
    };

    if capped_max == 0 {
        return Err(anyhow!(
            "cannot set finite RLIMIT_NOFILE: computed hard limit is zero"
        ));
    }

    let capped_cur = if current.rlim_cur == libc::RLIM_INFINITY {
        capped_max
    } else {
        current.rlim_cur.min(capped_max)
    };

    let updated = libc::rlimit {
        rlim_cur: capped_cur,
        rlim_max: capped_max,
    };

    // SAFETY: `setrlimit` reads from a valid pointer to `rlimit`.
    let write_result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const updated) };
    if write_result != 0 {
        return Err(anyhow!(
            "failed to set finite RLIMIT_NOFILE (cur={}, max={}): {}",
            capped_cur,
            capped_max,
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_finite_nofile_limit() -> anyhow::Result<()> {
    Ok(())
}

fn has_required_regtest_binaries() -> bool {
    ["ELEMENTSD_EXEC", "ELECTRS_LIQUID_EXEC"].iter().all(|key| {
        std::env::var(key)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    })
}

fn test_env_slot() -> anyhow::Result<Option<Arc<RwLock<TestEnv>>>> {
    let slot = TEST_ENV
        .lock()
        .map_err(|_| anyhow!("test env slot lock poisoned"))?;
    Ok(slot.clone())
}

fn ensure_test_env() -> anyhow::Result<Arc<RwLock<TestEnv>>> {
    if let Some(env) = test_env_slot()? {
        return Ok(env);
    }

    let _guard = TEST_ENV_INIT_LOCK
        .lock()
        .map_err(|_| anyhow!("test env init lock poisoned"))?;

    if let Some(env) = test_env_slot()? {
        return Ok(env);
    }

    let env = std::panic::catch_unwind(|| TestEnvBuilder::from_env().with_esplora().build())
        .map_err(|panic| {
            panic.downcast_ref::<String>().map_or_else(
                || anyhow!("failed to start regtest test environment"),
                |message| anyhow!("failed to start regtest test environment: {message}"),
            )
        })?;

    let shared = Arc::new(RwLock::new(env));
    {
        let mut slot = TEST_ENV
            .lock()
            .map_err(|_| anyhow!("test env slot lock poisoned"))?;
        *slot = Some(shared.clone());
    }

    Ok(shared)
}

pub fn shutdown_node_context() -> anyhow::Result<()> {
    let test_env = {
        let mut slot = TEST_ENV
            .lock()
            .map_err(|_| anyhow!("test env slot lock poisoned"))?;
        slot.take()
    };
    drop(test_env);
    Ok(())
}

pub fn ensure_node_context() -> anyhow::Result<NodeContext> {
    if !has_required_regtest_binaries() {
        return Err(anyhow!(
            "ELEMENTSD_EXEC and ELECTRS_LIQUID_EXEC must be set for regtest harness"
        ));
    }

    let test_env = ensure_test_env()?;
    let esplora_url = {
        let env = test_env
            .read()
            .map_err(|_| anyhow!("test env lock poisoned"))?;
        env.esplora_url()
    };

    Ok(NodeContext {
        test_env,
        esplora_url,
    })
}

fn rpc_client(env: &TestEnv) -> anyhow::Result<Client> {
    let rpc_url = env.elements_rpc_url();
    let (rpc_user, rpc_password) = env.elements_rpc_credentials();

    Client::new(&rpc_url, Auth::UserPass(rpc_user, rpc_password))
        .context("failed to connect to elements RPC")
}

#[allow(clippy::cast_precision_loss)]
fn sat_to_btc(satoshi: u64) -> f64 {
    satoshi as f64 / 100_000_000.0
}

pub fn fund_lbtc(
    test_env: &Arc<RwLock<TestEnv>>,
    signer_address: &Address,
    policy_asset: AssetId,
    amount_sat: u64,
) -> anyhow::Result<()> {
    if amount_sat == 0 {
        return Err(anyhow!("amount_sat must be > 0"));
    }

    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    env.elementsd_sendtoaddress(signer_address, amount_sat, Some(policy_asset));
    env.elementsd_generate(1);

    Ok(())
}

pub fn issue_and_fund_asset(
    test_env: &Arc<RwLock<TestEnv>>,
    signer_address: &Address,
    amount_sat: u64,
) -> anyhow::Result<AssetId> {
    if amount_sat == 0 {
        return Err(anyhow!("amount_sat must be > 0"));
    }

    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    let client = rpc_client(&env)?;
    let issued: Value = client
        .call("issueasset", &[sat_to_btc(amount_sat).into(), 0.into()])
        .context("issueasset RPC failed")?;

    let asset_id = issued
        .get("asset")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("issueasset response missing 'asset'"))?;
    let asset_id = AssetId::from_str(asset_id).context("invalid issued asset id")?;

    env.elementsd_generate(1);
    env.elementsd_sendtoaddress(signer_address, amount_sat, Some(asset_id));
    env.elementsd_generate(1);

    Ok(asset_id)
}

pub fn mine_blocks(test_env: &Arc<RwLock<TestEnv>>, blocks: usize) -> anyhow::Result<()> {
    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    for _ in 0..blocks {
        env.elementsd_generate(1);
    }

    Ok(())
}

pub fn single_mempool_txid(test_env: &Arc<RwLock<TestEnv>>, label: &str) -> anyhow::Result<Txid> {
    let env = test_env
        .read()
        .map_err(|_| anyhow!("test env lock poisoned"))?;

    let client = rpc_client(&env)?;
    let mempool: Vec<String> = client
        .call("getrawmempool", &[])
        .with_context(|| format!("failed to query mempool for {label}"))?;

    if mempool.len() != 1 {
        return Err(anyhow!(
            "expected exactly one mempool tx for {label}, got {} ({mempool:?})",
            mempool.len()
        ));
    }

    Txid::from_str(&mempool[0]).with_context(|| format!("invalid txid in mempool for {label}"))
}
