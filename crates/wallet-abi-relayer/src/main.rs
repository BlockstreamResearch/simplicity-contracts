#![warn(clippy::all, clippy::pedantic)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use config::RelayConfig;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};
use wallet_abi_transport::wa_relay::{WalletAbiRelayServerFrameV1, WalletAbiRelayStatusState};

mod config;
mod crypto;
mod http;
mod state_machine;
mod store;
mod ws;

#[derive(Clone)]
pub struct AppState {
    pub config: RelayConfig,
    pub store: Arc<store::SqliteStore>,
    pub peers: Arc<ws::PeerRegistry>,
    pub hmac_secret: Arc<Vec<u8>>,
}

impl AppState {
    #[must_use]
    pub fn new(
        config: RelayConfig,
        store: Arc<store::SqliteStore>,
        peers: Arc<ws::PeerRegistry>,
        hmac_secret: Vec<u8>,
    ) -> Self {
        Self {
            config,
            store,
            peers,
            hmac_secret: Arc::new(hmac_secret),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let config = RelayConfig::from_env()?;
    config.validate()?;

    if let Some(parent) = config.database_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dir '{}'", parent.display()))?;
    }

    let store = Arc::new(store::SqliteStore::new(&config.database_path)?);
    let peers = Arc::new(ws::PeerRegistry::new());
    let app_state = AppState::new(
        config.clone(),
        Arc::clone(&store),
        Arc::clone(&peers),
        config.hmac_secret.as_bytes().to_vec(),
    );

    spawn_janitor(app_state.clone());

    let app = http::router(app_state.clone());

    info!(
        bind = %config.bind_addr,
        ws_url = %config.public_relay_ws_url,
        db = %config.database_path.display(),
        "starting wallet-abi relayer"
    );

    if config.uses_tls() {
        let cert = config
            .tls_cert_path
            .as_ref()
            .expect("checked by config.validate");
        let key = config
            .tls_key_path
            .as_ref()
            .expect("checked by config.validate");

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .context("failed to load rustls cert/key")?;

        axum_server::bind_rustls(config.bind_addr, tls_config)
            .serve(app.into_make_service())
            .await
            .context("axum tls server failed")?;
    } else {
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("failed to bind TCP listener")?;

        axum::serve(listener, app)
            .await
            .context("axum server failed")?;
    }

    Ok(())
}

fn spawn_janitor(app_state: AppState) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(app_state.config.janitor_interval_ms)).await;
            let now = now_ms();

            match app_state.store.expire_pairings(now) {
                Ok(expired) => {
                    for pairing_id in expired {
                        let _ = app_state.store.add_event(
                            &pairing_id,
                            "pairing_expired",
                            &serde_json::json!({ "expired_at_ms": now }),
                            now,
                        );

                        let frame = WalletAbiRelayServerFrameV1::Status {
                            pairing_id: pairing_id.clone(),
                            state: WalletAbiRelayStatusState::Expired,
                            detail: "pairing expired".to_string(),
                        };
                        app_state.peers.broadcast(&pairing_id, frame).await;
                        app_state.peers.clear_pairing(&pairing_id).await;
                    }
                }
                Err(error) => {
                    error!("janitor failed to expire pairings: {error}");
                }
            }

            let prune_before = now.saturating_sub(app_state.config.event_retention_ms);
            match app_state.store.prune_events(prune_before) {
                Ok(count) => {
                    if count > 0 {
                        info!(count, "pruned old relay events");
                    }
                }
                Err(error) => {
                    warn!("janitor failed to prune events: {error}");
                }
            }
        }
    });
}

#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
