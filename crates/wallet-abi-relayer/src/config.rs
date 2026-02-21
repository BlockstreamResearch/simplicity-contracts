use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use url::Url;
use wallet_abi_transport::wa_transport::WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8787";
const DEFAULT_DB_PATH: &str = ".cache/wallet-abi-relayer/relayer.sqlite3";
const DEFAULT_PUBLIC_WS_URL: &str = "ws://127.0.0.1:8787/v1/ws";
const DEFAULT_HMAC_SECRET: &str = "dev-only-insecure-relay-secret";

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_addr: SocketAddr,
    pub database_path: PathBuf,
    pub public_relay_ws_url: String,
    pub hmac_secret: String,
    pub max_ttl_ms: u64,
    pub janitor_interval_ms: u64,
    pub event_retention_ms: u64,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

impl RelayConfig {
    pub fn from_env() -> Result<Self> {
        let bind_addr = env_var_or_default("WALLET_ABI_RELAYER_BIND_ADDR", DEFAULT_BIND_ADDR)
            .parse::<SocketAddr>()
            .with_context(
                || "WALLET_ABI_RELAYER_BIND_ADDR must be a valid host:port socket address",
            )?;

        let database_path = PathBuf::from(env_var_or_default(
            "WALLET_ABI_RELAYER_DB_PATH",
            DEFAULT_DB_PATH,
        ));

        let public_relay_ws_url =
            env_var_or_default("WALLET_ABI_RELAYER_PUBLIC_WS_URL", DEFAULT_PUBLIC_WS_URL);

        let hmac_secret = env::var("WALLET_ABI_RELAYER_HMAC_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_HMAC_SECRET.to_string());

        let max_ttl_ms = parse_u64_env(
            "WALLET_ABI_RELAYER_MAX_TTL_MS",
            WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS,
        )?;
        let janitor_interval_ms = parse_u64_env("WALLET_ABI_RELAYER_JANITOR_INTERVAL_MS", 30_000)?;
        let event_retention_ms =
            parse_u64_env("WALLET_ABI_RELAYER_EVENT_RETENTION_MS", 86_400_000)?;

        let tls_cert_path = env::var("WALLET_ABI_RELAYER_TLS_CERT_PATH")
            .ok()
            .map(PathBuf::from);
        let tls_key_path = env::var("WALLET_ABI_RELAYER_TLS_KEY_PATH")
            .ok()
            .map(PathBuf::from);

        Ok(Self {
            bind_addr,
            database_path,
            public_relay_ws_url,
            hmac_secret,
            max_ttl_ms,
            janitor_interval_ms,
            event_retention_ms,
            tls_cert_path,
            tls_key_path,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let ws_url = Url::parse(&self.public_relay_ws_url)
            .with_context(|| "WALLET_ABI_RELAYER_PUBLIC_WS_URL must be a valid URL")?;

        let Some(host) = ws_url.host_str() else {
            bail!("WALLET_ABI_RELAYER_PUBLIC_WS_URL must include a host");
        };

        match ws_url.scheme() {
            "ws" => {
                if !is_local_or_private_host(host) {
                    bail!(
                        "ws:// is only allowed for local/private hosts; use wss:// for non-local hosts"
                    );
                }
            }
            "wss" => {
                if self.tls_cert_path.is_none() || self.tls_key_path.is_none() {
                    bail!(
                        "wss:// requires WALLET_ABI_RELAYER_TLS_CERT_PATH and WALLET_ABI_RELAYER_TLS_KEY_PATH"
                    );
                }
            }
            other => {
                bail!("WALLET_ABI_RELAYER_PUBLIC_WS_URL scheme must be ws or wss; got '{other}'");
            }
        }

        if self.max_ttl_ms == 0 || self.max_ttl_ms > WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS {
            bail!(
                "WALLET_ABI_RELAYER_MAX_TTL_MS must be in 1..={WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS}"
            );
        }

        if self.janitor_interval_ms == 0 {
            bail!("WALLET_ABI_RELAYER_JANITOR_INTERVAL_MS must be > 0");
        }

        if self.event_retention_ms == 0 {
            bail!("WALLET_ABI_RELAYER_EVENT_RETENTION_MS must be > 0");
        }

        if self.hmac_secret == DEFAULT_HMAC_SECRET && !is_local_or_private_host(host) {
            bail!("WALLET_ABI_RELAYER_HMAC_SECRET must be set for non-local host deployments");
        }

        if ws_url.scheme() == "wss" {
            if let Some(path) = &self.tls_cert_path
                && !path.exists()
            {
                bail!("TLS cert path '{}' does not exist", path.display());
            }
            if let Some(path) = &self.tls_key_path
                && !path.exists()
            {
                bail!("TLS key path '{}' does not exist", path.display());
            }
        }

        Ok(())
    }

    #[must_use]
    pub const fn uses_tls(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }
}

fn env_var_or_default(key: &str, default_value: &str) -> String {
    env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_value.to_string())
}

fn parse_u64_env(key: &str, default_value: u64) -> Result<u64> {
    let raw = env_var_or_default(key, &default_value.to_string());
    u64::from_str(&raw).with_context(|| format!("{key} must be a valid u64 integer"))
}

fn is_local_or_private_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
        return true;
    }

    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };

    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unique_local(),
    }
}

const fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> RelayConfig {
        RelayConfig {
            bind_addr: "127.0.0.1:8787".parse().expect("addr"),
            database_path: PathBuf::from(":memory:"),
            public_relay_ws_url: "ws://127.0.0.1:8787/v1/ws".to_string(),
            hmac_secret: "secret".to_string(),
            max_ttl_ms: WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS,
            janitor_interval_ms: 30_000,
            event_retention_ms: 86_400_000,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    #[test]
    fn ws_local_is_allowed() {
        let cfg = base_config();
        cfg.validate().expect("local ws should validate");
    }

    #[test]
    fn ws_public_host_is_rejected() {
        let mut cfg = base_config();
        cfg.public_relay_ws_url = "ws://relay.example.com/v1/ws".to_string();

        let err = cfg.validate().expect_err("must reject public ws host");
        assert!(err.to_string().contains("ws:// is only allowed"));
    }

    #[test]
    fn wss_requires_tls_paths() {
        let mut cfg = base_config();
        cfg.public_relay_ws_url = "wss://relay.example.com/v1/ws".to_string();

        let err = cfg.validate().expect_err("must reject missing tls paths");
        assert!(
            err.to_string()
                .contains("requires WALLET_ABI_RELAYER_TLS_CERT_PATH")
        );
    }

    #[test]
    fn unique_local_ipv6_is_private() {
        assert!(is_local_or_private_host("fd00::1"));
        assert!(!is_local_or_private_host("2001:db8::1"));
    }
}
