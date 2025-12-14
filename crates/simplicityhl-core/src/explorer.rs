//! Esplora API client for interacting with Liquid testnet.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use reqwest::Client;
use tokio::fs;

use simplicityhl::simplicity::elements::{OutPoint, Transaction, TxOut, encode};

/// Default Esplora API base URL for Liquid testnet.
pub const DEFAULT_BASE_URL: &str = "https://blockstream.info/liquidtestnet/api";

/// Default request timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Client for interacting with the Esplora API.
#[derive(Debug, Clone)]
pub struct EsploraClient {
    client: Client,
    base_url: String,
}

impl Default for EsploraClient {
    fn default() -> Self {
        Self::new()
    }
}

impl EsploraClient {
    /// Creates a new client with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE_URL)
    }

    /// Creates a new client with a custom base URL.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be built (invalid TLS backend).
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }

    /// Broadcasts a transaction to the network.
    ///
    /// # Returns
    ///
    /// The transaction ID (txid) as a hex string on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The HTTP request fails
    /// - The server rejects the transaction
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String> {
        let tx_hex = encode::serialize_hex(tx);
        let url = format!("{}/tx", self.base_url);

        let response = self
            .client
            .post(&url)
            .body(tx_hex)
            .send()
            .await
            .context("Failed to send broadcast request")?;

        let status = response.status();
        let response_url = response.url().to_string();
        let body = response
            .text()
            .await
            .context("Failed to read response body")?;

        if !status.is_success() {
            anyhow::bail!(
                "Broadcast failed with HTTP {status} for {response_url}: {}",
                body.trim()
            );
        }

        Ok(body.trim().to_owned())
    }

    /// Fetches a UTXO from the network with local file caching.
    ///
    /// The transaction hex is cached locally to avoid redundant network requests.
    /// Cache is stored in `.cache/explorer/tx/{txid}.hex` relative to the current directory.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The network request fails
    /// - The transaction cannot be decoded
    /// - The output index is out of bounds
    pub async fn fetch_utxo(&self, outpoint: OutPoint) -> Result<TxOut> {
        let tx_hex = self.fetch_transaction_hex(outpoint.txid).await?;

        extract_output(&tx_hex, outpoint.vout as usize)
    }

    /// Fetches raw transaction hex, using cache when available.
    async fn fetch_transaction_hex(
        &self,
        tx_id: simplicityhl::simplicity::elements::Txid,
    ) -> Result<String> {
        let cache_path = transaction_cache_path(&tx_id.to_string())?;

        if cache_path.exists() {
            return fs::read_to_string(&cache_path)
                .await
                .context("Failed to read cached transaction");
        }

        let url = format!("{}/tx/{tx_id}/hex", self.base_url);
        let tx_hex = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch transaction")?
            .error_for_status()
            .context("Server returned error status")?
            .text()
            .await
            .context("Failed to read transaction hex")?;

        // (best-effort, ignore errors)
        let _ = fs::write(&cache_path, &tx_hex).await;

        Ok(tx_hex)
    }
}

/// Extracts a specific output from a serialized transaction.
fn extract_output(tx_hex: &str, index: usize) -> Result<TxOut> {
    let tx_bytes = hex::decode(tx_hex.trim()).context("Invalid transaction hex")?;

    let tx: Transaction = encode::deserialize(&tx_bytes).context("Failed to decode transaction")?;

    tx.output
        .get(index)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Output index {index} out of bounds for tx {}", tx.txid()))
}

/// Returns the cache file path for a transaction.
fn transaction_cache_path(txid: &str) -> Result<PathBuf> {
    let mut path = std::env::current_dir().context("Failed to get current directory")?;

    path.extend([".cache", "explorer", "tx"]);

    std::fs::create_dir_all(&path).context("Failed to create cache directory")?;

    path.push(format!("{txid}.hex"));

    Ok(path)
}

/// Broadcasts a transaction using the default Esplora client.
///
/// # Errors
///
/// See [`EsploraClient::broadcast_transaction`].
pub async fn broadcast_tx(tx: &Transaction) -> Result<String> {
    EsploraClient::new().broadcast_transaction(tx).await
}

/// Fetches a UTXO using the default Esplora client.
///
/// # Errors
///
/// See [`EsploraClient::fetch_utxo`].
pub async fn fetch_utxo(outpoint: OutPoint) -> Result<TxOut> {
    EsploraClient::new().fetch_utxo(outpoint).await
}
