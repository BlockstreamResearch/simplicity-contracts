//! Esplora API client for interacting with Liquid testnet.

use std::path::PathBuf;
use std::time::Duration;

use tokio::fs;

use simplicityhl::simplicity::elements::{OutPoint, Transaction, TxOut, encode};

/// Default Esplora API base URL for Liquid testnet.
pub const DEFAULT_BASE_URL: &str = "https://blockstream.info/liquidtestnet/api";

/// Default request timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Client for interacting with the Esplora API.
#[derive(Debug, Clone)]
pub struct EsploraClient {
    base_url: String,
    timeout: Duration,
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
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
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
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<String, ExplorerError> {
        let tx_hex = encode::serialize_hex(tx);
        let url = format!("{}/tx", self.base_url);
        let timeout_secs = self.timeout.as_secs();

        let response = tokio::task::spawn_blocking(move || {
            minreq::post(&url)
                .with_timeout(timeout_secs)
                .with_body(tx_hex)
                .send()
        })
        .await
        .map_err(|e| ExplorerError::TaskJoin(e.to_string()))??;

        let status = response.status_code;
        let body = response.as_str().unwrap_or("").trim().to_owned();

        if !(200..300).contains(&status) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            return Err(ExplorerError::BroadcastRejected {
                status: status as u16, // HTTP status codes are always positive and fit in u16
                url: format!("{}/tx", self.base_url),
                message: body,
            });
        }

        Ok(body)
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
    pub async fn fetch_utxo(&self, outpoint: OutPoint) -> Result<TxOut, ExplorerError> {
        let tx_hex = self.fetch_transaction_hex(outpoint.txid).await?;

        extract_output(&tx_hex, outpoint.vout as usize)
    }

    /// Fetches raw transaction hex, using cache when available.
    async fn fetch_transaction_hex(
        &self,
        tx_id: simplicityhl::simplicity::elements::Txid,
    ) -> Result<String, ExplorerError> {
        let cache_path = transaction_cache_path(&tx_id.to_string())?;

        if cache_path.exists() {
            return Ok(fs::read_to_string(&cache_path).await?);
        }

        let url = format!("{}/tx/{tx_id}/hex", self.base_url);
        let timeout_secs = self.timeout.as_secs();

        let response = tokio::task::spawn_blocking(move || {
            minreq::get(&url).with_timeout(timeout_secs).send()
        })
        .await
        .map_err(|e| ExplorerError::TaskJoin(e.to_string()))??;

        if !(200..300).contains(&response.status_code) {
            return Err(ExplorerError::HttpRequest(format!(
                "Request failed with status {}",
                response.status_code
            )));
        }

        let tx_hex = response.as_str().unwrap_or("").to_owned();

        // (best-effort, ignore errors)
        let _ = fs::write(&cache_path, &tx_hex).await;

        Ok(tx_hex)
    }
}

/// Extracts a specific output from a serialized transaction.
fn extract_output(tx_hex: &str, index: usize) -> Result<TxOut, ExplorerError> {
    let tx_bytes = hex::decode(tx_hex.trim())?;

    let tx: Transaction = encode::deserialize(&tx_bytes)?;

    tx.output
        .get(index)
        .cloned()
        .ok_or_else(|| ExplorerError::OutputIndexOutOfBounds {
            index,
            txid: tx.txid().to_string(),
        })
}

/// Returns the cache file path for a transaction.
fn transaction_cache_path(txid: &str) -> Result<PathBuf, ExplorerError> {
    let mut path = std::env::current_dir()?;

    path.extend([".cache", "explorer", "tx"]);

    std::fs::create_dir_all(&path)?;

    path.push(format!("{txid}.hex"));

    Ok(path)
}

/// Broadcasts a transaction using the default Esplora client.
///
/// # Errors
///
/// See [`EsploraClient::broadcast_transaction`].
pub async fn broadcast_tx(tx: &Transaction) -> Result<String, ExplorerError> {
    EsploraClient::new().broadcast_transaction(tx).await
}

/// Fetches a UTXO using the default Esplora client.
///
/// # Errors
///
/// See [`EsploraClient::fetch_utxo`].
pub async fn fetch_utxo(outpoint: OutPoint) -> Result<TxOut, ExplorerError> {
    EsploraClient::new().fetch_utxo(outpoint).await
}

/// Errors that occur when interacting with the Esplora API or local cache.
///
/// These errors are returned by [`EsploraClient`](crate::EsploraClient) methods
/// for broadcasting transactions and fetching UTXOs.
#[derive(Debug, thiserror::Error)]
pub enum ExplorerError {
    /// Returned when an HTTP request to the Esplora API fails.
    #[error("HTTP request failed: {0}")]
    HttpRequest(String),

    /// Returned when minreq encounters an error.
    #[error("HTTP error: {0}")]
    Minreq(#[from] minreq::Error),

    /// Returned when a tokio task join fails.
    #[error("Task join error: {0}")]
    TaskJoin(String),

    #[error("Broadcast failed with HTTP {status} for {url}: {message}")]
    BroadcastRejected {
        status: u16,
        url: String,
        message: String,
    },

    /// Returned when a filesystem operation fails (cache read/write, directory creation).
    #[error("IO operation failed: {0}")]
    Io(#[from] std::io::Error),

    /// Returned when transaction data is not valid hexadecimal.
    #[error("Invalid transaction hex: {0}")]
    InvalidTransactionHex(#[from] hex::FromHexError),

    /// Returned when raw transaction bytes cannot be parsed.
    #[error("Failed to deserialize transaction: {0}")]
    TransactionDeserialize(#[from] simplicityhl::simplicity::elements::encode::Error),

    /// Returned when the requested output index does not exist in the transaction.
    #[error("Output index {index} out of bounds for transaction {txid}")]
    OutputIndexOutOfBounds { index: usize, txid: String },
}
