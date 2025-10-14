use anyhow::Result;
use reqwest::blocking::Client;
use simplicityhl::simplicity::elements::{OutPoint, Transaction, TxOut, encode};
use std::{fs, path::PathBuf, time::Duration};

/// Broadcast a transaction to Liquid testnet Esplora.
/// Returns the txid string on success.
pub fn broadcast_tx(tx: &Transaction) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let tx_hex = encode::serialize_hex(tx);
    let response = client
        .post("https://blockstream.info/liquidtestnet/api/tx")
        .body(tx_hex)
        .send()?;

    let status = response.status();
    let url = response.url().to_string();
    let text = response.text()?;

    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "HTTP error {} for url ({}): {}",
            status,
            url,
            text.trim()
        ));
    }

    Ok(text.trim().to_string())
}

/// Fetch UTXO given the txid and vout
pub fn fetch_utxo(outpoint: OutPoint) -> anyhow::Result<TxOut> {
    // Check file cache first
    let txid_str = outpoint.txid.to_string();
    let cache_path = cache_path_for_txid(&txid_str)?;
    if cache_path.exists() {
        let cached_hex = fs::read_to_string(&cache_path)?;
        return extract_utxo(&cached_hex, outpoint.vout as usize);
    }

    let url = format!(
        "https://blockstream.info/liquidtestnet/api/tx/{}/hex",
        outpoint.txid
    );

    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    let tx_hex = client.get(&url).send()?.error_for_status()?.text()?;
    // Persist to cache best-effort
    if let Err(_e) = fs::write(&cache_path, &tx_hex) {
        // Ignore cache write errors
    }
    extract_utxo(&tx_hex, outpoint.vout as usize)
}

/// Extract UTXO from a raw transaction given its index
fn extract_utxo(tx_hex: &str, vout: usize) -> anyhow::Result<TxOut> {
    let tx_bytes = hex::decode(tx_hex.trim())?;
    let transaction: Transaction = encode::deserialize(&tx_bytes)?;

    if vout >= transaction.output.len() {
        return Err(anyhow::anyhow!("Invalid vout index: {}", vout));
    }

    Ok(transaction.output[vout].clone())
}

/// Resolve cache path for a given txid, ensuring directory exists
fn cache_path_for_txid(txid: &str) -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    dir.push(".cache");
    dir.push("explorer");
    dir.push("tx");
    fs::create_dir_all(&dir)?;
    let mut path = dir;
    path.push(format!("{}.hex", txid));
    Ok(path)
}
