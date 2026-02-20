#![allow(clippy::missing_errors_doc)]

use anyhow::anyhow;

use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::{TransactionInfo, TxCreateRequest};

pub async fn execute_request(
    runtime: &mut WalletRuntimeConfig,
    request: TxCreateRequest,
) -> anyhow::Result<TransactionInfo> {
    let response = runtime.process_request(&request).await?;
    let tx_info = response
        .transaction
        .ok_or_else(|| anyhow!("Expected transaction info in runtime response"))?;

    if request.broadcast {
        println!("Broadcasted txid: {}", tx_info.txid);
    } else {
        println!("{}", tx_info.tx_hex);
    }

    Ok(tx_info)
}

pub fn wallet_data_root() -> std::path::PathBuf {
    std::env::var_os("SIMPLICITY_CLI_WALLET_DATA_DIR").map_or_else(
        || std::path::PathBuf::from(".cache/wallet"),
        std::path::PathBuf::from,
    )
}

#[must_use]
pub fn esplora_url_from_network(network: lwk_common::Network) -> String {
    match network {
        lwk_common::Network::Liquid => "https://blockstream.info/liquid/api".to_string(),
        lwk_common::Network::TestnetLiquid => {
            "https://blockstream.info/liquidtestnet/api".to_string()
        }
        lwk_common::Network::LocaltestLiquid => "http://127.0.0.1:3001".to_string(),
    }
}
