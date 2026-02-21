use serde::{Deserialize, Serialize};
use serde_json::Value;
use wallet_abi::schema::tx_create::TxCreateRequest;

#[derive(Debug, Deserialize)]
pub struct HarnessRequest {
    pub id: u64,
    #[serde(flatten)]
    pub command: HarnessCommand,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum HarnessCommand {
    Init {
        mnemonic: Option<String>,
    },
    SignerInfo,
    FundLbtc {
        amount_sat: u64,
    },
    IssueAndFundAsset {
        amount_sat: u64,
    },
    MineBlocks {
        blocks: usize,
    },
    ProcessTxCreate {
        request: TxCreateRequest,
    },
    SingleMempoolTxid {
        label: String,
    },
    ExtractIssuanceInfo {
        tx_hex: String,
        issuance_entropy: Vec<u8>,
    },
    Shutdown,
}

#[derive(Debug, Serialize)]
pub struct HarnessResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitResult {
    pub network: String,
    pub policy_asset_id: String,
    pub signer_address: String,
    pub signer_script_hex: String,
    pub esplora_url: String,
    pub workdir: String,
    pub wallet_data_dir: String,
}

#[derive(Debug, Serialize)]
pub struct SignerInfoResult {
    pub address: String,
    pub script_hex: String,
    pub xonly_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct IssuanceInfoResult {
    pub asset_id: String,
    pub reissuance_token_asset_id: String,
    pub asset_entropy: Vec<u8>,
}
