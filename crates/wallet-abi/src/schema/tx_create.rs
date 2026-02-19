use serde::{Deserialize, Serialize};

use lwk_wollet::elements::Txid;

use crate::schema::types::ErrorInfo;
use crate::{Network, RuntimeParams};

pub const TX_CREATE_ABI_VERSION: &str = "wallet-create-0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionInfo {
    pub tx_hex: String,
    pub txid: Txid,
}

pub type TxCreateArtifacts = serde_json::Map<String, serde_json::Value>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxCreateRequest {
    pub abi_version: String,
    pub request_id: String,
    pub network: Network,
    pub params: RuntimeParams,
    pub broadcast: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxCreateResponse {
    pub abi_version: String,
    pub request_id: String,
    pub network: Network,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<TxCreateArtifacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

impl TxCreateResponse {
    #[must_use]
    pub fn ok(
        request: &TxCreateRequest,
        transaction: TransactionInfo,
        artifacts: Option<TxCreateArtifacts>,
    ) -> Self {
        Self {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: request.request_id.clone(),
            network: request.network,
            status: Status::Ok,
            transaction: Some(transaction),
            artifacts,
            error: None,
        }
    }

    #[must_use]
    pub fn error(request: &TxCreateRequest, code: &str, message: &str) -> Self {
        Self {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: request.request_id.clone(),
            network: request.network,
            status: Status::Error,
            transaction: None,
            artifacts: None,
            error: Some(ErrorInfo {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
            }),
        }
    }
}
