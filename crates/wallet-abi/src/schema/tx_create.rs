use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use lwk_wollet::elements::Txid;

use crate::Network;
use crate::schema::types::ErrorInfo;

pub const TX_CREATE_ABI_VERSION: &str = "wallet-create-0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionInfo {
    pub tx_hex: String,
    pub txid: String,
}

pub type TxCreateArtifacts = serde_json::Map<String, serde_json::Value>;

const fn default_broadcast_false() -> bool {
    false
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TxCreateRequest {
    pub abi_version: String,
    #[serde(rename = "type")]
    pub request_type: String,
    pub request_id: String,
    pub network: Network,
    pub schema_uri: String,
    pub branch: String,
    pub params: serde_json::Value,
    pub broadcast: bool,
}

impl<'de> Deserialize<'de> for TxCreateRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawTxCreateRequest {
            abi_version: String,
            #[serde(rename = "type")]
            request_type: String,
            request_id: String,
            network: Network,
            schema_uri: String,
            branch: String,
            params: serde_json::Value,
            #[serde(default = "default_broadcast_false")]
            broadcast: bool,
        }

        let raw = RawTxCreateRequest::deserialize(deserializer)?;
        if raw.abi_version != TX_CREATE_ABI_VERSION {
            return Err(D::Error::custom(format!(
                "expected abi_version={TX_CREATE_ABI_VERSION}, got {}",
                raw.abi_version
            )));
        }
        if raw.request_type != "tx.create" {
            return Err(D::Error::custom(format!(
                "expected type=tx.create, got {}",
                raw.request_type
            )));
        }
        if raw.request_id.trim().is_empty() {
            return Err(D::Error::custom("request_id must not be empty"));
        }
        if raw.branch.trim().is_empty() {
            return Err(D::Error::custom("branch must not be empty"));
        }
        if raw.schema_uri.trim().is_empty() {
            return Err(D::Error::custom("schema_uri must not be empty"));
        }

        Ok(Self {
            abi_version: raw.abi_version,
            request_type: raw.request_type,
            request_id: raw.request_id,
            network: raw.network,
            schema_uri: raw.schema_uri,
            branch: raw.branch,
            params: raw.params,
            broadcast: raw.broadcast,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxCreateResponse {
    pub abi_version: String,
    #[serde(rename = "type")]
    pub response_type: String,
    pub request_id: String,
    pub network: Network,
    pub schema_uri: String,
    pub schema_id: String,
    pub schema_version: String,
    pub branch: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<Txid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<TxCreateArtifacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

impl TxCreateResponse {
    #[must_use]
    pub fn ok(
        request: &TxCreateRequest,
        schema_id: &str,
        schema_version: &str,
        transaction: TransactionInfo,
        broadcast: Option<Txid>,
        artifacts: Option<TxCreateArtifacts>,
    ) -> Self {
        Self {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            response_type: "tx.create.result".to_string(),
            request_id: request.request_id.clone(),
            network: request.network,
            schema_uri: request.schema_uri.clone(),
            schema_id: schema_id.to_string(),
            schema_version: schema_version.to_string(),
            branch: request.branch.clone(),
            status: Status::Ok,
            transaction: Some(transaction),
            broadcast,
            artifacts,
            error: None,
        }
    }

    #[must_use]
    pub fn error(
        request: &TxCreateRequest,
        schema_id: Option<&str>,
        schema_version: Option<&str>,
        code: &str,
        message: &str,
    ) -> Self {
        Self {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            response_type: "tx.create.result".to_string(),
            request_id: request.request_id.clone(),
            network: request.network,
            schema_uri: request.schema_uri.clone(),
            schema_id: schema_id.unwrap_or("unknown").to_string(),
            schema_version: schema_version.unwrap_or("unknown").to_string(),
            branch: request.branch.clone(),
            status: Status::Error,
            transaction: None,
            broadcast: None,
            artifacts: None,
            error: Some(ErrorInfo {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
            }),
        }
    }
}
