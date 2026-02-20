use serde::{Deserialize, Serialize};

use lwk_wollet::elements::Txid;

use crate::schema::types::ErrorInfo;
use crate::{Network, RuntimeParams, WalletAbiError};

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

/// Transaction-create request envelope for the `wallet-create-0.1` ABI.
///
/// `abi_version` and `network` are contract-level fields and should be validated
/// by runtime entrypoints before any wallet/network side effects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxCreateRequest {
    pub abi_version: String,
    pub request_id: String,
    pub network: Network,
    pub params: RuntimeParams,
    pub broadcast: bool,
}

impl TxCreateRequest {
    /// Validate request-level contract fields against the active runtime context.
    ///
    /// # Errors
    ///
    /// Returns [`WalletAbiError::InvalidRequest`] when `abi_version` or `network`
    /// does not match runtime expectations.
    pub fn validate_for_runtime(&self, runtime_network: Network) -> Result<(), WalletAbiError> {
        if self.abi_version != TX_CREATE_ABI_VERSION {
            return Err(WalletAbiError::InvalidRequest(format!(
                "request abi_version mismatch: expected '{TX_CREATE_ABI_VERSION}', got '{}'",
                self.abi_version
            )));
        }

        if self.network != runtime_network {
            return Err(WalletAbiError::InvalidRequest(format!(
                "request network mismatch: expected {:?}, got {:?}",
                runtime_network, self.network
            )));
        }

        Ok(())
    }
}

/// Transaction-create response envelope for the `wallet-create-0.1` ABI.
///
/// Runtime currently returns `Result<TxCreateResponse, WalletAbiError>`.
/// This type is still useful for adapters that always emit ABI envelopes.
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
    /// Build a successful ABI response envelope.
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

    /// Build an error ABI response envelope.
    ///
    /// Intended for transport/adapters that must always return ABI responses
    /// instead of bubbling runtime errors.
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
