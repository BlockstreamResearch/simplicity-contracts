use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;
use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};

pub const WALLET_ABI_TRANSPORT_VERSION: u64 = 1;
pub const WALLET_ABI_TRANSPORT_KIND_TX_CREATE: &str = "tx_create";
pub const WALLET_ABI_TRANSPORT_REQUEST_PARAM: &str = "wa_v1";
pub const WALLET_ABI_TRANSPORT_RESPONSE_PARAM: &str = "wa_resp_v1";
pub const WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES: usize = 64 * 1024;
pub const WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletAbiTransportCallbackMode {
    SameDeviceHttps,
    BackendPush,
    QrRoundtrip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiTransportCallback {
    pub mode: WalletAbiTransportCallbackMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletAbiTransportRequestV1 {
    pub v: u64,
    pub kind: String,
    pub request_id: String,
    pub origin: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub callback: WalletAbiTransportCallback,
    pub tx_create_request: TxCreateRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiTransportResponseError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiTransportResponseV1 {
    pub v: u64,
    pub request_id: String,
    pub origin: String,
    pub processed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_create_response: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WalletAbiTransportResponseError>,
}

pub struct TransportBuildInput {
    pub request_id: String,
    pub origin: String,
    pub created_at_ms: u64,
    pub ttl_ms: u64,
    pub callback_mode: WalletAbiTransportCallbackMode,
    pub callback_url: Option<String>,
    pub tx_create_request: TxCreateRequest,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("{0}")]
    Validation(String),

    #[error("failed to serialize transport envelope: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to base64url decode transport payload: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("failed to zstd compress transport payload: {0}")]
    Compress(#[source] std::io::Error),

    #[error("failed to parse transport envelope: {0}")]
    Parse(#[source] serde_json::Error),
}

pub fn build_transport_request(
    input: TransportBuildInput,
) -> Result<WalletAbiTransportRequestV1, TransportError> {
    if input.request_id.trim().is_empty() {
        return Err(TransportError::Validation(
            "request_id must not be blank".to_string(),
        ));
    }

    validate_https_url(&input.origin, "origin")?;

    if input.ttl_ms > WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS {
        return Err(TransportError::Validation(format!(
            "ttl_ms must be <= {WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS}",
        )));
    }

    if input.tx_create_request.abi_version != TX_CREATE_ABI_VERSION {
        return Err(TransportError::Validation(format!(
            "tx_create_request.abi_version must be {TX_CREATE_ABI_VERSION}",
        )));
    }

    if input.tx_create_request.request_id != input.request_id {
        return Err(TransportError::Validation(
            "request_id mismatch between transport and tx_create_request".to_string(),
        ));
    }

    let callback = match input.callback_mode {
        WalletAbiTransportCallbackMode::QrRoundtrip => {
            if input.callback_url.is_some() {
                return Err(TransportError::Validation(
                    "callback_url must be omitted for qr_roundtrip".to_string(),
                ));
            }

            WalletAbiTransportCallback {
                mode: WalletAbiTransportCallbackMode::QrRoundtrip,
                url: None,
                session_id: None,
            }
        }
        WalletAbiTransportCallbackMode::SameDeviceHttps
        | WalletAbiTransportCallbackMode::BackendPush => {
            let callback_url = input.callback_url.ok_or_else(|| {
                TransportError::Validation(
                    "callback_url is required for same_device_https and backend_push".to_string(),
                )
            })?;
            validate_https_url(&callback_url, "callback_url")?;

            WalletAbiTransportCallback {
                mode: input.callback_mode,
                url: Some(callback_url),
                session_id: None,
            }
        }
    };

    let expires_at_ms = input
        .created_at_ms
        .checked_add(input.ttl_ms)
        .ok_or_else(|| {
            TransportError::Validation("created_at_ms + ttl_ms overflowed".to_string())
        })?;

    Ok(WalletAbiTransportRequestV1 {
        v: WALLET_ABI_TRANSPORT_VERSION,
        kind: WALLET_ABI_TRANSPORT_KIND_TX_CREATE.to_string(),
        request_id: input.request_id,
        origin: input.origin,
        created_at_ms: input.created_at_ms,
        expires_at_ms,
        callback,
        tx_create_request: input.tx_create_request,
    })
}

pub fn encode_transport_request(
    envelope: &WalletAbiTransportRequestV1,
) -> Result<String, TransportError> {
    let serialized = serde_json::to_vec(envelope)?;
    encode_transport_payload(&serialized)
}

pub fn encode_transport_response(
    envelope: &WalletAbiTransportResponseV1,
) -> Result<String, TransportError> {
    let serialized = serde_json::to_vec(envelope)?;
    encode_transport_payload(&serialized)
}

pub fn decode_transport_request(
    encoded: &str,
) -> Result<WalletAbiTransportRequestV1, TransportError> {
    let payload = decode_transport_payload(encoded)?;
    serde_json::from_slice(&payload).map_err(TransportError::Parse)
}

pub fn decode_transport_response(
    encoded: &str,
) -> Result<WalletAbiTransportResponseV1, TransportError> {
    let payload = decode_transport_payload(encoded)?;
    serde_json::from_slice(&payload).map_err(TransportError::Parse)
}

#[must_use]
pub fn build_deep_link(base_link: &str, encoded_payload: &str) -> String {
    let separator = if base_link.contains('#') { '&' } else { '#' };
    format!("{base_link}{separator}{WALLET_ABI_TRANSPORT_REQUEST_PARAM}={encoded_payload}")
}

#[must_use]
pub fn extract_fragment_param(uri_or_fragment: &str, key: &str) -> Option<String> {
    let fragment = uri_or_fragment
        .split_once('#')
        .map_or(uri_or_fragment, |(_, value)| value)
        .trim_start_matches('#')
        .trim();

    if fragment.is_empty() {
        return None;
    }

    fragment.split('&').find_map(|pair| {
        let (candidate_key, candidate_value) = pair.split_once('=')?;
        if candidate_key == key {
            Some(candidate_value.to_string())
        } else {
            None
        }
    })
}

pub fn validate_https_url(url: &str, field_name: &str) -> Result<(), TransportError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(TransportError::Validation(format!(
            "{field_name} must not be empty"
        )));
    }

    let Some(without_scheme) = trimmed.strip_prefix("https://") else {
        return Err(TransportError::Validation(format!(
            "{field_name} must use https://"
        )));
    };

    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();

    if host.is_empty() {
        return Err(TransportError::Validation(format!(
            "{field_name} must include a host"
        )));
    }

    if host.contains(' ') {
        return Err(TransportError::Validation(format!(
            "{field_name} host must not contain spaces"
        )));
    }

    Ok(())
}

fn encode_transport_payload(serialized: &[u8]) -> Result<String, TransportError> {
    let compressed = zstd::stream::encode_all(serialized, 0).map_err(TransportError::Compress)?;
    Ok(URL_SAFE_NO_PAD.encode(compressed))
}

fn decode_transport_payload(encoded: &str) -> Result<Vec<u8>, TransportError> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;

    let payload = match zstd::stream::decode_all(decoded.as_slice()) {
        Ok(decompressed) => decompressed,
        Err(_) => decoded,
    };

    if payload.len() > WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES {
        return Err(TransportError::Validation(format!(
            "transport payload exceeds {WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES} bytes",
        )));
    }

    Ok(payload)
}
