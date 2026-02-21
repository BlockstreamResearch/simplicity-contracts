use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ring::hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;
use url::Url;

pub const WALLET_ABI_RELAY_VERSION: u64 = 1;
pub const WALLET_ABI_RELAY_PAIRING_PARAM: &str = "wa_relay_v1";
pub const WALLET_ABI_RELAY_MAX_DECODED_BYTES: usize = 64 * 1024;
pub const WALLET_ABI_RELAY_CHANNEL_KEY_BYTES: usize = 32;
pub const WALLET_ABI_RELAY_NONCE_BYTES: usize = 24;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletAbiRelayAlgorithm {
    Xchacha20poly1305HkdfSha256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiRelayPairingV1 {
    pub v: u64,
    pub pairing_id: String,
    pub relay_ws_url: String,
    pub expires_at_ms: u64,
    pub phone_token: String,
    pub channel_key_b64: String,
    pub alg: WalletAbiRelayAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiRelayRequestV1 {
    pub v: u64,
    pub pairing_id: String,
    pub request_id: String,
    pub origin: String,
    pub tx_create_request: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiRelayResponseError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAbiRelayResponseV1 {
    pub v: u64,
    pub pairing_id: String,
    pub request_id: String,
    pub origin: String,
    pub processed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_create_response: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WalletAbiRelayResponseError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WalletAbiRelayRole {
    Web,
    Phone,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletAbiRelayDirection {
    WebToPhone,
    PhoneToWeb,
}

impl WalletAbiRelayDirection {
    #[must_use]
    pub const fn expected_sender_role(self) -> WalletAbiRelayRole {
        match self {
            Self::WebToPhone => WalletAbiRelayRole::Web,
            Self::PhoneToWeb => WalletAbiRelayRole::Phone,
        }
    }

    #[must_use]
    pub const fn expected_receiver_role(self) -> WalletAbiRelayRole {
        match self {
            Self::WebToPhone => WalletAbiRelayRole::Phone,
            Self::PhoneToWeb => WalletAbiRelayRole::Web,
        }
    }

    #[must_use]
    pub const fn hkdf_info_label(self) -> &'static [u8] {
        match self {
            Self::WebToPhone => b"web_to_phone",
            Self::PhoneToWeb => b"phone_to_web",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletAbiRelayStatusState {
    PeerConnected,
    RequestSent,
    ResponseSent,
    Closed,
    Expired,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalletAbiRelayClientFrameV1 {
    Auth {
        pairing_id: String,
        role: WalletAbiRelayRole,
        token: String,
    },
    Publish {
        pairing_id: String,
        direction: WalletAbiRelayDirection,
        msg_id: String,
        nonce_b64: String,
        ciphertext_b64: String,
    },
    Ack {
        pairing_id: String,
        msg_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalletAbiRelayServerFrameV1 {
    Ack {
        pairing_id: String,
        msg_id: String,
    },
    Deliver {
        pairing_id: String,
        direction: WalletAbiRelayDirection,
        msg_id: String,
        nonce_b64: String,
        ciphertext_b64: String,
        created_at_ms: u64,
    },
    Status {
        pairing_id: String,
        state: WalletAbiRelayStatusState,
        detail: String,
    },
    Error {
        pairing_id: Option<String>,
        code: String,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum WalletAbiRelayError {
    #[error("{0}")]
    Validation(String),

    #[error("failed to serialize relay payload: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to decode base64url payload: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("failed to zstd compress payload: {0}")]
    Compress(#[source] std::io::Error),

    #[error("failed to parse relay payload: {0}")]
    Parse(#[source] serde_json::Error),

    #[error("invalid ws URL in pairing payload")]
    InvalidWsUrl,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed")]
    Decrypt,
}

pub type RelayChannelKey = [u8; WALLET_ABI_RELAY_CHANNEL_KEY_BYTES];
pub type RelayNonce = [u8; WALLET_ABI_RELAY_NONCE_BYTES];

pub fn validate_pairing_metadata(
    pairing: &WalletAbiRelayPairingV1,
) -> Result<(), WalletAbiRelayError> {
    if pairing.v != WALLET_ABI_RELAY_VERSION {
        return Err(WalletAbiRelayError::Validation(format!(
            "pairing.v must be {WALLET_ABI_RELAY_VERSION}",
        )));
    }

    if pairing.pairing_id.trim().is_empty() {
        return Err(WalletAbiRelayError::Validation(
            "pairing_id must not be empty".to_string(),
        ));
    }

    validate_ws_url(&pairing.relay_ws_url)?;

    if pairing.expires_at_ms == 0 {
        return Err(WalletAbiRelayError::Validation(
            "expires_at_ms must be greater than zero".to_string(),
        ));
    }

    if pairing.phone_token.trim().is_empty() {
        return Err(WalletAbiRelayError::Validation(
            "phone_token must not be empty".to_string(),
        ));
    }

    let _ = decode_channel_key_b64(&pairing.channel_key_b64)?;

    if pairing.alg != WalletAbiRelayAlgorithm::Xchacha20poly1305HkdfSha256 {
        return Err(WalletAbiRelayError::Validation(
            "unsupported relay algorithm".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_ws_url(url: &str) -> Result<(), WalletAbiRelayError> {
    let parsed = Url::parse(url).map_err(|_| WalletAbiRelayError::InvalidWsUrl)?;

    let scheme = parsed.scheme();
    if scheme != "ws" && scheme != "wss" {
        return Err(WalletAbiRelayError::Validation(
            "relay_ws_url must use ws:// or wss://".to_string(),
        ));
    }

    if parsed.host_str().is_none() {
        return Err(WalletAbiRelayError::Validation(
            "relay_ws_url must include a host".to_string(),
        ));
    }

    Ok(())
}

pub fn encode_relay_pairing(
    pairing: &WalletAbiRelayPairingV1,
) -> Result<String, WalletAbiRelayError> {
    validate_pairing_metadata(pairing)?;
    let serialized = serde_json::to_vec(pairing)?;
    let compressed = zstd::stream::encode_all(serialized.as_slice(), 0)
        .map_err(WalletAbiRelayError::Compress)?;
    Ok(URL_SAFE_NO_PAD.encode(compressed))
}

pub fn decode_relay_pairing(encoded: &str) -> Result<WalletAbiRelayPairingV1, WalletAbiRelayError> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    let payload = decode_compressed_or_raw(&decoded)?;
    let pairing: WalletAbiRelayPairingV1 =
        serde_json::from_slice(&payload).map_err(WalletAbiRelayError::Parse)?;
    validate_pairing_metadata(&pairing)?;
    Ok(pairing)
}

#[must_use]
pub fn build_relay_deep_link(base_link: &str, encoded_payload: &str) -> String {
    let separator = if base_link.contains('#') { '&' } else { '#' };
    format!("{base_link}{separator}{WALLET_ABI_RELAY_PAIRING_PARAM}={encoded_payload}")
}

#[must_use]
pub fn encode_channel_key_b64(key: &RelayChannelKey) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

pub fn decode_channel_key_b64(encoded: &str) -> Result<RelayChannelKey, WalletAbiRelayError> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    if decoded.len() != WALLET_ABI_RELAY_CHANNEL_KEY_BYTES {
        return Err(WalletAbiRelayError::Validation(format!(
            "channel key must be {WALLET_ABI_RELAY_CHANNEL_KEY_BYTES} bytes",
        )));
    }

    let mut key = [0_u8; WALLET_ABI_RELAY_CHANNEL_KEY_BYTES];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[must_use]
pub fn encode_nonce_b64(nonce: &RelayNonce) -> String {
    URL_SAFE_NO_PAD.encode(nonce)
}

pub fn decode_nonce_b64(encoded: &str) -> Result<RelayNonce, WalletAbiRelayError> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    if decoded.len() != WALLET_ABI_RELAY_NONCE_BYTES {
        return Err(WalletAbiRelayError::Validation(format!(
            "nonce must be {WALLET_ABI_RELAY_NONCE_BYTES} bytes",
        )));
    }

    let mut nonce = [0_u8; WALLET_ABI_RELAY_NONCE_BYTES];
    nonce.copy_from_slice(&decoded);
    Ok(nonce)
}

pub fn derive_directional_key(
    channel_key: &RelayChannelKey,
    pairing_id: &str,
    direction: WalletAbiRelayDirection,
) -> Result<[u8; 32], WalletAbiRelayError> {
    if pairing_id.trim().is_empty() {
        return Err(WalletAbiRelayError::Validation(
            "pairing_id must not be empty".to_string(),
        ));
    }

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, pairing_id.as_bytes());
    let prk = salt.extract(channel_key);
    let key_type = HkdfLen(32);
    let info = [
        b"wallet_abi_relay_v1".as_slice(),
        direction.hkdf_info_label(),
    ];
    let okm = prk
        .expand(&info, key_type)
        .map_err(|_| WalletAbiRelayError::KeyDerivation)?;

    let mut out = [0_u8; 32];
    okm.fill(&mut out)
        .map_err(|_| WalletAbiRelayError::KeyDerivation)?;
    Ok(out)
}

#[must_use]
pub fn build_relay_aad(
    pairing_id: &str,
    direction: WalletAbiRelayDirection,
    msg_id: &str,
) -> Vec<u8> {
    format!("{pairing_id}|{direction}|{msg_id}").into_bytes()
}

pub fn encrypt_relay_payload(
    channel_key: &RelayChannelKey,
    pairing_id: &str,
    direction: WalletAbiRelayDirection,
    msg_id: &str,
    nonce: &RelayNonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, WalletAbiRelayError> {
    let derived = derive_directional_key(channel_key, pairing_id, direction)?;
    let aad = build_relay_aad(pairing_id, direction, msg_id);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| WalletAbiRelayError::Encrypt)
}

pub fn decrypt_relay_payload(
    channel_key: &RelayChannelKey,
    pairing_id: &str,
    direction: WalletAbiRelayDirection,
    msg_id: &str,
    nonce: &RelayNonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WalletAbiRelayError> {
    let derived = derive_directional_key(channel_key, pairing_id, direction)?;
    let aad = build_relay_aad(pairing_id, direction, msg_id);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| WalletAbiRelayError::Decrypt)
}

#[must_use]
pub fn encode_ciphertext_b64(ciphertext: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(ciphertext)
}

pub fn decode_ciphertext_b64(encoded: &str) -> Result<Vec<u8>, WalletAbiRelayError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(WalletAbiRelayError::Base64)
}

fn decode_compressed_or_raw(bytes: &[u8]) -> Result<Vec<u8>, WalletAbiRelayError> {
    let payload = match zstd::stream::decode_all(bytes) {
        Ok(decompressed) => decompressed,
        Err(_) => bytes.to_vec(),
    };

    if payload.len() > WALLET_ABI_RELAY_MAX_DECODED_BYTES {
        return Err(WalletAbiRelayError::Validation(format!(
            "relay payload exceeds {WALLET_ABI_RELAY_MAX_DECODED_BYTES} bytes",
        )));
    }

    Ok(payload)
}

#[derive(Clone, Copy)]
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl fmt::Display for WalletAbiRelayDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebToPhone => f.write_str("web_to_phone"),
            Self::PhoneToWeb => f.write_str("phone_to_web"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> RelayChannelKey {
        [0x11; WALLET_ABI_RELAY_CHANNEL_KEY_BYTES]
    }

    #[test]
    fn pairing_roundtrip_encode_decode() {
        let pairing = WalletAbiRelayPairingV1 {
            v: WALLET_ABI_RELAY_VERSION,
            pairing_id: "pair-1".to_string(),
            relay_ws_url: "ws://127.0.0.1:8787/v1/ws".to_string(),
            expires_at_ms: 1_700_000_120_000,
            phone_token: "token-phone".to_string(),
            channel_key_b64: encode_channel_key_b64(&sample_key()),
            alg: WalletAbiRelayAlgorithm::Xchacha20poly1305HkdfSha256,
        };

        let encoded = encode_relay_pairing(&pairing).expect("encode");
        let decoded = decode_relay_pairing(&encoded).expect("decode");

        assert_eq!(pairing, decoded);
    }

    #[test]
    fn pairing_rejects_non_ws_url() {
        let pairing = WalletAbiRelayPairingV1 {
            v: WALLET_ABI_RELAY_VERSION,
            pairing_id: "pair-1".to_string(),
            relay_ws_url: "https://example.com/ws".to_string(),
            expires_at_ms: 1_700_000_120_000,
            phone_token: "token-phone".to_string(),
            channel_key_b64: encode_channel_key_b64(&sample_key()),
            alg: WalletAbiRelayAlgorithm::Xchacha20poly1305HkdfSha256,
        };

        let err = validate_pairing_metadata(&pairing).expect_err("must fail");
        assert!(err.to_string().contains("ws:// or wss://"));
    }

    #[test]
    fn key_and_nonce_roundtrip() {
        let key = sample_key();
        let encoded = encode_channel_key_b64(&key);
        let decoded = decode_channel_key_b64(&encoded).expect("decode key");
        assert_eq!(key, decoded);

        let nonce: RelayNonce = [0x22; WALLET_ABI_RELAY_NONCE_BYTES];
        let encoded_nonce = encode_nonce_b64(&nonce);
        let decoded_nonce = decode_nonce_b64(&encoded_nonce).expect("decode nonce");
        assert_eq!(nonce, decoded_nonce);
    }

    #[test]
    fn xchacha_encrypt_decrypt_roundtrip() {
        let channel_key = sample_key();
        let nonce: RelayNonce = [0x22; WALLET_ABI_RELAY_NONCE_BYTES];
        let plaintext = b"{\"request_id\":\"req-1\"}";

        let ciphertext = encrypt_relay_payload(
            &channel_key,
            "pair-1",
            WalletAbiRelayDirection::WebToPhone,
            "msg-1",
            &nonce,
            plaintext,
        )
        .expect("encrypt");

        let decrypted = decrypt_relay_payload(
            &channel_key,
            "pair-1",
            WalletAbiRelayDirection::WebToPhone,
            "msg-1",
            &nonce,
            &ciphertext,
        )
        .expect("decrypt");

        assert_eq!(plaintext.as_slice(), decrypted);
    }

    #[test]
    fn deterministic_ciphertext_vector_is_stable() {
        let channel_key = sample_key();
        let nonce: RelayNonce = [0x22; WALLET_ABI_RELAY_NONCE_BYTES];
        let plaintext = b"{\"request_id\":\"req-1\"}";

        let ciphertext = encrypt_relay_payload(
            &channel_key,
            "pair-1",
            WalletAbiRelayDirection::WebToPhone,
            "msg-1",
            &nonce,
            plaintext,
        )
        .expect("encrypt");

        assert_eq!(
            hex::encode(ciphertext),
            "0398150cd1167eacfc6f87bca67c9b7399113ec70071fc01bd858fd81d94b06dcb90023a7205"
        );
    }
}
