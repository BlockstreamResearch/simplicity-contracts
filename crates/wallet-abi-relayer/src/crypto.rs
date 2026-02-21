use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::hmac;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wallet_abi_transport::wa_relay::WalletAbiRelayRole;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    pub pairing_id: String,
    pub role: WalletAbiRelayRole,
    pub exp: u64,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token format is invalid")]
    InvalidFormat,

    #[error("token version is unsupported")]
    UnsupportedVersion,

    #[error("token payload decode failed: {0}")]
    PayloadDecode(#[from] base64::DecodeError),

    #[error("token payload json parse failed: {0}")]
    ParsePayload(#[from] serde_json::Error),

    #[error("token signature verification failed")]
    InvalidSignature,

    #[error("token pairing_id mismatch")]
    PairingMismatch,

    #[error("token role mismatch")]
    RoleMismatch,

    #[error("token is expired")]
    Expired,
}

pub fn sign_token(secret: &[u8], claims: &TokenClaims) -> Result<String, TokenError> {
    let payload_bytes = serde_json::to_vec(claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_bytes);

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let signature = hmac::sign(&key, payload_b64.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

    Ok(format!("v1.{payload_b64}.{signature_b64}"))
}

pub fn verify_token(
    secret: &[u8],
    token: &str,
    expected_pairing_id: &str,
    expected_role: WalletAbiRelayRole,
    now_ms: u64,
) -> Result<TokenClaims, TokenError> {
    let mut parts = token.split('.');

    let version = parts.next().ok_or(TokenError::InvalidFormat)?;
    if version != "v1" {
        return Err(TokenError::UnsupportedVersion);
    }

    let payload_b64 = parts.next().ok_or(TokenError::InvalidFormat)?;
    let signature_b64 = parts.next().ok_or(TokenError::InvalidFormat)?;

    if parts.next().is_some() {
        return Err(TokenError::InvalidFormat);
    }

    let signature = URL_SAFE_NO_PAD.decode(signature_b64)?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, payload_b64.as_bytes(), &signature)
        .map_err(|_| TokenError::InvalidSignature)?;

    let payload = URL_SAFE_NO_PAD.decode(payload_b64)?;
    let claims: TokenClaims = serde_json::from_slice(&payload)?;

    if claims.pairing_id != expected_pairing_id {
        return Err(TokenError::PairingMismatch);
    }

    if claims.role != expected_role {
        return Err(TokenError::RoleMismatch);
    }

    if now_ms > claims.exp {
        return Err(TokenError::Expired);
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"relay-secret-for-tests";

    #[test]
    fn signs_and_verifies_token() {
        let claims = TokenClaims {
            pairing_id: "pair-1".to_string(),
            role: WalletAbiRelayRole::Web,
            exp: 2_000_000,
        };

        let token = sign_token(SECRET, &claims).expect("sign");
        let decoded = verify_token(SECRET, &token, "pair-1", WalletAbiRelayRole::Web, 1_500_000)
            .expect("verify");

        assert_eq!(decoded, claims);
    }

    #[test]
    fn rejects_role_mismatch() {
        let claims = TokenClaims {
            pairing_id: "pair-1".to_string(),
            role: WalletAbiRelayRole::Web,
            exp: 2_000_000,
        };

        let token = sign_token(SECRET, &claims).expect("sign");
        let err = verify_token(
            SECRET,
            &token,
            "pair-1",
            WalletAbiRelayRole::Phone,
            1_500_000,
        )
        .expect_err("must reject");

        assert!(matches!(err, TokenError::RoleMismatch));
    }

    #[test]
    fn rejects_expired_token() {
        let claims = TokenClaims {
            pairing_id: "pair-1".to_string(),
            role: WalletAbiRelayRole::Web,
            exp: 100,
        };

        let token = sign_token(SECRET, &claims).expect("sign");
        let err = verify_token(SECRET, &token, "pair-1", WalletAbiRelayRole::Web, 101)
            .expect_err("must reject");

        assert!(matches!(err, TokenError::Expired));
    }
}
