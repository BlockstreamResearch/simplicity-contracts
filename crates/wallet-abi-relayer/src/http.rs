use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use wallet_abi_transport::wa_transport::validate_https_url;

use crate::crypto::{TokenClaims, sign_token};
use crate::{AppState, now_ms, ws};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/pairings", post(create_pairing))
        .route(
            "/v1/pairings/{pairing_id}",
            get(get_pairing).delete(delete_pairing),
        )
        .route("/v1/ws", get(ws::ws_handler))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct CreatePairingRequest {
    origin: String,
    request_id: String,
    network: String,
    ttl_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CreatePairingResponse {
    pairing_id: String,
    relay_ws_url: String,
    expires_at_ms: u64,
    web_token: String,
    phone_token: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn create_pairing(
    State(state): State<AppState>,
    Json(payload): Json<CreatePairingRequest>,
) -> Result<Json<CreatePairingResponse>, ApiError> {
    if payload.request_id.trim().is_empty() {
        return Err(ApiError::bad_request("request_id must not be empty"));
    }
    if payload.network.trim().is_empty() {
        return Err(ApiError::bad_request("network must not be empty"));
    }

    validate_https_url(&payload.origin, "origin")
        .map_err(|error| ApiError::bad_request(error.to_string()))?;

    let ttl_ms = payload.ttl_ms.unwrap_or(state.config.max_ttl_ms);
    if ttl_ms == 0 || ttl_ms > state.config.max_ttl_ms {
        return Err(ApiError::bad_request(format!(
            "ttl_ms must be in 1..={} ms",
            state.config.max_ttl_ms
        )));
    }

    let created_at_ms = now_ms();
    let expires_at_ms = created_at_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| ApiError::bad_request("created_at_ms + ttl_ms overflowed"))?;

    let pairing_id = Uuid::new_v4().to_string();

    let web_token = sign_token(
        state.hmac_secret.as_slice(),
        &TokenClaims {
            pairing_id: pairing_id.clone(),
            role: wallet_abi_transport::wa_relay::WalletAbiRelayRole::Web,
            exp: expires_at_ms,
        },
    )
    .map_err(|error| ApiError::internal(error.to_string()))?;

    let phone_token = sign_token(
        state.hmac_secret.as_slice(),
        &TokenClaims {
            pairing_id: pairing_id.clone(),
            role: wallet_abi_transport::wa_relay::WalletAbiRelayRole::Phone,
            exp: expires_at_ms,
        },
    )
    .map_err(|error| ApiError::internal(error.to_string()))?;

    state
        .store
        .create_pairing(&crate::store::CreatePairingInput {
            pairing_id: pairing_id.clone(),
            origin: payload.origin,
            request_id: payload.request_id,
            network: payload.network,
            created_at_ms,
            expires_at_ms,
            state: "created".to_string(),
        })
        .map_err(|error| ApiError::internal(error.to_string()))?;

    state
        .store
        .add_event(
            &pairing_id,
            "pairing_created",
            &json!({
                "expires_at_ms": expires_at_ms,
                "relay_ws_url": state.config.public_relay_ws_url,
            }),
            created_at_ms,
        )
        .map_err(|error| ApiError::internal(error.to_string()))?;

    Ok(Json(CreatePairingResponse {
        pairing_id,
        relay_ws_url: state.config.public_relay_ws_url,
        expires_at_ms,
        web_token,
        phone_token,
    }))
}

async fn get_pairing(
    Path(pairing_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<crate::store::PairingSnapshot>, ApiError> {
    let snapshot = state
        .store
        .pairing_snapshot(&pairing_id)
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("pairing '{pairing_id}' not found")))?;

    Ok(Json(snapshot))
}

async fn delete_pairing(
    Path(pairing_id): Path<String>,
    State(state): State<AppState>,
) -> Result<StatusCode, ApiError> {
    let now = now_ms();

    let exists = state
        .store
        .get_pairing(&pairing_id)
        .map_err(|error| ApiError::internal(error.to_string()))?
        .is_some();

    if !exists {
        return Err(ApiError::not_found(format!(
            "pairing '{pairing_id}' not found"
        )));
    }

    state
        .store
        .set_state(&pairing_id, "closed", Some(now), None)
        .map_err(|error| ApiError::internal(error.to_string()))?;

    state
        .store
        .add_event(
            &pairing_id,
            "pairing_closed",
            &json!({ "closed_by": "api_delete", "closed_at_ms": now }),
            now,
        )
        .map_err(|error| ApiError::internal(error.to_string()))?;

    state.peers.clear_pairing(&pairing_id).await;
    Ok(StatusCode::NO_CONTENT)
}
