use std::collections::HashMap;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, warn};
use wallet_abi_transport::wa_relay::{
    WalletAbiRelayClientFrameV1, WalletAbiRelayDirection, WalletAbiRelayRole,
    WalletAbiRelayServerFrameV1, WalletAbiRelayStatusState, decode_ciphertext_b64,
    decode_nonce_b64,
};
use wallet_abi_transport::wa_transport::WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES;

use crate::crypto::verify_token;
use crate::state_machine;
use crate::store::InsertMessageInput;
use crate::{AppState, now_ms};

const MAX_CIPHERTEXT_BYTES: usize = WALLET_ABI_TRANSPORT_MAX_DECODED_BYTES + 1024;

type PeerSender = mpsc::UnboundedSender<WalletAbiRelayServerFrameV1>;

#[derive(Default)]
struct PairingPeers {
    web: Option<PeerSender>,
    phone: Option<PeerSender>,
}

#[derive(Default)]
pub struct PeerRegistry {
    peers: RwLock<HashMap<String, PairingPeers>>,
}

impl PeerRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(
        &self,
        pairing_id: &str,
        role: WalletAbiRelayRole,
        sender: PeerSender,
    ) -> bool {
        let mut map = self.peers.write().await;
        let entry = map.entry(pairing_id.to_string()).or_default();

        match role {
            WalletAbiRelayRole::Web => entry.web = Some(sender),
            WalletAbiRelayRole::Phone => entry.phone = Some(sender),
        }

        entry.web.is_some() && entry.phone.is_some()
    }

    pub async fn unregister(&self, pairing_id: &str, role: WalletAbiRelayRole) {
        let mut map = self.peers.write().await;
        if let Some(entry) = map.get_mut(pairing_id) {
            match role {
                WalletAbiRelayRole::Web => entry.web = None,
                WalletAbiRelayRole::Phone => entry.phone = None,
            }

            if entry.web.is_none() && entry.phone.is_none() {
                map.remove(pairing_id);
            }
        }
    }

    pub async fn send_to(
        &self,
        pairing_id: &str,
        role: WalletAbiRelayRole,
        frame: WalletAbiRelayServerFrameV1,
    ) -> bool {
        let sender = {
            let map = self.peers.read().await;
            map.get(pairing_id).and_then(|entry| match role {
                WalletAbiRelayRole::Web => entry.web.clone(),
                WalletAbiRelayRole::Phone => entry.phone.clone(),
            })
        };

        sender.is_some_and(|sender| sender.send(frame).is_ok())
    }

    pub async fn broadcast(&self, pairing_id: &str, frame: WalletAbiRelayServerFrameV1) {
        let senders = {
            let map = self.peers.read().await;
            map.get(pairing_id)
                .map(|entry| {
                    [entry.web.clone(), entry.phone.clone()]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };

        for sender in senders {
            let _ = sender.send(frame.clone());
        }
    }

    pub async fn clear_pairing(&self, pairing_id: &str) {
        let mut map = self.peers.write().await;
        map.remove(pairing_id);
    }
}

#[derive(Debug, Clone)]
struct AuthContext {
    pairing_id: String,
    role: WalletAbiRelayRole,
}

pub async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<WalletAbiRelayServerFrameV1>();

    let sender_task = tokio::spawn(async move {
        if let Err(error) = write_outgoing_frames(&mut sink, out_rx).await {
            warn!("websocket sender loop ended with error: {error}");
        }
    });

    let auth_context = read_incoming_frames(&state, &out_tx, &mut stream).await;

    if let Some(context) = auth_context {
        state
            .peers
            .unregister(&context.pairing_id, context.role)
            .await;
        let _ = state.store.add_event(
            &context.pairing_id,
            "peer_disconnected",
            &json!({ "role": context.role }),
            now_ms(),
        );
    }

    drop(out_tx);
    let _ = sender_task.await;
}

async fn write_outgoing_frames(
    sink: &mut SplitSink<WebSocket, Message>,
    mut out_rx: mpsc::UnboundedReceiver<WalletAbiRelayServerFrameV1>,
) -> anyhow::Result<()> {
    while let Some(frame) = out_rx.recv().await {
        let serialized = serde_json::to_string(&frame)?;
        sink.send(Message::Text(serialized.into())).await?;
    }

    Ok(())
}

async fn read_incoming_frames(
    state: &AppState,
    out_tx: &PeerSender,
    stream: &mut SplitStream<WebSocket>,
) -> Option<AuthContext> {
    let mut auth_context: Option<AuthContext> = None;

    while let Some(result) = stream.next().await {
        let message = match result {
            Ok(message) => message,
            Err(error) => {
                warn!("websocket receive error: {error}");
                break;
            }
        };

        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                break;
            }
            continue;
        };

        let frame = match serde_json::from_str::<WalletAbiRelayClientFrameV1>(&text) {
            Ok(frame) => frame,
            Err(error) => {
                send_error(
                    state,
                    out_tx,
                    None,
                    "invalid_frame",
                    &format!("invalid relay client frame: {error}"),
                )
                .await;
                continue;
            }
        };

        if auth_context.is_none() {
            let auth_frame = if let WalletAbiRelayClientFrameV1::Auth {
                pairing_id,
                role,
                token,
            } = frame
            {
                (pairing_id, role, token)
            } else {
                send_error(
                    state,
                    out_tx,
                    None,
                    "auth_required",
                    "first websocket frame must be auth",
                )
                .await;
                continue;
            };

            match authenticate_peer(state, out_tx, auth_frame.0, auth_frame.1, auth_frame.2).await {
                Ok(ctx) => {
                    auth_context = Some(ctx);
                }
                Err((pairing_id, code, message)) => {
                    send_error(state, out_tx, pairing_id.as_deref(), code, &message).await;
                    break;
                }
            }

            continue;
        }

        let ctx = auth_context.clone().expect("checked above");

        match frame {
            WalletAbiRelayClientFrameV1::Auth { .. } => {
                send_error(
                    state,
                    out_tx,
                    Some(&ctx.pairing_id),
                    "already_authenticated",
                    "auth frame is only valid as first message",
                )
                .await;
            }
            WalletAbiRelayClientFrameV1::Publish {
                pairing_id,
                direction,
                msg_id,
                nonce_b64,
                ciphertext_b64,
            } => {
                if pairing_id != ctx.pairing_id {
                    send_error(
                        state,
                        out_tx,
                        Some(&ctx.pairing_id),
                        "pairing_mismatch",
                        "publish pairing_id does not match authenticated pairing",
                    )
                    .await;
                    continue;
                }

                let publish_result = process_publish(
                    state,
                    out_tx,
                    &ctx,
                    direction,
                    msg_id,
                    nonce_b64,
                    ciphertext_b64,
                )
                .await;

                if let Err((code, message)) = publish_result {
                    send_error(state, out_tx, Some(&ctx.pairing_id), code, &message).await;
                }
            }
            WalletAbiRelayClientFrameV1::Ack { pairing_id, msg_id } => {
                if pairing_id != ctx.pairing_id {
                    send_error(
                        state,
                        out_tx,
                        Some(&ctx.pairing_id),
                        "pairing_mismatch",
                        "ack pairing_id does not match authenticated pairing",
                    )
                    .await;
                    continue;
                }

                let now = now_ms();
                if let Err(error) = state.store.mark_message_acked(&pairing_id, &msg_id, now) {
                    send_error(
                        state,
                        out_tx,
                        Some(&pairing_id),
                        "ack_failed",
                        &format!("failed to persist ack: {error}"),
                    )
                    .await;
                    continue;
                }

                let _ = state.store.add_event(
                    &pairing_id,
                    "message_acked",
                    &json!({ "msg_id": msg_id }),
                    now,
                );

                let _ = out_tx.send(WalletAbiRelayServerFrameV1::Ack { pairing_id, msg_id });
            }
        }
    }

    auth_context
}

async fn authenticate_peer(
    state: &AppState,
    out_tx: &PeerSender,
    pairing_id: String,
    role: WalletAbiRelayRole,
    token: String,
) -> Result<AuthContext, (Option<String>, &'static str, String)> {
    let now = now_ms();

    let pairing = state
        .store
        .get_pairing(&pairing_id)
        .map_err(|error| {
            (
                Some(pairing_id.clone()),
                "pairing_lookup_failed",
                format!("failed to load pairing: {error}"),
            )
        })?
        .ok_or_else(|| {
            (
                Some(pairing_id.clone()),
                "pairing_not_found",
                format!("pairing '{pairing_id}' does not exist"),
            )
        })?;

    if pairing.state == "expired" {
        return Err((
            Some(pairing_id),
            "pairing_expired",
            "pairing is expired".to_string(),
        ));
    }

    if pairing.state == "closed" {
        return Err((
            Some(pairing_id),
            "pairing_closed",
            "pairing is closed".to_string(),
        ));
    }

    if now > pairing.expires_at_ms {
        let _ = state.store.set_state(
            &pairing.pairing_id,
            "expired",
            Some(now),
            Some("expired at auth"),
        );

        return Err((
            Some(pairing.pairing_id),
            "pairing_expired",
            "pairing expired before auth".to_string(),
        ));
    }

    verify_token(
        state.hmac_secret.as_slice(),
        &token,
        &pairing.pairing_id,
        role,
        now,
    )
    .map_err(|error| {
        (
            Some(pairing.pairing_id.clone()),
            "token_invalid",
            format!("token validation failed: {error}"),
        )
    })?;

    let both_connected = state
        .peers
        .register(&pairing.pairing_id, role, out_tx.clone())
        .await;

    state
        .store
        .mark_peer_connected(&pairing.pairing_id, role, now)
        .map_err(|error| {
            (
                Some(pairing.pairing_id.clone()),
                "pairing_update_failed",
                format!("failed to mark peer connected: {error}"),
            )
        })?;

    let _ = state.store.add_event(
        &pairing.pairing_id,
        "peer_connected",
        &json!({ "role": role }),
        now,
    );

    if both_connected {
        if let Some(next_state) = state_machine::transition_on_peer_connected(&pairing.state) {
            let _ = state
                .store
                .set_state(&pairing.pairing_id, &next_state, None, None);
        }

        state
            .peers
            .broadcast(
                &pairing.pairing_id,
                WalletAbiRelayServerFrameV1::Status {
                    pairing_id: pairing.pairing_id.clone(),
                    state: WalletAbiRelayStatusState::PeerConnected,
                    detail: "both peers are connected".to_string(),
                },
            )
            .await;
    }

    let pending_direction = match role {
        WalletAbiRelayRole::Web => WalletAbiRelayDirection::PhoneToWeb,
        WalletAbiRelayRole::Phone => WalletAbiRelayDirection::WebToPhone,
    };

    if let Ok(pending_messages) = state
        .store
        .messages_by_direction(&pairing.pairing_id, pending_direction)
    {
        for message in pending_messages {
            let _ = out_tx.send(WalletAbiRelayServerFrameV1::Deliver {
                pairing_id: message.pairing_id,
                direction: message.direction,
                msg_id: message.msg_id,
                nonce_b64: message.nonce_b64,
                ciphertext_b64: message.ciphertext_b64,
                created_at_ms: message.created_at_ms,
            });
        }
    }

    Ok(AuthContext {
        pairing_id: pairing.pairing_id,
        role,
    })
}

async fn process_publish(
    state: &AppState,
    out_tx: &PeerSender,
    ctx: &AuthContext,
    direction: WalletAbiRelayDirection,
    msg_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
) -> Result<(), (&'static str, String)> {
    if msg_id.trim().is_empty() {
        return Err(("invalid_msg_id", "msg_id must not be empty".to_string()));
    }

    let _ = decode_nonce_b64(&nonce_b64)
        .map_err(|error| ("invalid_nonce", format!("nonce decoding failed: {error}")))?;

    let ciphertext_bytes = decode_ciphertext_b64(&ciphertext_b64).map_err(|error| {
        (
            "invalid_ciphertext",
            format!("ciphertext decoding failed: {error}"),
        )
    })?;

    if ciphertext_bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err((
            "ciphertext_too_large",
            format!("ciphertext exceeds {MAX_CIPHERTEXT_BYTES} bytes limit"),
        ));
    }

    let now = now_ms();

    let pairing = state
        .store
        .get_pairing(&ctx.pairing_id)
        .map_err(|error| {
            (
                "pairing_lookup_failed",
                format!("failed to fetch pairing during publish: {error}"),
            )
        })?
        .ok_or(("pairing_not_found", "pairing no longer exists".to_string()))?;

    let counts = state
        .store
        .message_counts(&ctx.pairing_id)
        .map_err(|error| {
            (
                "message_count_failed",
                format!("failed to fetch message counts: {error}"),
            )
        })?;

    let transition = state_machine::validate_publish(
        &pairing.state,
        ctx.role,
        direction,
        state_machine::MessageCounts {
            web_to_phone: counts.web_to_phone,
            phone_to_web: counts.phone_to_web,
        },
    )
    .map_err(|error| ("state_transition_failed", error.to_string()))?;

    let insert = state.store.insert_message(&InsertMessageInput {
        pairing_id: ctx.pairing_id.clone(),
        direction,
        msg_id: msg_id.clone(),
        nonce_b64: nonce_b64.clone(),
        ciphertext_b64: ciphertext_b64.clone(),
        created_at_ms: now,
    });

    if let Err(error) = insert {
        if crate::store::is_sqlite_unique_violation(&error) {
            return Err((
                "duplicate_msg_id",
                "duplicate msg_id for pairing".to_string(),
            ));
        }

        return Err((
            "message_insert_failed",
            format!("failed to insert message: {error}"),
        ));
    }

    state
        .store
        .set_state(
            &ctx.pairing_id,
            &transition.next_state,
            (transition.next_state == "closed").then_some(now),
            None,
        )
        .map_err(|error| {
            (
                "pairing_state_update_failed",
                format!("failed to update pairing state: {error}"),
            )
        })?;

    state
        .store
        .add_event(
            &ctx.pairing_id,
            "message_published",
            &json!({
                "direction": direction,
                "msg_id": msg_id,
                "ciphertext_bytes": ciphertext_bytes.len(),
            }),
            now,
        )
        .map_err(|error| {
            (
                "event_insert_failed",
                format!("failed to record publish event: {error}"),
            )
        })?;

    let _ = out_tx.send(WalletAbiRelayServerFrameV1::Ack {
        pairing_id: ctx.pairing_id.clone(),
        msg_id: msg_id.clone(),
    });

    let deliver_frame = WalletAbiRelayServerFrameV1::Deliver {
        pairing_id: ctx.pairing_id.clone(),
        direction,
        msg_id,
        nonce_b64,
        ciphertext_b64,
        created_at_ms: now,
    };

    let receiver = direction.expected_receiver_role();
    let delivered = state
        .peers
        .send_to(&ctx.pairing_id, receiver, deliver_frame)
        .await;

    debug!(
        pairing_id = %ctx.pairing_id,
        delivered,
        "publish processed"
    );

    for status in &transition.status_events {
        state
            .peers
            .broadcast(
                &ctx.pairing_id,
                WalletAbiRelayServerFrameV1::Status {
                    pairing_id: ctx.pairing_id.clone(),
                    state: *status,
                    detail: status_detail(*status).to_string(),
                },
            )
            .await;
    }

    Ok(())
}

fn format_last_error(code: &str, message: &str) -> String {
    let mut value = format!("{code}: {message}");
    const MAX_LAST_ERROR_CHARS: usize = 512;

    if value.len() > MAX_LAST_ERROR_CHARS {
        value.truncate(MAX_LAST_ERROR_CHARS);
        value.push_str("...");
    }

    value
}

async fn send_error(
    state: &AppState,
    out_tx: &PeerSender,
    pairing_id: Option<&str>,
    code: &str,
    message: &str,
) {
    let _ = out_tx.send(WalletAbiRelayServerFrameV1::Error {
        pairing_id: pairing_id.map(ToString::to_string),
        code: code.to_string(),
        message: message.to_string(),
    });

    let Some(pairing_id) = pairing_id else {
        return;
    };

    let now = now_ms();
    let last_error = format_last_error(code, message);

    let _ = state.store.set_last_error(pairing_id, Some(&last_error));
    let _ = state.store.add_event(
        pairing_id,
        "relay_error",
        &json!({
            "code": code,
            "message": message,
        }),
        now,
    );
}

const fn status_detail(state: WalletAbiRelayStatusState) -> &'static str {
    match state {
        WalletAbiRelayStatusState::PeerConnected => "both peers connected",
        WalletAbiRelayStatusState::RequestSent => "request message accepted",
        WalletAbiRelayStatusState::ResponseSent => "response message accepted",
        WalletAbiRelayStatusState::Closed => "pairing lifecycle completed",
        WalletAbiRelayStatusState::Expired => "pairing expired",
        WalletAbiRelayStatusState::Error => "relay error",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::ws::Message as AxumMessage;
    use futures_util::{SinkExt, StreamExt};
    use reqwest::Client;
    use serde::Deserialize;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;
    use wallet_abi_transport::wa_relay::{
        WalletAbiRelayClientFrameV1, WalletAbiRelayDirection, WalletAbiRelayRole,
        WalletAbiRelayServerFrameV1,
    };

    use crate::config::RelayConfig;
    use crate::ws::PeerRegistry;
    use crate::{AppState, http, store};

    #[derive(Debug, Deserialize)]
    struct CreatePairingResponse {
        pairing_id: String,
        relay_ws_url: String,
        web_token: String,
        phone_token: String,
    }

    async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("relay.sqlite3");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");

        let config = RelayConfig {
            bind_addr: addr,
            database_path: db_path,
            public_relay_ws_url: format!("ws://{addr}/v1/ws"),
            hmac_secret: "test-relay-secret".to_string(),
            max_ttl_ms: 120_000,
            janitor_interval_ms: 1_000,
            event_retention_ms: 60_000,
            tls_cert_path: None,
            tls_key_path: None,
        };
        config.validate().expect("config validate");

        let store = Arc::new(store::SqliteStore::new(&config.database_path).expect("store"));
        let peers = Arc::new(PeerRegistry::new());
        let state = AppState::new(
            config.clone(),
            Arc::clone(&store),
            Arc::clone(&peers),
            config.hmac_secret.as_bytes().to_vec(),
        );

        let app = http::router(state);
        let base_url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        // Keep tempdir alive by leaking in this test helper process lifetime.
        std::mem::forget(dir);

        (base_url, handle)
    }

    async fn read_server_frame(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> WalletAbiRelayServerFrameV1 {
        loop {
            let Some(message) = ws.next().await else {
                panic!("websocket closed unexpectedly");
            };
            let message = message.expect("ws read");

            if let Message::Text(text) = message {
                return serde_json::from_str::<WalletAbiRelayServerFrameV1>(&text)
                    .expect("server frame");
            }
        }
    }

    async fn send_client_frame(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        frame: &WalletAbiRelayClientFrameV1,
    ) {
        ws.send(Message::Text(
            serde_json::to_string(frame).expect("serialize frame"),
        ))
        .await
        .expect("send frame");
    }

    #[tokio::test]
    async fn websocket_one_shot_happy_path() {
        let (base_url, handle) = spawn_test_server().await;
        let client = Client::new();

        let pairing: CreatePairingResponse = client
            .post(format!("{base_url}/v1/pairings"))
            .json(&serde_json::json!({
                "origin": "https://dapp.example",
                "request_id": "req-1",
                "network": "testnet-liquid",
                "ttl_ms": 120000
            }))
            .send()
            .await
            .expect("create pairing response")
            .error_for_status()
            .expect("status")
            .json()
            .await
            .expect("decode pairing response");

        let (mut web_ws, _) = connect_async(&pairing.relay_ws_url)
            .await
            .expect("web ws connect");
        let (mut phone_ws, _) = connect_async(&pairing.relay_ws_url)
            .await
            .expect("phone ws connect");

        send_client_frame(
            &mut web_ws,
            &WalletAbiRelayClientFrameV1::Auth {
                pairing_id: pairing.pairing_id.clone(),
                role: WalletAbiRelayRole::Web,
                token: pairing.web_token.clone(),
            },
        )
        .await;

        send_client_frame(
            &mut phone_ws,
            &WalletAbiRelayClientFrameV1::Auth {
                pairing_id: pairing.pairing_id.clone(),
                role: WalletAbiRelayRole::Phone,
                token: pairing.phone_token.clone(),
            },
        )
        .await;

        send_client_frame(
            &mut web_ws,
            &WalletAbiRelayClientFrameV1::Publish {
                pairing_id: pairing.pairing_id.clone(),
                direction: WalletAbiRelayDirection::WebToPhone,
                msg_id: "msg-req".to_string(),
                nonce_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ciphertext_b64: "AQID".to_string(),
            },
        )
        .await;

        // Phone should receive either status then deliver, or deliver directly.
        let mut got_request_deliver = false;
        for _ in 0..5 {
            let frame = read_server_frame(&mut phone_ws).await;
            if let WalletAbiRelayServerFrameV1::Deliver { msg_id, .. } = frame
                && msg_id == "msg-req"
            {
                got_request_deliver = true;
                break;
            }
        }
        assert!(
            got_request_deliver,
            "phone did not receive request deliver frame"
        );

        send_client_frame(
            &mut phone_ws,
            &WalletAbiRelayClientFrameV1::Publish {
                pairing_id: pairing.pairing_id.clone(),
                direction: WalletAbiRelayDirection::PhoneToWeb,
                msg_id: "msg-resp".to_string(),
                nonce_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ciphertext_b64: "BAUG".to_string(),
            },
        )
        .await;

        let mut got_response_deliver = false;
        for _ in 0..7 {
            let frame = read_server_frame(&mut web_ws).await;
            if let WalletAbiRelayServerFrameV1::Deliver { msg_id, .. } = frame
                && msg_id == "msg-resp"
            {
                got_response_deliver = true;
                break;
            }
        }
        assert!(
            got_response_deliver,
            "web did not receive response deliver frame"
        );

        let snapshot: serde_json::Value = client
            .get(format!("{base_url}/v1/pairings/{}", pairing.pairing_id))
            .send()
            .await
            .expect("snapshot response")
            .error_for_status()
            .expect("snapshot status")
            .json()
            .await
            .expect("snapshot json");

        assert_eq!(snapshot["pairing"]["state"], "closed");
        assert_eq!(
            snapshot["messages"]
                .as_array()
                .expect("messages array")
                .len(),
            2
        );

        let _ = web_ws.close(None).await;
        let _ = phone_ws.close(None).await;

        handle.abort();
    }

    #[tokio::test]
    async fn rejects_invalid_token_on_auth() {
        let (base_url, handle) = spawn_test_server().await;
        let client = Client::new();

        let pairing: CreatePairingResponse = client
            .post(format!("{base_url}/v1/pairings"))
            .json(&serde_json::json!({
                "origin": "https://dapp.example",
                "request_id": "req-2",
                "network": "testnet-liquid"
            }))
            .send()
            .await
            .expect("create pairing")
            .error_for_status()
            .expect("status")
            .json()
            .await
            .expect("json");

        let (mut ws, _) = connect_async(&pairing.relay_ws_url)
            .await
            .expect("ws connect");

        send_client_frame(
            &mut ws,
            &WalletAbiRelayClientFrameV1::Auth {
                pairing_id: pairing.pairing_id,
                role: WalletAbiRelayRole::Web,
                token: format!("{}-tampered", pairing.web_token),
            },
        )
        .await;

        let frame = read_server_frame(&mut ws).await;
        assert!(matches!(
            frame,
            WalletAbiRelayServerFrameV1::Error { code, .. } if code == "token_invalid"
        ));

        let _ = ws.close(None).await;
        handle.abort();
    }

    #[tokio::test]
    async fn rejects_expired_pairing_auth() {
        let (base_url, handle) = spawn_test_server().await;
        let client = Client::new();

        let pairing: CreatePairingResponse = client
            .post(format!("{base_url}/v1/pairings"))
            .json(&serde_json::json!({
                "origin": "https://dapp.example",
                "request_id": "req-3",
                "network": "testnet-liquid",
                "ttl_ms": 1
            }))
            .send()
            .await
            .expect("create pairing")
            .error_for_status()
            .expect("status")
            .json()
            .await
            .expect("json");

        tokio::time::sleep(Duration::from_millis(20)).await;

        let (mut ws, _) = connect_async(&pairing.relay_ws_url)
            .await
            .expect("ws connect");
        send_client_frame(
            &mut ws,
            &WalletAbiRelayClientFrameV1::Auth {
                pairing_id: pairing.pairing_id,
                role: WalletAbiRelayRole::Web,
                token: pairing.web_token,
            },
        )
        .await;

        let frame = read_server_frame(&mut ws).await;
        assert!(matches!(
            frame,
            WalletAbiRelayServerFrameV1::Error { code, .. } if code == "pairing_expired"
        ));

        let _ = ws.close(None).await;
        handle.abort();
    }

    #[tokio::test]
    #[ignore = "requires regtest binaries and wallet-abi-regtest-harness process wiring"]
    async fn e2e_with_wallet_abi_regtest_harness_placeholder() {
        // Intentionally ignored in CI until dedicated harness process orchestration
        // is configured. This test slot is reserved for the relay <-> harness flow.
        let _ = AxumMessage::Ping(vec![1, 2, 3].into());
    }
}
