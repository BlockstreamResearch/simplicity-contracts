use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::runtime::Builder;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use wallet_abi::schema::tx_create::TxCreateRequest;
use wallet_abi_transport::wa_relay::{
    RelayChannelKey, RelayNonce, WALLET_ABI_RELAY_CHANNEL_KEY_BYTES, WALLET_ABI_RELAY_NONCE_BYTES,
    WALLET_ABI_RELAY_VERSION, WalletAbiRelayAlgorithm, WalletAbiRelayClientFrameV1,
    WalletAbiRelayDirection, WalletAbiRelayPairingV1, WalletAbiRelayRequestV1,
    WalletAbiRelayResponseV1, WalletAbiRelayRole, WalletAbiRelayServerFrameV1,
    WalletAbiRelayStatusState, build_relay_deep_link, decode_ciphertext_b64, decode_nonce_b64,
    decrypt_relay_payload, encode_channel_key_b64, encode_ciphertext_b64, encode_nonce_b64,
    encode_relay_pairing, encrypt_relay_payload,
};

use crate::option_offer::OptionOfferRefArtifact;
use crate::qr::{render_png_qr, render_text_qr};

#[derive(Debug, Clone)]
pub struct RelayConnectRunInput {
    pub relay_http_url: String,
    pub base_link: String,
    pub out_dir: std::path::PathBuf,
    pub pixel_per_module: u8,
    pub wait_timeout_ms: u64,
    pub request_id: String,
    pub origin: String,
    pub ttl_ms: u64,
    pub tx_create_request: TxCreateRequest,
    pub option_offer_ref_artifact: Option<OptionOfferRefArtifact>,
}

#[derive(Debug, Clone, Serialize)]
struct CreatePairingRequest {
    origin: String,
    request_id: String,
    network: String,
    ttl_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct CreatePairingResponse {
    pairing_id: String,
    relay_ws_url: String,
    expires_at_ms: u64,
    web_token: String,
    phone_token: String,
}

pub fn run_relay_connect(input: RelayConnectRunInput) -> Result<()> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize async runtime")?;

    runtime.block_on(run_relay_connect_async(input))
}

async fn run_relay_connect_async(input: RelayConnectRunInput) -> Result<()> {
    let client = reqwest::Client::new();
    let pairings_url = api_url(&input.relay_http_url, "/v1/pairings")?;

    let pairing = client
        .post(pairings_url)
        .json(&CreatePairingRequest {
            origin: input.origin.clone(),
            request_id: input.request_id.clone(),
            network: input.tx_create_request.network.to_string(),
            ttl_ms: input.ttl_ms,
        })
        .send()
        .await
        .context("failed to create relay pairing")?
        .error_for_status()
        .context("relay pairing create returned non-success status")?
        .json::<CreatePairingResponse>()
        .await
        .context("failed to decode pairing create response")?;

    let mut channel_key: RelayChannelKey = [0_u8; WALLET_ABI_RELAY_CHANNEL_KEY_BYTES];
    let rng = SystemRandom::new();
    rng.fill(&mut channel_key)
        .map_err(|_| anyhow::anyhow!("failed to generate random relay channel key"))?;

    let relay_pairing = WalletAbiRelayPairingV1 {
        v: WALLET_ABI_RELAY_VERSION,
        pairing_id: pairing.pairing_id.clone(),
        relay_ws_url: pairing.relay_ws_url.clone(),
        expires_at_ms: pairing.expires_at_ms,
        phone_token: pairing.phone_token.clone(),
        channel_key_b64: encode_channel_key_b64(&channel_key),
        alg: WalletAbiRelayAlgorithm::Xchacha20poly1305HkdfSha256,
    };

    let encoded_pairing = encode_relay_pairing(&relay_pairing)?;
    let deep_link = build_relay_deep_link(&input.base_link, &encoded_pairing);
    let qr_text = render_text_qr(&deep_link)?;
    let qr_png = render_png_qr(&deep_link, input.pixel_per_module)?;

    fs::create_dir_all(&input.out_dir).with_context(|| {
        format!(
            "failed to create output directory '{}'",
            input.out_dir.display()
        )
    })?;

    let tx_request_path = input
        .out_dir
        .join(format!("{}.tx_create_request.json", input.request_id));
    let relay_pairing_path = input
        .out_dir
        .join(format!("{}.relay_pairing.json", input.request_id));
    let deep_link_path = input
        .out_dir
        .join(format!("{}.relay_deep_link.txt", input.request_id));
    let qr_png_path = input
        .out_dir
        .join(format!("{}.relay_qr.png", input.request_id));

    write_json_file(&tx_request_path, &input.tx_create_request)?;
    write_json_file(&relay_pairing_path, &relay_pairing)?;
    if let Some(option_offer_ref_artifact) = &input.option_offer_ref_artifact {
        let option_offer_ref_path = input
            .out_dir
            .join(format!("{}.option_offer_ref.json", input.request_id));
        write_json_file(&option_offer_ref_path, option_offer_ref_artifact)?;
        println!("option_offer_ref_file: {}", option_offer_ref_path.display());
    }
    write_text_file(&deep_link_path, format!("{deep_link}\n"))?;
    write_binary_file(&qr_png_path, &qr_png)?;

    println!("request_id: {}", input.request_id);
    println!("pairing_id: {}", pairing.pairing_id);
    println!("relay_ws_url: {}", pairing.relay_ws_url);
    println!("deep_link: {deep_link}");
    println!("wa_relay_v1_length: {}", encoded_pairing.len());
    println!("expires_at_ms: {}", pairing.expires_at_ms);
    println!("qr_png: {}", qr_png_path.display());
    println!("qr_text:\n{qr_text}");
    println!("waiting_for_phone: true");

    let roundtrip_result = relay_roundtrip(
        &pairing,
        &channel_key,
        &input.request_id,
        &input.origin,
        &input.tx_create_request,
        input.wait_timeout_ms,
    )
    .await;

    let delete_result = delete_pairing(&client, &input.relay_http_url, &pairing.pairing_id).await;
    if let Err(error) = delete_result {
        eprintln!(
            "warning: failed to delete pairing '{}' during cleanup: {error}",
            pairing.pairing_id
        );
    }

    let response = roundtrip_result?;
    let relay_response_path = input
        .out_dir
        .join(format!("{}.relay_response.json", input.request_id));
    write_json_file(&relay_response_path, &response)?;

    println!(
        "relay_response:\n{}",
        serde_json::to_string_pretty(&response).context("failed to format relay response json")?
    );
    println!("response_file: {}", relay_response_path.display());

    Ok(())
}

async fn relay_roundtrip(
    pairing: &CreatePairingResponse,
    channel_key: &RelayChannelKey,
    request_id: &str,
    origin: &str,
    tx_create_request: &TxCreateRequest,
    wait_timeout_ms: u64,
) -> Result<WalletAbiRelayResponseV1> {
    let (mut websocket, _) = connect_async(&pairing.relay_ws_url)
        .await
        .context("failed to connect relay websocket")?;

    send_client_frame(
        &mut websocket,
        &WalletAbiRelayClientFrameV1::Auth {
            pairing_id: pairing.pairing_id.clone(),
            role: WalletAbiRelayRole::Web,
            token: pairing.web_token.clone(),
        },
    )
    .await?;

    let request_payload = WalletAbiRelayRequestV1 {
        v: WALLET_ABI_RELAY_VERSION,
        pairing_id: pairing.pairing_id.clone(),
        request_id: request_id.to_string(),
        origin: origin.to_string(),
        tx_create_request: serde_json::to_value(tx_create_request)
            .context("failed to serialize tx_create_request for relay payload")?,
    };
    let request_plaintext = serde_json::to_vec(&request_payload)
        .context("failed to serialize relay request payload")?;

    let request_msg_id = format!("msg-req-{}", Uuid::new_v4());
    let mut request_sent = false;

    loop {
        let next_message = timeout(Duration::from_millis(wait_timeout_ms), websocket.next())
            .await
            .context("relay websocket timeout while waiting for server frame")?;

        let Some(next_message) = next_message else {
            bail!("relay websocket closed before receiving response");
        };

        let message = next_message.context("failed to read relay websocket message")?;
        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                bail!("relay websocket closed before receiving response");
            }
            continue;
        };

        let server_frame: WalletAbiRelayServerFrameV1 =
            serde_json::from_str(&text).context("failed to decode relay server frame json")?;

        match server_frame {
            WalletAbiRelayServerFrameV1::Status {
                pairing_id,
                state,
                detail,
            } => {
                if pairing_id != pairing.pairing_id {
                    continue;
                }

                if state == WalletAbiRelayStatusState::Expired {
                    bail!("relay pairing expired before response: {detail}");
                }

                if !request_sent && state == WalletAbiRelayStatusState::PeerConnected {
                    send_encrypted_request(
                        &mut websocket,
                        &pairing.pairing_id,
                        channel_key,
                        &request_msg_id,
                        &request_plaintext,
                    )
                    .await?;
                    request_sent = true;
                    println!("request_sent: true");
                }
            }
            WalletAbiRelayServerFrameV1::Deliver {
                pairing_id,
                direction,
                msg_id,
                nonce_b64,
                ciphertext_b64,
                ..
            } => {
                if pairing_id != pairing.pairing_id {
                    continue;
                }
                if direction != WalletAbiRelayDirection::PhoneToWeb {
                    continue;
                }

                let nonce =
                    decode_nonce_b64(&nonce_b64).context("failed to decode response nonce")?;
                let ciphertext = decode_ciphertext_b64(&ciphertext_b64)
                    .context("failed to decode response ciphertext")?;
                let plaintext = decrypt_relay_payload(
                    channel_key,
                    &pairing.pairing_id,
                    WalletAbiRelayDirection::PhoneToWeb,
                    &msg_id,
                    &nonce,
                    &ciphertext,
                )
                .context("failed to decrypt relay response payload")?;

                let response: WalletAbiRelayResponseV1 = serde_json::from_slice(&plaintext)
                    .context("failed to decode decrypted relay response payload json")?;

                send_client_frame(
                    &mut websocket,
                    &WalletAbiRelayClientFrameV1::Ack {
                        pairing_id: pairing.pairing_id.clone(),
                        msg_id,
                    },
                )
                .await?;

                return Ok(response);
            }
            WalletAbiRelayServerFrameV1::Error { code, message, .. } => {
                bail!("relay server returned error '{code}': {message}");
            }
            WalletAbiRelayServerFrameV1::Ack { .. } => {}
        }
    }
}

async fn send_encrypted_request(
    websocket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    pairing_id: &str,
    channel_key: &RelayChannelKey,
    msg_id: &str,
    plaintext: &[u8],
) -> Result<()> {
    let nonce = random_nonce()?;
    let ciphertext = encrypt_relay_payload(
        channel_key,
        pairing_id,
        WalletAbiRelayDirection::WebToPhone,
        msg_id,
        &nonce,
        plaintext,
    )
    .context("failed to encrypt relay request payload")?;

    send_client_frame(
        websocket,
        &WalletAbiRelayClientFrameV1::Publish {
            pairing_id: pairing_id.to_string(),
            direction: WalletAbiRelayDirection::WebToPhone,
            msg_id: msg_id.to_string(),
            nonce_b64: encode_nonce_b64(&nonce),
            ciphertext_b64: encode_ciphertext_b64(&ciphertext),
        },
    )
    .await
}

fn random_nonce() -> Result<RelayNonce> {
    let mut nonce: RelayNonce = [0_u8; WALLET_ABI_RELAY_NONCE_BYTES];
    let rng = SystemRandom::new();
    rng.fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("failed to generate random relay nonce"))?;
    Ok(nonce)
}

async fn send_client_frame(
    websocket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    frame: &WalletAbiRelayClientFrameV1,
) -> Result<()> {
    let encoded = serde_json::to_string(frame).context("failed to serialize client frame")?;
    websocket
        .send(Message::Text(encoded.into()))
        .await
        .context("failed to send relay websocket frame")
}

async fn delete_pairing(
    client: &reqwest::Client,
    relay_http_url: &str,
    pairing_id: &str,
) -> Result<()> {
    let delete_url = api_url(relay_http_url, &format!("/v1/pairings/{pairing_id}"))?;
    let response = client
        .delete(delete_url)
        .send()
        .await
        .context("failed to delete relay pairing")?;

    if !response.status().is_success() && response.status().as_u16() != 404 {
        bail!(
            "relay pairing delete returned unexpected status {}",
            response.status()
        );
    }
    Ok(())
}

fn api_url(base: &str, endpoint: &str) -> Result<Url> {
    let normalized = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };

    let base_url =
        Url::parse(&normalized).with_context(|| format!("invalid relay HTTP URL '{base}'"))?;
    base_url
        .join(endpoint.trim_start_matches('/'))
        .with_context(|| format!("failed to build API URL for endpoint '{endpoint}'"))
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let serialized = serde_json::to_vec_pretty(value).context("failed to serialize json")?;
    write_binary_file(path, &serialized)
}

fn write_text_file(path: &Path, content: String) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write '{}'", path.display()))
}

fn write_binary_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write '{}'", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_abi_transport::wa_relay::{WALLET_ABI_RELAY_PAIRING_PARAM, decode_relay_pairing};
    use wallet_abi_transport::wa_transport::extract_fragment_param;

    #[test]
    fn pairing_roundtrip_via_qr_deeplink_fragment() {
        let channel_key: RelayChannelKey = [7_u8; WALLET_ABI_RELAY_CHANNEL_KEY_BYTES];
        let pairing = WalletAbiRelayPairingV1 {
            v: WALLET_ABI_RELAY_VERSION,
            pairing_id: "pairing-1".to_string(),
            relay_ws_url: "ws://127.0.0.1:8787/v1/ws".to_string(),
            expires_at_ms: 1_700_000_120_000,
            phone_token: "phone-token-1".to_string(),
            channel_key_b64: encode_channel_key_b64(&channel_key),
            alg: WalletAbiRelayAlgorithm::Xchacha20poly1305HkdfSha256,
        };

        let encoded = encode_relay_pairing(&pairing).expect("encode pairing");
        let deep_link =
            build_relay_deep_link("https://blockstream.com/walletabi/request", &encoded);
        let extracted = extract_fragment_param(&deep_link, WALLET_ABI_RELAY_PAIRING_PARAM)
            .expect("extract wa_relay_v1 param");
        let decoded = decode_relay_pairing(&extracted).expect("decode pairing");

        assert_eq!(decoded, pairing);
    }
}
