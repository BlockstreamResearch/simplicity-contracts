#![allow(clippy::needless_pass_by_value)]

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::{TxCreateRequest, TxCreateResponse};

use crate::error::WalletAbiException;

#[derive(uniffi::Object)]
pub struct WalletAbiRuntime {
    runtime: Mutex<WalletRuntimeConfig>,
    runtime_network: wallet_abi::Network,
    async_runtime: tokio::runtime::Runtime,
}

#[uniffi::export]
impl WalletAbiRuntime {
    #[uniffi::constructor]
    pub fn from_mnemonic(
        mnemonic: String,
        network: String,
        esplora_url: String,
        wallet_data_dir: String,
    ) -> Result<Arc<Self>, WalletAbiException> {
        let runtime_network = parse_network(&network)?;

        let config = WalletRuntimeConfig::from_mnemonic(
            &mnemonic,
            runtime_network,
            &esplora_url,
            &wallet_data_dir,
        )
        .map_err(|e| WalletAbiException::RuntimeInitialization { msg: e.to_string() })?;

        let async_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WalletAbiException::RuntimeInitialization {
                msg: format!("failed to initialize tokio runtime: {e}"),
            })?;

        Ok(Arc::new(Self {
            runtime: Mutex::new(config),
            runtime_network,
            async_runtime,
        }))
    }

    pub fn process_tx_create_request_json(
        &self,
        request_json: String,
    ) -> Result<String, WalletAbiException> {
        let request: TxCreateRequest = serde_json::from_str(&request_json)
            .map_err(|e| WalletAbiException::MalformedJson { msg: e.to_string() })?;

        let mut runtime = self.runtime.lock()?;

        let response = match self
            .async_runtime
            .block_on(runtime.process_request(&request))
        {
            Ok(response) => response,
            Err(err) => {
                TxCreateResponse::error(&request, runtime_error_code(&err), &err.to_string())
            }
        };

        serde_json::to_string(&response)
            .map_err(|e| WalletAbiException::Serialization { msg: e.to_string() })
    }

    pub fn network(&self) -> String {
        self.runtime_network.to_string()
    }
}

#[uniffi::export]
pub fn default_esplora_url(network: String) -> Result<String, WalletAbiException> {
    let network = parse_network(&network)?;
    Ok(default_esplora_url_for_network(network))
}

#[uniffi::export]
pub fn extract_request_network(request_json: String) -> Result<String, WalletAbiException> {
    let value: Value = serde_json::from_str(&request_json)
        .map_err(|e| WalletAbiException::MalformedJson { msg: e.to_string() })?;

    value
        .get("network")
        .and_then(Value::as_str)
        .map(std::string::ToString::to_string)
        .ok_or_else(|| WalletAbiException::InvalidRequestEnvelope {
            msg: "missing string field 'network'".to_string(),
        })
}

fn canonicalize_network(network: &str) -> String {
    network.trim().to_lowercase().replace('_', "-")
}

fn parse_network(network: &str) -> Result<wallet_abi::Network, WalletAbiException> {
    let canonical = canonicalize_network(network);
    wallet_abi::Network::from_str(&canonical).map_err(|_| WalletAbiException::InvalidNetwork {
        network: network.to_string(),
    })
}

fn default_esplora_url_for_network(network: wallet_abi::Network) -> String {
    match network {
        wallet_abi::Network::Liquid => "https://blockstream.info/liquid/api".to_string(),
        wallet_abi::Network::TestnetLiquid => {
            "https://blockstream.info/liquidtestnet/api".to_string()
        }
        wallet_abi::Network::LocaltestLiquid => "http://127.0.0.1:3001".to_string(),
    }
}

const fn runtime_error_code(error: &wallet_abi::WalletAbiError) -> &'static str {
    match error {
        wallet_abi::WalletAbiError::InvalidRequest(_) => "invalid_request",
        wallet_abi::WalletAbiError::InvalidResponse(_) => "invalid_response",
        wallet_abi::WalletAbiError::InvalidFinalizationSteps(_) => "invalid_finalization_steps",
        wallet_abi::WalletAbiError::InvalidSignerConfig(_) => "invalid_signer_config",
        wallet_abi::WalletAbiError::Funding(_) => "funding",
        wallet_abi::WalletAbiError::Io(_) => "io_error",
        wallet_abi::WalletAbiError::Serde(_) => "serde_error",
        wallet_abi::WalletAbiError::Hex(_) => "hex_error",
        wallet_abi::WalletAbiError::Pset(_) => "pset_error",
        wallet_abi::WalletAbiError::PsetBlind(_) => "pset_blind_error",
        wallet_abi::WalletAbiError::TxDecode(_) => "tx_decode_error",
        wallet_abi::WalletAbiError::AmountProofVerification(_) => "amount_proof_verification_error",
        wallet_abi::WalletAbiError::Program(_) => "program_error",
        wallet_abi::WalletAbiError::ProgramTrace(_) => "program_error",
        wallet_abi::WalletAbiError::EsploraPoisoned(_) => "esplora_poisoned",
        wallet_abi::WalletAbiError::LWKSigner(_) => "lwk_signer_error",
        wallet_abi::WalletAbiError::LWKSign(_) => "lwk_sign_error",
        wallet_abi::WalletAbiError::LWKWollet(_) => "lwk_wollet_error",
        wallet_abi::WalletAbiError::Unblind(_) => "unblind_error",
        wallet_abi::WalletAbiError::Locktime(_) => "locktime_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    use wallet_abi::schema::runtime_params::RuntimeParams;
    use wallet_abi::schema::tx_create::{Status, TX_CREATE_ABI_VERSION, TransactionInfo};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn request_json(network: &str) -> String {
        let request = TxCreateRequest {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: "req-1".to_string(),
            network: parse_network(network).expect("valid network"),
            params: RuntimeParams {
                inputs: vec![],
                outputs: vec![],
                fee_rate_sat_vb: Some(0.1),
                locktime: None,
            },
            broadcast: false,
        };

        serde_json::to_string(&request).expect("serializable request")
    }

    #[test]
    fn default_esplora_url_maps_supported_networks() {
        assert_eq!(
            default_esplora_url("liquid".to_string()).expect("liquid"),
            "https://blockstream.info/liquid/api"
        );
        assert_eq!(
            default_esplora_url("testnet_liquid".to_string()).expect("testnet alias"),
            "https://blockstream.info/liquidtestnet/api"
        );
        assert_eq!(
            default_esplora_url("localtest-liquid".to_string()).expect("localtest"),
            "http://127.0.0.1:3001"
        );
    }

    #[test]
    fn extract_request_network_returns_network() {
        let json = request_json("liquid");
        assert_eq!(
            extract_request_network(json).expect("extract network"),
            "liquid"
        );
    }

    #[test]
    fn extract_request_network_rejects_malformed_json() {
        let err = extract_request_network("{".to_string()).expect_err("must fail");
        assert!(matches!(err, WalletAbiException::MalformedJson { .. }));
    }

    #[test]
    fn process_returns_error_envelope_for_runtime_business_error() {
        let dir = tempdir().expect("tempdir");

        let runtime = WalletAbiRuntime::from_mnemonic(
            TEST_MNEMONIC.to_string(),
            "localtest-liquid".to_string(),
            "http://127.0.0.1:3001".to_string(),
            dir.path().to_string_lossy().into_owned(),
        )
        .expect("runtime init");

        let mismatch_request = request_json("liquid");

        let response_json = runtime
            .process_tx_create_request_json(mismatch_request)
            .expect("envelope response");
        let response: TxCreateResponse =
            serde_json::from_str(&response_json).expect("valid response json");

        assert_eq!(response.abi_version, TX_CREATE_ABI_VERSION);
        assert!(matches!(response.status, Status::Error));
        assert_eq!(
            response.error.expect("error info").code,
            "invalid_request".to_string()
        );
    }

    #[test]
    fn process_rejects_malformed_json() {
        let dir = tempdir().expect("tempdir");

        let runtime = WalletAbiRuntime::from_mnemonic(
            TEST_MNEMONIC.to_string(),
            "localtest-liquid".to_string(),
            "http://127.0.0.1:3001".to_string(),
            dir.path().to_string_lossy().into_owned(),
        )
        .expect("runtime init");

        let err = runtime
            .process_tx_create_request_json("{".to_string())
            .expect_err("must fail");

        assert!(matches!(err, WalletAbiException::MalformedJson { .. }));
    }

    #[test]
    fn valid_request_json_and_valid_ok_response_json_roundtrip() {
        let valid_request_json = request_json("liquid");
        let request: TxCreateRequest =
            serde_json::from_str(&valid_request_json).expect("valid request json");

        let tx_info = TransactionInfo {
            tx_hex: "00".to_string(),
            txid: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .expect("valid txid"),
        };
        let response = TxCreateResponse::ok(&request, tx_info, None);
        let response_json = serde_json::to_string(&response).expect("serialize response");
        let parsed: TxCreateResponse =
            serde_json::from_str(&response_json).expect("parse response");

        assert!(matches!(parsed.status, Status::Ok));
        assert!(parsed.transaction.is_some());
    }
}
