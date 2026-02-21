use std::path::PathBuf;

use anyhow::{Context, anyhow};
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::{AssetId, Transaction, encode};
use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::{TxCreateRequest, TxCreateResponse};
use wallet_abi::{Network, get_new_asset_entropy};

use crate::protocol::{InitResult, IssuanceInfoResult, SignerInfoResult};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub struct WalletSession {
    runtime: WalletRuntimeConfig,
    workdir: PathBuf,
    wallet_data_dir: PathBuf,
}

impl WalletSession {
    pub fn bootstrap(esplora_url: String, mnemonic: Option<String>) -> anyhow::Result<Self> {
        let workdir = enter_temp_dir("simplicity-wallet-abi-ts-regtest")?;
        let wallet_data_dir = workdir.join(".cache").join("wallet");
        std::fs::create_dir_all(&wallet_data_dir).with_context(|| {
            format!("failed to create wallet dir {}", wallet_data_dir.display())
        })?;

        let selected_mnemonic = mnemonic.unwrap_or_else(|| TEST_MNEMONIC.to_string());
        let runtime = WalletRuntimeConfig::from_mnemonic(
            &selected_mnemonic,
            Network::LocaltestLiquid,
            &esplora_url,
            &wallet_data_dir,
        )?;

        Ok(Self {
            runtime,
            workdir,
            wallet_data_dir,
        })
    }

    pub fn init_result(&self, esplora_url: String) -> anyhow::Result<InitResult> {
        let signer = self.runtime.signer_receive_address()?;
        Ok(InitResult {
            network: self.runtime.network.to_string(),
            policy_asset_id: self.runtime.network.policy_asset().to_string(),
            signer_address: signer.to_string(),
            signer_script_hex: signer.script_pubkey().to_hex(),
            esplora_url,
            workdir: self.workdir.display().to_string(),
            wallet_data_dir: self.wallet_data_dir.display().to_string(),
        })
    }

    pub fn signer_info(&self) -> anyhow::Result<SignerInfoResult> {
        let signer = self.runtime.signer_receive_address()?;

        Ok(SignerInfoResult {
            address: signer.to_string(),
            script_hex: signer.script_pubkey().to_hex(),
            xonly_pubkey: self.runtime.signer_x_only_public_key()?.to_string(),
        })
    }

    pub fn signer_receive_address(&self) -> anyhow::Result<simplicityhl::elements::Address> {
        Ok(self.runtime.signer_receive_address()?)
    }

    pub fn policy_asset_id(&self) -> AssetId {
        *self.runtime.network.policy_asset()
    }

    pub async fn process_tx_create(
        &mut self,
        request: &TxCreateRequest,
    ) -> anyhow::Result<TxCreateResponse> {
        Ok(self.runtime.process_request(request).await?)
    }

    pub fn extract_issuance_info(
        &self,
        tx_hex: &str,
        issuance_entropy: Vec<u8>,
    ) -> anyhow::Result<IssuanceInfoResult> {
        let tx = decode_transaction(tx_hex)?;

        let issuance_input = tx
            .input
            .iter()
            .find(|input| !input.asset_issuance.is_null())
            .ok_or_else(|| anyhow!("transaction does not contain any issuance inputs"))?;

        let contract_entropy: [u8; 32] = issuance_entropy.try_into().map_err(|_| {
            anyhow!("issuance_entropy must contain exactly 32 bytes (got different length)")
        })?;

        let asset_entropy =
            get_new_asset_entropy(&issuance_input.previous_output, contract_entropy);
        let expected_asset_id = AssetId::from_entropy(asset_entropy);
        let expected_reissuance_token_asset_id =
            AssetId::reissuance_token_from_entropy(asset_entropy, false);

        let (actual_asset_id, actual_reissuance_token_asset_id) = issuance_input.issuance_ids();
        if expected_asset_id != actual_asset_id
            || expected_reissuance_token_asset_id != actual_reissuance_token_asset_id
        {
            return Err(anyhow!(
                "provided issuance_entropy does not match issuance ids in transaction"
            ));
        }

        Ok(IssuanceInfoResult {
            asset_id: expected_asset_id.to_string(),
            reissuance_token_asset_id: expected_reissuance_token_asset_id.to_string(),
            asset_entropy: asset_entropy.to_byte_array().to_vec(),
        })
    }
}

fn enter_temp_dir(prefix: &str) -> anyhow::Result<PathBuf> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("failed to read system time")?
        .as_millis();
    let pid = std::process::id();

    let temp_dir = std::env::temp_dir().join(format!("{prefix}-{pid}-{timestamp}"));
    std::fs::create_dir_all(&temp_dir)
        .with_context(|| format!("failed to create temp dir {}", temp_dir.display()))?;
    std::env::set_current_dir(&temp_dir)
        .with_context(|| format!("failed to enter temp dir {}", temp_dir.display()))?;

    Ok(temp_dir)
}

fn decode_transaction(tx_hex: &str) -> anyhow::Result<Transaction> {
    let tx_bytes = hex::decode(tx_hex).context("failed to decode transaction hex")?;
    encode::deserialize(&tx_bytes).context("failed to decode transaction bytes")
}
