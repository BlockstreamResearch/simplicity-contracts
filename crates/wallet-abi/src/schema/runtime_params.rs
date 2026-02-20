//! Runtime transaction parameter schema used by `wallet-create-0.1`.
//!
//! Serialization note:
//! enum variants are serialized in `snake_case` across this schema.

use crate::WalletAbiError;
use crate::schema::values::resolve_arguments;
use crate::taproot_pubkey_gen::{TaprootPubkeyGen, generate_public_key_without_private};

use lwk_simplicity::scripts::{create_p2tr_address, load_program};

use lwk_wollet::bitcoin::XOnlyPublicKey;
use lwk_wollet::elements::LockTime;
use lwk_wollet::elements::pset::PartiallySignedTransaction;

use serde::{Deserialize, Serialize};

use simplicityhl::elements::secp256k1_zkp::{PublicKey, SecretKey};
use simplicityhl::elements::{Address, AssetId, OutPoint, Script, Sequence};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeParams {
    #[serde(default)]
    pub inputs: Vec<InputSchema>,
    #[serde(default)]
    pub outputs: Vec<OutputSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_rate_sat_vb: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locktime: Option<LockTime>,
}

impl RuntimeParams {
    pub fn from_request_params(value: &serde_json::Value) -> Result<Self, WalletAbiError> {
        serde_json::from_value(value.clone())
            .map_err(|e| WalletAbiError::InvalidRequest(format!("invalid request params: {e}")))
    }

    pub fn to_request_params_value(&self) -> Result<serde_json::Value, WalletAbiError> {
        serde_json::to_value(self).map_err(WalletAbiError::from)
    }
}

impl InputSchema {
    #[must_use]
    pub const fn with_issuance(mut self, issuance: InputIssuance) -> Self {
        self.issuance = Some(issuance);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AssetFilter {
    #[default]
    None,
    Exact {
        asset_id: AssetId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AmountFilter {
    #[default]
    None,
    Exact {
        satoshi: u64,
    },
    Min {
        satoshi: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockFilter {
    #[default]
    None,
    Script {
        script: Script,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WalletSourceFilter {
    pub asset: AssetFilter,
    pub amount: AmountFilter,
    pub lock: LockFilter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UTXOSource {
    Wallet { filter: WalletSourceFilter },
    Provided { outpoint: OutPoint },
}

impl Default for UTXOSource {
    fn default() -> Self {
        Self::Wallet {
            filter: WalletSourceFilter::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputIssuanceKind {
    New,
    Reissue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputIssuance {
    pub kind: InputIssuanceKind,
    pub asset_amount_sat: u64,
    pub token_amount_sat: u64,
    pub entropy: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InternalKeySource {
    Local { key: PublicKey },
    External { key: Box<TaprootPubkeyGen> },
}

impl Default for InternalKeySource {
    fn default() -> Self {
        let (deterministic_pubkey, _) = generate_public_key_without_private();

        Self::Local {
            key: deterministic_pubkey.inner,
        }
    }
}

impl InternalKeySource {
    #[must_use]
    pub fn get_x_only_pubkey(&self) -> XOnlyPublicKey {
        match self {
            Self::Local { key } => key.x_only_public_key().0,
            Self::External { key } => key.pubkey.inner.x_only_public_key().0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FinalizerSpec {
    #[default]
    Wallet,
    Simf {
        source_simf: String,
        internal_key: InternalKeySource,
        arguments: Vec<u8>,
        witness: Vec<u8>,
    },
}

impl FinalizerSpec {
    pub fn try_resolve_script_pubkey(
        &self,
        pst: &PartiallySignedTransaction,
        network: lwk_common::Network,
    ) -> Result<Script, WalletAbiError> {
        let Self::Simf {
            source_simf,
            internal_key,
            arguments,
            ..
        } = self
        else {
            return Err(WalletAbiError::InvalidRequest(
                "trying to get runtime key from non-simplicity".to_string(),
            ));
        };

        let internal_key = match internal_key {
            InternalKeySource::Local { key } => key,
            InternalKeySource::External { key } => return Ok(key.address.script_pubkey()),
        };

        let arguments = resolve_arguments(arguments, pst)?;

        let program = load_program(source_simf, arguments)?;

        let p2tr = create_p2tr_address(
            program.commit().cmr(),
            &internal_key.x_only_public_key().0,
            network.address_params(),
        );

        Ok(p2tr.script_pubkey())
    }
}

impl FinalizerSpec {
    pub fn try_encode(&self) -> Result<Vec<u8>, WalletAbiError> {
        serde_json::to_vec(self).map_err(Into::into)
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode()
            .expect("finalizer spec serialization should not fail")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WalletAbiError> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputBlinder {
    #[default]
    Wallet,
    Provided {
        secret_key: SecretKey,
    },
    Explicit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct InputSchema {
    pub id: String,
    pub utxo_source: UTXOSource,
    pub blinder: InputBlinder,
    pub sequence: Sequence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance: Option<InputIssuance>,
    pub finalizer: FinalizerSpec,
}

impl InputSchema {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LockVariant {
    Script { script: Script },
    Finalizer { finalizer: Box<FinalizerSpec> },
}

impl Default for LockVariant {
    fn default() -> Self {
        Self::Finalizer {
            finalizer: Box::new(FinalizerSpec::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AssetVariant {
    AssetId { asset_id: AssetId },
    NewIssuanceAsset { input_index: u32 },
    NewIssuanceToken { input_index: u32 },
    ReIssuanceAsset { input_index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlinderVariant {
    #[default]
    Wallet,
    Provided {
        pubkey: PublicKey,
    },
    Explicit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputSchema {
    pub id: String,
    pub amount_sat: u64,
    pub lock: LockVariant,
    pub asset: AssetVariant,
    pub blinder: BlinderVariant,
}

impl OutputSchema {
    #[must_use]
    pub fn from_address(
        id: impl Into<String>,
        asset_id: AssetId,
        amount_sat: u64,
        address: &Address,
    ) -> Self {
        let blinder = address
            .blinding_pubkey
            .map_or_else(BlinderVariant::default, |pubkey| BlinderVariant::Provided {
                pubkey,
            });

        Self {
            id: id.into(),
            amount_sat,
            lock: LockVariant::Script {
                script: address.script_pubkey(),
            },
            asset: AssetVariant::AssetId { asset_id },
            blinder,
        }
    }

    #[must_use]
    pub fn from_script(
        id: impl Into<String>,
        asset_id: AssetId,
        amount_sat: u64,
        script: Script,
    ) -> Self {
        Self {
            id: id.into(),
            amount_sat,
            lock: LockVariant::Script { script },
            asset: AssetVariant::AssetId { asset_id },
            blinder: BlinderVariant::Explicit,
        }
    }

    #[must_use]
    pub fn fee_placeholder(policy_asset: AssetId) -> Self {
        Self {
            id: "fee".to_string(),
            amount_sat: 0,
            lock: LockVariant::Script {
                script: Script::new(),
            },
            asset: AssetVariant::AssetId {
                asset_id: policy_asset,
            },
            blinder: BlinderVariant::Explicit,
        }
    }
}
