use crate::WalletAbiError;
use crate::taproot_pubkey_gen::TaprootPubkeyGen;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use simplicityhl::elements::secp256k1_zkp::{PublicKey, SecretKey};
use simplicityhl::elements::{Address, AssetId, OutPoint, Script, Sequence};
use simplicityhl::WitnessValues;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaBundle {
    #[serde(rename = "$defs", default, skip_serializing_if = "Option::is_none")]
    pub defs: Option<serde_json::Value>,
    pub sources: BTreeMap<String, String>,
    pub schema_id: String,
    pub schema_version: String,
    pub branches: BTreeMap<String, BranchSchema>,
}

impl SchemaBundle {
    pub fn from_uri(schema_uri: &str) -> Result<Self, WalletAbiError> {
        let json: serde_json::Value = serde_json::from_slice(schema_uri.as_bytes())?;

        let bundle: Self = serde_json::from_value(json)?;

        if bundle.schema_id.is_empty() || bundle.schema_version.is_empty() {
            return Err(WalletAbiError::InvalidResponse(
                "schema bundle must have non-empty schema_id and schema_version".to_string(),
            ));
        }
        if bundle.sources.is_empty() {
            return Err(WalletAbiError::InvalidResponse(
                "schema bundle must include non-empty sources map".to_string(),
            ));
        }

        Ok(bundle)
    }

    pub fn get_branch(&self, branch: &str) -> Result<&BranchSchema, WalletAbiError> {
        self
            .branch(branch)
            .ok_or_else(|| WalletAbiError::UnsupportedBranch(branch.to_string()))
    }
}

impl SchemaBundle {
    #[must_use]
    pub fn branch(&self, branch: &str) -> Option<&BranchSchema> {
        self.branches.get(branch)
    }
}

impl InputSchema {
    #[must_use]
    pub const fn with_issuance(mut self, issuance: InputIssuance) -> Self {
        self.issuance = Some(issuance);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BranchSchema {
    pub params_schema: serde_json::Value,
    pub contract_inputs: Vec<InputSchema>,
    pub contract_outputs: Vec<OutputSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AssetFilter {
    #[default]
    None,
    Exact {
        asset_id: AssetId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FinalizerSpec {
    #[default]
    Wallet,
    Simf {
        source_simf: String,
        internal_key: Box<TaprootPubkeyGen>,
        arguments: Vec<u8>,
        witness: Vec<u8>,
    },
}

impl FinalizerSpec {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WalletAbiError> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputIntent {
    #[default]
    Transfer,
    Issuance {
        input_index: u32,
    },
    Reissuance {
        input_index: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LockVariant {
    Script {
        script: Script,
    },
    Finalizer {
        finalizer: Box<FinalizerSpec>,
    },
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
    AssetId {
        asset_id: AssetId,
    },
    NewIssuanceAsset {
        input_index: u32,
    },
    NewIssuanceToken {
        input_index: u32,
    },
    ReIssuanceAsset {
        input_index: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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
    pub intent: OutputIntent,
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
            intent: OutputIntent::Transfer,
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
            intent: OutputIntent::Transfer,
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
            intent: OutputIntent::Transfer,
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
