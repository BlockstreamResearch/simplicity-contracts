use crate::WalletAbiError;
use crate::runtime::WalletRuntimeConfig;
use lwk_wollet::elements::Transaction;
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::hashes::Hash;
use lwk_wollet::secp256k1::{Message, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use simplicityhl::num::U256;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::str::WitnessName;
use simplicityhl::value::{UIntValue, ValueConstructible};
use simplicityhl::{Arguments, Value, WitnessValues};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeSimfValue {
    NewIssuanceAsset { input_index: u32 },
    NewIssuanceToken { input_index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimfArguments {
    pub resolved: simplicityhl::Arguments,
    pub runtime_arguments: HashMap<String, RuntimeSimfValue>,
}

impl SimfArguments {
    #[must_use]
    pub fn new(static_arguments: simplicityhl::Arguments) -> Self {
        Self {
            resolved: static_arguments,
            runtime_arguments: HashMap::new(),
        }
    }

    pub fn append_runtime_simf_value(&mut self, name: &str, runtime_simf_value: RuntimeSimfValue) {
        self.runtime_arguments
            .insert(name.to_string(), runtime_simf_value);
    }
}

/// Convert compiled Simplicity arguments into bytes.
pub fn serialize_arguments(arguments: &SimfArguments) -> Result<Vec<u8>, WalletAbiError> {
    Ok(serde_json::to_vec(arguments)?)
}

/// Convert compiled Simplicity arguments into bytes.
pub fn resolve_arguments(
    bytes: &[u8],
    pst: &PartiallySignedTransaction,
) -> Result<Arguments, WalletAbiError> {
    let simf_arguments: SimfArguments = serde_json::from_slice(bytes)?;

    let mut final_arguments: HashMap<WitnessName, Value> = HashMap::<WitnessName, Value>::new();

    for (name, value) in simf_arguments.runtime_arguments {
        match value {
            RuntimeSimfValue::NewIssuanceAsset { input_index } => {
                let (asset, _) = pst
                    .inputs()
                    .get(input_index as usize)
                    .unwrap()
                    .issuance_ids();

                final_arguments.insert(
                    WitnessName::from_str_unchecked(&name),
                    Value::from(UIntValue::U256(U256::from_byte_array(asset.into_inner().0))),
                );
            }
            RuntimeSimfValue::NewIssuanceToken { input_index } => {
                let (_, token) = pst
                    .inputs()
                    .get(input_index as usize)
                    .unwrap()
                    .issuance_ids();

                final_arguments.insert(
                    WitnessName::from_str_unchecked(&name),
                    Value::from(UIntValue::U256(U256::from_byte_array(token.into_inner().0))),
                );
            }
        }
    }

    for static_arg in simf_arguments.resolved.iter() {
        final_arguments.insert(static_arg.0.clone(), static_arg.1.clone());
    }

    Ok(Arguments::from(final_arguments))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeSimfWitness {
    SigHashAll {
        name: String,
        public_key: XOnlyPublicKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimfWitness {
    pub resolved: WitnessValues,
    pub runtime_arguments: Vec<RuntimeSimfWitness>,
}

/// Convert compiled Simplicity witness into bytes.
pub fn serialize_witness(witness: &SimfWitness) -> Result<Vec<u8>, WalletAbiError> {
    Ok(serde_json::to_vec(witness)?)
}

/// Convert compiled Simplicity witness into bytes.
pub fn resolve_witness(
    bytes: &[u8],
    runtime: &WalletRuntimeConfig,
    env: &ElementsEnv<Arc<Transaction>>,
) -> Result<WitnessValues, WalletAbiError> {
    let simf_arguments: SimfWitness = serde_json::from_slice(bytes)?;

    let mut final_witness: HashMap<WitnessName, Value> = HashMap::<WitnessName, Value>::new();

    let keypair = runtime.signer_keypair()?;
    let sighash_all = Message::from_digest(env.c_tx_env().sighash_all().to_byte_array());

    for value in simf_arguments.runtime_arguments {
        match value {
            RuntimeSimfWitness::SigHashAll { name, public_key } => {
                assert_eq!(keypair.x_only_public_key().0, public_key);

                final_witness.insert(
                    WitnessName::from_str_unchecked(&name),
                    Value::byte_array(keypair.sign_schnorr(sighash_all).serialize()),
                );
            }
        }
    }

    for static_arg in simf_arguments.resolved.iter() {
        final_witness.insert(static_arg.0.clone(), static_arg.1.clone());
    }

    Ok(WitnessValues::from(final_witness))
}

/// Build request params `extra` map with required arguments/internal key
/// and optional branch payload.
///
/// Separation of concerns:
/// - schema owns branch defaults and static path structure
/// - callers only provide dynamic branches or explicit overrides
#[must_use]
pub fn build_params_extra(
    arguments: serde_json::Value,
    internal_key: serde_json::Value,
    branch: Option<serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    let mut extra = BTreeMap::new();
    extra.insert("arguments".to_string(), arguments);
    extra.insert("internal_key".to_string(), internal_key);
    if let Some(branch) = branch {
        extra.insert("branch".to_string(), branch);
    }
    extra
}
