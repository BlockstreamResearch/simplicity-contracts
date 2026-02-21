use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use contracts::option_offer::build_witness::{OptionOfferBranch, build_option_offer_witness};
use contracts::option_offer::{
    OPTION_OFFER_SOURCE, OptionOfferArguments, get_option_offer_address,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use simplicityhl::elements::bitcoin::XOnlyPublicKey;
use simplicityhl::elements::encode;
use simplicityhl::elements::{AssetId, LockTime, OutPoint, Script, Sequence, Transaction, Txid};
use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
use wallet_abi::schema::values::{serialize_arguments, serialize_witness};
use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;
use wallet_abi::{
    Encodable, FinalizerSpec, InputBlinder, InputSchema, InternalKeySource, Network, OutputSchema,
    RuntimeParams, UTXOSource,
};

use crate::request::parse_and_validate_address;

pub const DEFAULT_OPTION_OFFER_STORE_PATH: &str = ".cache/store";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionOfferRefArtifact {
    pub taproot_pubkey_gen: String,
    pub option_offer_address: String,
    pub encoded_option_offer_arguments: String,
    pub collateral_per_contract: u64,
    pub premium_per_collateral: u64,
    pub expiry_time: u32,
}

#[derive(Debug, Clone)]
pub struct OptionOfferCreateBuildInput<'a> {
    pub request_id: &'a str,
    pub network: Network,
    pub collateral_asset_id: AssetId,
    pub premium_asset_id: AssetId,
    pub settlement_asset_id: AssetId,
    pub expected_to_deposit_collateral: u64,
    pub expected_to_deposit_premium: u64,
    pub expected_to_get_settlement: u64,
    pub expiry_time: u32,
    pub user_xonly_pubkey_hex: &'a str,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

#[derive(Debug, Clone)]
pub struct OptionOfferCreateBuildOutput {
    pub tx_create_request: TxCreateRequest,
    pub taproot_pubkey_gen: String,
    pub option_offer_address: String,
    pub encoded_option_offer_arguments: String,
    pub collateral_per_contract: u64,
    pub premium_per_collateral: u64,
    pub args: OptionOfferArguments,
}

#[derive(Debug, Clone)]
pub struct ResolveOptionOfferReferenceInput<'a> {
    pub network: Network,
    pub option_offer_taproot_pubkey_gen: &'a str,
    pub encoded_option_offer_arguments: Option<&'a str>,
    pub store_path: Option<&'a Path>,
}

#[derive(Debug, Clone)]
pub struct ResolvedOptionOfferReference {
    pub tap: TaprootPubkeyGen,
    pub arguments: OptionOfferArguments,
    pub encoded_option_offer_arguments: String,
}

#[derive(Debug, Clone)]
pub struct OptionOfferExerciseBuildInput<'a> {
    pub request_id: &'a str,
    pub network: Network,
    pub tap: &'a TaprootPubkeyGen,
    pub arguments: &'a OptionOfferArguments,
    pub creation_tx_id: Txid,
    pub collateral_amount: u64,
    pub to_address: &'a str,
    pub available_collateral_amount: Option<u64>,
    pub available_premium_amount: Option<u64>,
    pub esplora_url: Option<&'a str>,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

#[derive(Debug, Clone)]
pub struct OptionOfferWithdrawBuildInput<'a> {
    pub request_id: &'a str,
    pub network: Network,
    pub tap: &'a TaprootPubkeyGen,
    pub arguments: &'a OptionOfferArguments,
    pub exercise_tx_id: Txid,
    pub to_address: &'a str,
    pub settlement_vout: Option<u32>,
    pub settlement_amount_sat: Option<u64>,
    pub esplora_url: Option<&'a str>,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

#[derive(Debug, Clone)]
pub struct OptionOfferExpiryBuildInput<'a> {
    pub request_id: &'a str,
    pub network: Network,
    pub tap: &'a TaprootPubkeyGen,
    pub arguments: &'a OptionOfferArguments,
    pub creation_tx_id: Txid,
    pub to_address: &'a str,
    pub collateral_amount: Option<u64>,
    pub premium_amount: Option<u64>,
    pub esplora_url: Option<&'a str>,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

#[derive(Debug, Clone)]
struct CandidateOutput {
    vout: u32,
    script_pubkey: Script,
    asset_id: Option<AssetId>,
    value_sat: Option<u64>,
}

#[derive(Debug, Clone)]
struct OptionOfferStore {
    db: sled::Db,
}

impl OptionOfferStore {
    fn open(path: Option<&Path>) -> Result<Self> {
        let path = path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_OPTION_OFFER_STORE_PATH));
        let db = sled::open(&path)
            .with_context(|| format!("failed to open option-offer store '{}'", path.display()))?;
        Ok(Self { db })
    }

    fn put(&self, taproot_pubkey_gen: &str, arguments: &OptionOfferArguments) -> Result<()> {
        let encoded = arguments
            .encode()
            .context("failed to encode option-offer arguments")?;
        self.db
            .insert(taproot_pubkey_gen, encoded)
            .context("failed to persist option-offer arguments")?;
        self.db
            .flush()
            .context("failed to flush option-offer store")?;
        Ok(())
    }

    fn get(&self, taproot_pubkey_gen: &str) -> Result<OptionOfferArguments> {
        let Some(encoded) = self
            .db
            .get(taproot_pubkey_gen)
            .context("failed to read option-offer store")?
        else {
            bail!(
                "option-offer arguments not found in store for key '{}'",
                taproot_pubkey_gen
            );
        };

        OptionOfferArguments::decode(&encoded)
            .context("stored option-offer arguments are invalid or corrupted")
    }

    fn get_encoded_hex(&self, taproot_pubkey_gen: &str) -> Result<String> {
        let Some(encoded) = self
            .db
            .get(taproot_pubkey_gen)
            .context("failed to read option-offer store")?
        else {
            bail!(
                "option-offer arguments not found in store for key '{}'",
                taproot_pubkey_gen
            );
        };
        Ok(hex::encode(encoded))
    }
}

pub fn option_offer_state_import(
    store_path: Option<&Path>,
    network: Network,
    option_offer_taproot_pubkey_gen: &str,
    encoded_option_offer_arguments: &str,
) -> Result<()> {
    let arguments = decode_option_offer_arguments_hex(encoded_option_offer_arguments)?;
    let _ = TaprootPubkeyGen::build_from_str(
        option_offer_taproot_pubkey_gen,
        &arguments,
        network,
        &get_option_offer_address,
    )
    .with_context(|| {
        format!(
            "invalid option-offer taproot reference '{}' for supplied arguments",
            option_offer_taproot_pubkey_gen
        )
    })?;

    let store = OptionOfferStore::open(store_path)?;
    store.put(option_offer_taproot_pubkey_gen, &arguments)
}

pub fn option_offer_state_export(
    store_path: Option<&Path>,
    option_offer_taproot_pubkey_gen: &str,
) -> Result<String> {
    let store = OptionOfferStore::open(store_path)?;
    store.get_encoded_hex(option_offer_taproot_pubkey_gen)
}

pub fn persist_option_offer_reference(
    store_path: Option<&Path>,
    option_offer_taproot_pubkey_gen: &str,
    arguments: &OptionOfferArguments,
) -> Result<()> {
    let store = OptionOfferStore::open(store_path)?;
    store.put(option_offer_taproot_pubkey_gen, arguments)
}

pub fn resolve_option_offer_reference(
    input: ResolveOptionOfferReferenceInput<'_>,
) -> Result<ResolvedOptionOfferReference> {
    let (arguments, encoded_hex) = if let Some(encoded) = input.encoded_option_offer_arguments {
        let arguments = decode_option_offer_arguments_hex(encoded)?;
        (arguments, encoded.to_string())
    } else {
        let store = OptionOfferStore::open(input.store_path)?;
        let arguments = store.get(input.option_offer_taproot_pubkey_gen)?;
        let encoded_hex = hex::encode(
            arguments
                .encode()
                .context("failed to encode option-offer arguments")?,
        );
        (arguments, encoded_hex)
    };

    let tap = TaprootPubkeyGen::build_from_str(
        input.option_offer_taproot_pubkey_gen,
        &arguments,
        input.network,
        &get_option_offer_address,
    )
    .with_context(|| {
        format!(
            "invalid option-offer taproot reference '{}' for supplied arguments",
            input.option_offer_taproot_pubkey_gen
        )
    })?;

    Ok(ResolvedOptionOfferReference {
        tap,
        arguments,
        encoded_option_offer_arguments: encoded_hex,
    })
}

pub fn build_option_offer_create_request(
    input: OptionOfferCreateBuildInput<'_>,
) -> Result<OptionOfferCreateBuildOutput> {
    validate_fee_rate(input.fee_rate_sat_vb)?;

    let user_pubkey = parse_xonly_pubkey_hex(input.user_xonly_pubkey_hex)?;
    let (collateral_per_contract, premium_per_collateral) =
        derive_contract_terms_from_expected_amounts(
            input.expected_to_deposit_collateral,
            input.expected_to_deposit_premium,
            input.expected_to_get_settlement,
        )?;

    let arguments = OptionOfferArguments::new(
        input.collateral_asset_id,
        input.premium_asset_id,
        input.settlement_asset_id,
        collateral_per_contract,
        premium_per_collateral,
        input.expiry_time,
        user_pubkey,
    );

    let tap = TaprootPubkeyGen::from(&arguments, input.network, &get_option_offer_address)
        .context("failed to derive option-offer taproot handle")?;

    let premium_amount = input
        .expected_to_deposit_collateral
        .checked_mul(premium_per_collateral)
        .context("premium amount overflow")?;

    let tx_create_request = TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_string(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![InputSchema::new("input0"), InputSchema::new("input1")],
            outputs: vec![
                OutputSchema::from_script(
                    "out0",
                    input.collateral_asset_id,
                    input.expected_to_deposit_collateral,
                    tap.address.script_pubkey(),
                ),
                OutputSchema::from_script(
                    "out1",
                    input.premium_asset_id,
                    premium_amount,
                    tap.address.script_pubkey(),
                ),
            ],
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    };

    Ok(OptionOfferCreateBuildOutput {
        tx_create_request,
        taproot_pubkey_gen: tap.to_string(),
        option_offer_address: tap.address.to_string(),
        encoded_option_offer_arguments: hex::encode(
            arguments
                .encode()
                .context("failed to encode option-offer arguments")?,
        ),
        collateral_per_contract,
        premium_per_collateral,
        args: arguments,
    })
}

pub fn build_option_offer_exercise_request(
    input: OptionOfferExerciseBuildInput<'_>,
) -> Result<TxCreateRequest> {
    validate_fee_rate(input.fee_rate_sat_vb)?;
    if input.collateral_amount == 0 {
        bail!("collateral-amount must be greater than 0");
    }

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let to_script = to_address.script_pubkey();
    let (available_collateral, available_premium) = match (
        input.available_collateral_amount,
        input.available_premium_amount,
    ) {
        (Some(collateral), Some(premium)) => (collateral, premium),
        (Some(_), None) | (None, Some(_)) => {
            bail!(
                "--available-collateral-amount and --available-premium-amount must be provided together"
            )
        }
        (None, None) => {
            let esplora = input
                .esplora_url
                .map(ToString::to_string)
                .unwrap_or_else(|| default_esplora_url(input.network));
            resolve_creation_output_amounts(
                &esplora,
                input.creation_tx_id,
                input.arguments.get_collateral_asset_id(),
                input.arguments.get_premium_asset_id(),
            )?
        }
    };

    let premium_amount = input
        .collateral_amount
        .checked_mul(input.arguments.premium_per_collateral())
        .context("premium amount overflow")?;
    let settlement_amount = input
        .collateral_amount
        .checked_mul(input.arguments.collateral_per_contract())
        .context("settlement amount overflow")?;

    let collateral_change = available_collateral
        .checked_sub(input.collateral_amount)
        .ok_or_else(|| anyhow!("requested collateral exceeds covenant collateral balance"))?;
    let premium_change = available_premium
        .checked_sub(premium_amount)
        .ok_or_else(|| anyhow!("requested premium exceeds covenant premium balance"))?;

    let finalizer = build_option_offer_finalizer(
        input.arguments,
        input.tap,
        OptionOfferBranch::Exercise {
            collateral_amount: input.collateral_amount,
            is_change_needed: collateral_change != 0,
        },
    )?;

    let mut outputs: Vec<OutputSchema> = Vec::new();
    if collateral_change != 0 {
        outputs.push(OutputSchema::from_script(
            "covenant-collateral-change",
            input.arguments.get_collateral_asset_id(),
            collateral_change,
            input.tap.address.script_pubkey(),
        ));
        outputs.push(OutputSchema::from_script(
            "covenant-premium-change",
            input.arguments.get_premium_asset_id(),
            premium_change,
            input.tap.address.script_pubkey(),
        ));
    }

    outputs.push(OutputSchema::from_script(
        "covenant-settlement-change",
        input.arguments.get_settlement_asset_id(),
        settlement_amount,
        input.tap.address.script_pubkey(),
    ));
    outputs.push(OutputSchema::from_script(
        "user-collateral-requested",
        input.arguments.get_collateral_asset_id(),
        input.collateral_amount,
        to_script.clone(),
    ));
    outputs.push(OutputSchema::from_script(
        "user-premium-requested",
        input.arguments.get_premium_asset_id(),
        premium_amount,
        to_script,
    ));

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_string(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![
                InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(input.creation_tx_id, 0),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::default(),
                    issuance: None,
                    finalizer: finalizer.clone(),
                },
                InputSchema {
                    id: "input1".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(input.creation_tx_id, 1),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::default(),
                    issuance: None,
                    finalizer,
                },
                InputSchema::new("input2"),
            ],
            outputs,
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    })
}

pub fn build_option_offer_withdraw_request(
    input: OptionOfferWithdrawBuildInput<'_>,
) -> Result<TxCreateRequest> {
    validate_fee_rate(input.fee_rate_sat_vb)?;

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let to_script = to_address.script_pubkey();

    let (settlement_vout, settlement_amount_sat) =
        match (input.settlement_vout, input.settlement_amount_sat) {
            (Some(vout), Some(amount)) => (vout, amount),
            (Some(_), None) | (None, Some(_)) => {
                bail!("--settlement-vout and --settlement-amount-sat must be provided together")
            }
            (None, None) => {
                let esplora = input
                    .esplora_url
                    .map(ToString::to_string)
                    .unwrap_or_else(|| default_esplora_url(input.network));
                resolve_settlement_output_from_exercise(
                    &esplora,
                    input.exercise_tx_id,
                    input.tap.address.script_pubkey(),
                    input.arguments.get_settlement_asset_id(),
                )?
            }
        };

    let finalizer =
        build_option_offer_finalizer(input.arguments, input.tap, OptionOfferBranch::Withdraw)?;

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_string(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![InputSchema {
                id: "input0".to_string(),
                utxo_source: UTXOSource::Provided {
                    outpoint: OutPoint::new(input.exercise_tx_id, settlement_vout),
                },
                blinder: InputBlinder::Explicit,
                sequence: Sequence::default(),
                issuance: None,
                finalizer,
            }],
            outputs: vec![OutputSchema::from_script(
                "out0",
                input.arguments.get_settlement_asset_id(),
                settlement_amount_sat,
                to_script,
            )],
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    })
}

pub fn build_option_offer_expiry_request(
    input: OptionOfferExpiryBuildInput<'_>,
) -> Result<TxCreateRequest> {
    validate_fee_rate(input.fee_rate_sat_vb)?;

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let to_script = to_address.script_pubkey();

    let (collateral_amount, premium_amount) = match (input.collateral_amount, input.premium_amount)
    {
        (Some(collateral), Some(premium)) => (collateral, premium),
        (Some(_), None) | (None, Some(_)) => {
            bail!("--collateral-amount and --premium-amount must be provided together")
        }
        (None, None) => {
            let esplora = input
                .esplora_url
                .map(ToString::to_string)
                .unwrap_or_else(|| default_esplora_url(input.network));
            resolve_creation_output_amounts(
                &esplora,
                input.creation_tx_id,
                input.arguments.get_collateral_asset_id(),
                input.arguments.get_premium_asset_id(),
            )?
        }
    };

    let finalizer =
        build_option_offer_finalizer(input.arguments, input.tap, OptionOfferBranch::Expiry)?;

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_string(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![
                InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(input.creation_tx_id, 0),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    issuance: None,
                    finalizer: finalizer.clone(),
                },
                InputSchema {
                    id: "input1".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(input.creation_tx_id, 1),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    issuance: None,
                    finalizer,
                },
            ],
            outputs: vec![
                OutputSchema::from_script(
                    "out0",
                    input.arguments.get_collateral_asset_id(),
                    collateral_amount,
                    to_script.clone(),
                ),
                OutputSchema::from_script(
                    "out1",
                    input.arguments.get_premium_asset_id(),
                    premium_amount,
                    to_script,
                ),
            ],
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: Some(
                LockTime::from_time(input.arguments.expiry_time())
                    .context("invalid option-offer expiry locktime")?,
            ),
        },
        broadcast: input.broadcast,
    })
}

pub fn decode_option_offer_arguments_hex(value: &str) -> Result<OptionOfferArguments> {
    let bytes = hex::decode(value.trim()).context("invalid --encoded-option-offer-arguments")?;
    OptionOfferArguments::decode(&bytes)
        .context("failed to decode --encoded-option-offer-arguments as OptionOfferArguments")
}

fn build_option_offer_finalizer(
    arguments: &OptionOfferArguments,
    tap: &TaprootPubkeyGen,
    branch: OptionOfferBranch,
) -> Result<FinalizerSpec> {
    let user_xonly = XOnlyPublicKey::from_slice(&arguments.user_pubkey())
        .context("option-offer USER_PUBKEY is invalid")?;

    Ok(FinalizerSpec::Simf {
        source_simf: OPTION_OFFER_SOURCE.to_string(),
        internal_key: InternalKeySource::External {
            key: Box::new(tap.clone()),
        },
        arguments: serialize_arguments(&arguments.build_simf_arguments())
            .context("failed to serialize option-offer SIMF arguments")?,
        witness: serialize_witness(&build_option_offer_witness(&branch, user_xonly))
            .context("failed to serialize option-offer SIMF witness")?,
    })
}

fn parse_xonly_pubkey_hex(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value.trim()).context("invalid --user-xonly-pubkey-hex")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("--user-xonly-pubkey-hex must decode to exactly 32 bytes"))?;
    let _ = XOnlyPublicKey::from_slice(&bytes).context("--user-xonly-pubkey-hex is invalid")?;
    Ok(bytes)
}

fn checked_div_exact_u64(numerator: u64, denominator: u64, label: &str) -> Result<u64> {
    if denominator == 0 {
        bail!("{label} denominator must be > 0");
    }
    if !numerator.is_multiple_of(denominator) {
        bail!("{label} must divide exactly: numerator={numerator}, denominator={denominator}");
    }
    Ok(numerator / denominator)
}

fn derive_contract_terms_from_expected_amounts(
    expected_to_deposit_collateral: u64,
    expected_to_deposit_premium: u64,
    expected_to_get_settlement: u64,
) -> Result<(u64, u64)> {
    if expected_to_deposit_collateral == 0 {
        bail!("expected-to-deposit-collateral must be > 0");
    }

    let premium_per_collateral = checked_div_exact_u64(
        expected_to_deposit_premium,
        expected_to_deposit_collateral,
        "expected-to-deposit-premium / expected-to-deposit-collateral",
    )?;
    let collateral_per_contract = checked_div_exact_u64(
        expected_to_get_settlement,
        expected_to_deposit_collateral,
        "expected-to-get-settlement / expected-to-deposit-collateral",
    )?;

    Ok((collateral_per_contract, premium_per_collateral))
}

fn validate_fee_rate(fee_rate_sat_vb: f32) -> Result<()> {
    if !(fee_rate_sat_vb.is_finite() && fee_rate_sat_vb > 0.0) {
        bail!("fee_rate_sat_vb must be a finite value greater than 0");
    }
    Ok(())
}

fn default_esplora_url(network: Network) -> String {
    match network {
        Network::Liquid => "https://blockstream.info/liquid/api".to_string(),
        Network::TestnetLiquid => "https://blockstream.info/liquidtestnet/api".to_string(),
        Network::LocaltestLiquid => "http://127.0.0.1:3001".to_string(),
    }
}

fn resolve_creation_output_amounts(
    esplora_url: &str,
    creation_tx_id: Txid,
    collateral_asset_id: AssetId,
    premium_asset_id: AssetId,
) -> Result<(u64, u64)> {
    let tx = fetch_transaction(esplora_url, creation_tx_id)?;

    let collateral = tx.output.get(0).ok_or_else(|| {
        anyhow!(
            "creation tx {} is missing collateral output at vout=0",
            creation_tx_id
        )
    })?;
    ensure_explicit_asset(
        Option::from(&collateral.asset.explicit()),
        collateral_asset_id,
        "covenant collateral output",
    )?;
    let collateral_amount =
        explicit_amount(collateral.value.explicit(), "covenant collateral output")?;

    let premium = tx.output.get(1).ok_or_else(|| {
        anyhow!(
            "creation tx {} is missing premium output at vout=1",
            creation_tx_id
        )
    })?;
    ensure_explicit_asset(
        Option::from(&premium.asset.explicit()),
        premium_asset_id,
        "covenant premium output",
    )?;
    let premium_amount = explicit_amount(premium.value.explicit(), "covenant premium output")?;

    Ok((collateral_amount, premium_amount))
}

fn resolve_settlement_output_from_exercise(
    esplora_url: &str,
    exercise_tx_id: Txid,
    covenant_script: Script,
    settlement_asset_id: AssetId,
) -> Result<(u32, u64)> {
    let tx = fetch_transaction(esplora_url, exercise_tx_id)?;

    let outputs = tx
        .output
        .iter()
        .enumerate()
        .map(|(vout, tx_out)| -> Result<Option<CandidateOutput>> {
            if tx_out.asset.is_confidential() {
                return Ok(None);
            }

            let asset_id = tx_out.asset.explicit().ok_or_else(|| {
                anyhow!(
                    "exercise transaction output at vout={} has non-explicit asset id",
                    vout
                )
            })?;

            if asset_id != settlement_asset_id {
                return Ok(None);
            }

            Ok(Some(CandidateOutput {
                vout: u32::try_from(vout).context("exercise transaction vout overflow")?,
                script_pubkey: tx_out.script_pubkey.clone(),
                asset_id: Some(asset_id),
                value_sat: tx_out.value.explicit(),
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    let outputs: Vec<_> = outputs.into_iter().flatten().collect();
    select_settlement_output_for_withdraw(&outputs, &covenant_script, settlement_asset_id)
}

fn select_settlement_output_for_withdraw(
    outputs: &[CandidateOutput],
    covenant_script: &Script,
    settlement_asset_id: AssetId,
) -> Result<(u32, u64)> {
    let Some(selected) = outputs
        .iter()
        .rfind(|output| output.script_pubkey == *covenant_script)
    else {
        bail!("exercise transaction has no covenant settlement output")
    };

    ensure_explicit_asset(
        Option::from(&selected.asset_id),
        settlement_asset_id,
        "selected covenant settlement output",
    )?;
    let amount = explicit_amount(selected.value_sat, "selected covenant settlement output")?;

    Ok((selected.vout, amount))
}

fn fetch_transaction(esplora_url: &str, txid: Txid) -> Result<Transaction> {
    let tx_hex = fetch_transaction_hex(esplora_url, txid)?;
    decode_transaction_hex(&tx_hex)
}

fn fetch_transaction_hex(esplora_url: &str, txid: Txid) -> Result<String> {
    let tx_url = build_esplora_url(esplora_url, &format!("tx/{txid}/hex"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize async runtime for esplora lookup")?;

    runtime.block_on(async move {
        let client = reqwest::Client::new();
        let response = client
            .get(tx_url)
            .send()
            .await
            .context("failed to query esplora transaction endpoint")?
            .error_for_status()
            .context("esplora transaction endpoint returned non-success status")?;

        response
            .text()
            .await
            .context("failed to read esplora tx hex response")
    })
}

fn decode_transaction_hex(tx_hex: &str) -> Result<Transaction> {
    let bytes = hex::decode(tx_hex.trim()).context("failed to decode transaction hex")?;
    encode::deserialize(&bytes).context("failed to decode transaction bytes")
}

fn build_esplora_url(base: &str, endpoint: &str) -> Result<Url> {
    let normalized = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{base}/")
    };

    let base_url =
        Url::parse(&normalized).with_context(|| format!("invalid esplora URL '{base}'"))?;
    base_url
        .join(endpoint.trim_start_matches('/'))
        .with_context(|| format!("failed to build esplora URL for endpoint '{endpoint}'"))
}

fn ensure_explicit_asset(
    actual: Option<&AssetId>,
    expected: AssetId,
    context_label: &str,
) -> Result<()> {
    match actual {
        Some(asset_id) if *asset_id == expected => Ok(()),
        Some(asset_id) => {
            bail!("{context_label} has wrong asset id: expected {expected}, got {asset_id}")
        }
        None => bail!("{context_label} must have explicit asset id"),
    }
}

fn explicit_amount(value: Option<u64>, context_label: &str) -> Result<u64> {
    value.ok_or_else(|| anyhow!("{context_label} must have explicit value"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TESTNET_ADDRESS: &str = "tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m";
    const VALID_USER_XONLY_PUBKEY_HEX: &str =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn valid_user_xonly_pubkey() -> [u8; 32] {
        let bytes = hex::decode(VALID_USER_XONLY_PUBKEY_HEX).expect("hex");
        let bytes: [u8; 32] = bytes.try_into().expect("32 bytes");
        let _ = XOnlyPublicKey::from_slice(&bytes).expect("valid xonly pubkey");
        bytes
    }

    fn test_asset_id(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn test_txid(byte: u8) -> Txid {
        Txid::from_str(&hex::encode([byte; 32])).expect("txid")
    }

    fn build_test_args() -> OptionOfferArguments {
        OptionOfferArguments::new(
            test_asset_id(1),
            test_asset_id(2),
            test_asset_id(3),
            100,
            10,
            1_700_000_000,
            valid_user_xonly_pubkey(),
        )
    }

    #[test]
    fn contract_terms_reject_non_divisible_values() {
        let error = derive_contract_terms_from_expected_amounts(3, 10, 20).expect_err("must fail");
        assert!(
            error
                .to_string()
                .contains("expected-to-deposit-premium / expected-to-deposit-collateral")
        );
    }

    #[test]
    fn import_export_roundtrip_with_store_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store_path = tmp.path().join("store");
        let args = build_test_args();
        let tap = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &get_option_offer_address)
            .expect("tap");
        let encoded = hex::encode(args.encode().expect("encode"));

        option_offer_state_import(
            Some(&store_path),
            Network::TestnetLiquid,
            &tap.to_string(),
            &encoded,
        )
        .expect("import");

        let exported =
            option_offer_state_export(Some(&store_path), &tap.to_string()).expect("export");
        assert_eq!(exported, encoded);
    }

    #[test]
    fn resolve_reference_rejects_taproot_argument_mismatch() {
        let args_a = build_test_args();
        let tap_a =
            TaprootPubkeyGen::from(&args_a, Network::TestnetLiquid, &get_option_offer_address)
                .expect("tap");

        let mut args_b = build_test_args();
        args_b = OptionOfferArguments::new(
            args_b.get_collateral_asset_id(),
            args_b.get_premium_asset_id(),
            AssetId::from_slice(&[8_u8; 32]).expect("asset"),
            args_b.collateral_per_contract(),
            args_b.premium_per_collateral(),
            args_b.expiry_time(),
            args_b.user_pubkey(),
        );
        let encoded_b = hex::encode(args_b.encode().expect("encode"));

        let error = resolve_option_offer_reference(ResolveOptionOfferReferenceInput {
            network: Network::TestnetLiquid,
            option_offer_taproot_pubkey_gen: &tap_a.to_string(),
            encoded_option_offer_arguments: Some(&encoded_b),
            store_path: None,
        })
        .expect_err("must fail for mismatched handle");

        assert!(
            error
                .to_string()
                .contains("invalid option-offer taproot reference")
        );
    }

    #[test]
    fn settlement_selector_uses_latest_matching_covenant_output() {
        let script = Script::new();
        let settlement_asset = test_asset_id(3);

        let outputs = vec![
            CandidateOutput {
                vout: 1,
                script_pubkey: script.clone(),
                asset_id: Some(settlement_asset),
                value_sat: Some(100),
            },
            CandidateOutput {
                vout: 3,
                script_pubkey: script.clone(),
                asset_id: Some(settlement_asset),
                value_sat: Some(200),
            },
        ];

        let (vout, amount) =
            select_settlement_output_for_withdraw(&outputs, &script, settlement_asset)
                .expect("select");

        assert_eq!(vout, 3);
        assert_eq!(amount, 200);
    }

    #[test]
    fn create_builder_produces_expected_deposit_outputs() {
        let input = OptionOfferCreateBuildInput {
            request_id: "req-option-create-test",
            network: Network::TestnetLiquid,
            collateral_asset_id: test_asset_id(1),
            premium_asset_id: test_asset_id(2),
            settlement_asset_id: test_asset_id(3),
            expected_to_deposit_collateral: 10,
            expected_to_deposit_premium: 50,
            expected_to_get_settlement: 1_000,
            expiry_time: 1_800_000_000,
            user_xonly_pubkey_hex: VALID_USER_XONLY_PUBKEY_HEX,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        };

        let output = build_option_offer_create_request(input).expect("create request");

        assert_eq!(output.tx_create_request.params.outputs.len(), 2);
        assert_eq!(output.tx_create_request.params.outputs[0].id, "out0");
        assert_eq!(output.tx_create_request.params.outputs[0].amount_sat, 10);
        assert_eq!(output.tx_create_request.params.outputs[1].id, "out1");
        assert_eq!(output.tx_create_request.params.outputs[1].amount_sat, 50);
        assert_eq!(output.collateral_per_contract, 100);
        assert_eq!(output.premium_per_collateral, 5);
    }

    #[test]
    fn exercise_builder_with_explicit_overrides_produces_expected_shape() {
        let args = build_test_args();
        let tap = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &get_option_offer_address)
            .expect("tap");

        let request = build_option_offer_exercise_request(OptionOfferExerciseBuildInput {
            request_id: "req-option-exercise-test",
            network: Network::TestnetLiquid,
            tap: &tap,
            arguments: &args,
            creation_tx_id: test_txid(9),
            collateral_amount: 5,
            to_address: TESTNET_ADDRESS,
            available_collateral_amount: Some(8),
            available_premium_amount: Some(100),
            esplora_url: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("exercise request");

        let output_ids: Vec<_> = request
            .params
            .outputs
            .iter()
            .map(|output| output.id.as_str())
            .collect();
        assert_eq!(
            output_ids,
            vec![
                "covenant-collateral-change",
                "covenant-premium-change",
                "covenant-settlement-change",
                "user-collateral-requested",
                "user-premium-requested",
            ]
        );
        assert_eq!(request.params.inputs.len(), 3);
        assert!(matches!(
            request.params.outputs[3].blinder,
            wallet_abi::BlinderVariant::Explicit
        ));
        assert!(matches!(
            request.params.outputs[4].blinder,
            wallet_abi::BlinderVariant::Explicit
        ));
    }

    #[test]
    fn withdraw_builder_with_explicit_settlement_uses_provided_outpoint() {
        let args = build_test_args();
        let tap = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &get_option_offer_address)
            .expect("tap");

        let request = build_option_offer_withdraw_request(OptionOfferWithdrawBuildInput {
            request_id: "req-option-withdraw-test",
            network: Network::TestnetLiquid,
            tap: &tap,
            arguments: &args,
            exercise_tx_id: test_txid(10),
            to_address: TESTNET_ADDRESS,
            settlement_vout: Some(4),
            settlement_amount_sat: Some(321),
            esplora_url: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("withdraw request");

        assert_eq!(request.params.inputs.len(), 1);
        assert_eq!(request.params.outputs.len(), 1);
        assert_eq!(request.params.outputs[0].amount_sat, 321);
        assert!(matches!(
            request.params.outputs[0].blinder,
            wallet_abi::BlinderVariant::Explicit
        ));
    }

    #[test]
    fn expiry_builder_with_explicit_amounts_sets_locktime() {
        let args = build_test_args();
        let tap = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &get_option_offer_address)
            .expect("tap");

        let request = build_option_offer_expiry_request(OptionOfferExpiryBuildInput {
            request_id: "req-option-expiry-test",
            network: Network::TestnetLiquid,
            tap: &tap,
            arguments: &args,
            creation_tx_id: test_txid(11),
            to_address: TESTNET_ADDRESS,
            collateral_amount: Some(777),
            premium_amount: Some(111),
            esplora_url: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("expiry request");

        assert_eq!(request.params.inputs.len(), 2);
        assert_eq!(request.params.outputs.len(), 2);
        assert!(request.params.locktime.is_some());
        assert!(matches!(
            request.params.outputs[0].blinder,
            wallet_abi::BlinderVariant::Explicit
        ));
        assert!(matches!(
            request.params.outputs[1].blinder,
            wallet_abi::BlinderVariant::Explicit
        ));
    }
}
