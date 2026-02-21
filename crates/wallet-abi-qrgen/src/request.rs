use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use simplicityhl::elements::{Address, AssetId, Sequence};
use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
use wallet_abi::{
    AmountFilter, AssetFilter, AssetVariant, BlinderVariant, FinalizerSpec, InputBlinder,
    InputIssuance, InputIssuanceKind, InputSchema, LockFilter, LockVariant, OutputSchema,
    RuntimeParams, UTXOSource, WalletSourceFilter,
};

pub struct SimpleTransferRequestInput<'a> {
    pub request_id: &'a str,
    pub network: wallet_abi::Network,
    pub to_address: &'a str,
    pub amount_sat: u64,
    pub asset_id: Option<&'a str>,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

pub struct SplitTransferRequestInput<'a> {
    pub request_id: &'a str,
    pub network: wallet_abi::Network,
    pub to_address: &'a str,
    pub split_parts: u16,
    pub part_amount_sat: u64,
    pub asset_id: Option<&'a str>,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

pub struct IssueAssetRequestInput<'a> {
    pub request_id: &'a str,
    pub network: wallet_abi::Network,
    pub to_address: &'a str,
    pub issue_amount_sat: u64,
    pub token_amount_sat: u64,
    pub issuance_entropy_hex: &'a str,
    pub funding_asset_id: Option<&'a str>,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

pub struct ReissueAssetRequestInput<'a> {
    pub request_id: &'a str,
    pub network: wallet_abi::Network,
    pub to_address: &'a str,
    pub reissue_token_asset_id: &'a str,
    pub reissue_amount_sat: u64,
    pub asset_entropy_hex: &'a str,
    pub token_change_sat: u64,
    pub fee_rate_sat_vb: f32,
    pub broadcast: bool,
}

pub fn build_simple_transfer_request(
    input: SimpleTransferRequestInput<'_>,
) -> Result<TxCreateRequest> {
    validate_request_id(input.request_id)?;

    if input.amount_sat == 0 {
        bail!("amount_sat must be greater than 0");
    }

    if !(input.fee_rate_sat_vb.is_finite() && input.fee_rate_sat_vb > 0.0) {
        bail!("fee_rate_sat_vb must be a finite value greater than 0");
    }

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let asset_id = resolve_asset_id(input.asset_id, input.network, "--asset-id")?;

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_owned(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![wallet_input_with_exact_asset(
                "input0",
                asset_id,
                AmountFilter::default(),
                None,
            )],
            outputs: vec![OutputSchema::from_address(
                "out0",
                asset_id,
                input.amount_sat,
                &to_address,
            )],
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    })
}

pub fn build_split_transfer_request(
    input: SplitTransferRequestInput<'_>,
) -> Result<TxCreateRequest> {
    validate_request_id(input.request_id)?;

    if input.split_parts < 2 {
        bail!("split_parts must be at least 2");
    }
    if input.part_amount_sat == 0 {
        bail!("part_amount_sat must be greater than 0");
    }
    let _total_amount_sat = input
        .part_amount_sat
        .checked_mul(u64::from(input.split_parts))
        .context("total output amount overflow")?;
    if !(input.fee_rate_sat_vb.is_finite() && input.fee_rate_sat_vb > 0.0) {
        bail!("fee_rate_sat_vb must be a finite value greater than 0");
    }

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let asset_id = resolve_asset_id(input.asset_id, input.network, "--asset-id")?;

    let mut outputs = Vec::with_capacity(usize::from(input.split_parts));
    for index in 0..input.split_parts {
        outputs.push(OutputSchema::from_address(
            format!("out{index}"),
            asset_id,
            input.part_amount_sat,
            &to_address,
        ));
    }

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_owned(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![wallet_input_with_exact_asset(
                "input0",
                asset_id,
                AmountFilter::default(),
                None,
            )],
            outputs,
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    })
}

pub fn build_issue_asset_request(input: IssueAssetRequestInput<'_>) -> Result<TxCreateRequest> {
    validate_request_id(input.request_id)?;

    if input.issue_amount_sat == 0 {
        bail!("issue_amount_sat must be greater than 0");
    }
    if input.token_amount_sat == 0 {
        bail!("token_amount_sat must be greater than 0");
    }
    if !(input.fee_rate_sat_vb.is_finite() && input.fee_rate_sat_vb > 0.0) {
        bail!("fee_rate_sat_vb must be a finite value greater than 0");
    }

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let funding_asset_id =
        resolve_asset_id(input.funding_asset_id, input.network, "--funding-asset-id")?;
    let entropy = parse_entropy_hex(input.issuance_entropy_hex, "--issuance-entropy-hex")?;

    let issuance = InputIssuance {
        kind: InputIssuanceKind::New,
        asset_amount_sat: input.issue_amount_sat,
        token_amount_sat: input.token_amount_sat,
        entropy,
    };

    let outputs = vec![
        output_to_address_with_asset_variant(
            "token-output",
            input.token_amount_sat,
            AssetVariant::NewIssuanceToken { input_index: 0 },
            &to_address,
        ),
        output_to_address_with_asset_variant(
            "asset-output",
            input.issue_amount_sat,
            AssetVariant::NewIssuanceAsset { input_index: 0 },
            &to_address,
        ),
    ];

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_owned(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![wallet_input_with_exact_asset(
                "input0",
                funding_asset_id,
                AmountFilter::default(),
                Some(issuance),
            )],
            outputs,
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    })
}

pub fn build_reissue_asset_request(input: ReissueAssetRequestInput<'_>) -> Result<TxCreateRequest> {
    validate_request_id(input.request_id)?;

    if input.reissue_amount_sat == 0 {
        bail!("reissue_amount_sat must be greater than 0");
    }
    if input.token_change_sat == 0 {
        bail!("token_change_sat must be greater than 0");
    }
    if !(input.fee_rate_sat_vb.is_finite() && input.fee_rate_sat_vb > 0.0) {
        bail!("fee_rate_sat_vb must be a finite value greater than 0");
    }

    let to_address = parse_and_validate_address(input.to_address, input.network)?;
    let reissue_token_asset_id =
        AssetId::from_str(input.reissue_token_asset_id).with_context(|| {
            format!(
                "invalid --reissue-token-asset-id '{}'",
                input.reissue_token_asset_id
            )
        })?;
    let entropy = parse_entropy_hex(input.asset_entropy_hex, "--asset-entropy-hex")?;

    let issuance = InputIssuance {
        kind: InputIssuanceKind::Reissue,
        asset_amount_sat: input.reissue_amount_sat,
        token_amount_sat: 0,
        entropy,
    };

    let outputs = vec![
        OutputSchema::from_address(
            "token-change",
            reissue_token_asset_id,
            input.token_change_sat,
            &to_address,
        ),
        output_to_address_with_asset_variant(
            "reissued-asset",
            input.reissue_amount_sat,
            AssetVariant::ReIssuanceAsset { input_index: 0 },
            &to_address,
        ),
    ];

    Ok(TxCreateRequest {
        abi_version: TX_CREATE_ABI_VERSION.to_string(),
        request_id: input.request_id.to_owned(),
        network: input.network,
        params: RuntimeParams {
            inputs: vec![wallet_input_with_exact_asset(
                "input0",
                reissue_token_asset_id,
                AmountFilter::Min {
                    satoshi: input.token_change_sat,
                },
                Some(issuance),
            )],
            outputs,
            fee_rate_sat_vb: Some(input.fee_rate_sat_vb),
            locktime: None,
        },
        broadcast: input.broadcast,
    })
}

pub fn parse_and_validate_address(address: &str, network: wallet_abi::Network) -> Result<Address> {
    let parsed =
        Address::from_str(address).with_context(|| format!("invalid --to-address '{address}'"))?;

    if parsed.params != network.address_params() {
        return Err(anyhow!(
            "address network mismatch: expected {}, got {}",
            network,
            if parsed.params == &simplicityhl::elements::AddressParams::LIQUID {
                "liquid"
            } else if parsed.params == &simplicityhl::elements::AddressParams::LIQUID_TESTNET {
                "testnet-liquid"
            } else {
                "localtest-liquid"
            }
        ));
    }

    Ok(parsed)
}

pub fn validate_request_id(request_id: &str) -> Result<()> {
    if request_id.trim().is_empty() {
        bail!("request_id must not be empty");
    }

    if request_id.trim() != request_id {
        bail!("request_id must not have leading or trailing whitespace");
    }

    if request_id
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '/' || ch == '\\')
    {
        bail!("request_id contains unsupported characters");
    }

    Ok(())
}

fn resolve_asset_id(
    asset_id: Option<&str>,
    network: wallet_abi::Network,
    arg_name: &str,
) -> Result<AssetId> {
    match asset_id {
        Some(asset_id) => {
            AssetId::from_str(asset_id).with_context(|| format!("invalid {arg_name} '{asset_id}'"))
        }
        None => Ok(*network.policy_asset()),
    }
}

fn parse_entropy_hex(value: &str, arg_name: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value)
        .with_context(|| format!("invalid {arg_name}: expected hex-encoded bytes"))?;
    let entropy: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{arg_name} must decode to exactly 32 bytes"))?;
    Ok(entropy)
}

fn wallet_input_with_exact_asset(
    id: &str,
    asset_id: AssetId,
    amount_filter: AmountFilter,
    issuance: Option<InputIssuance>,
) -> InputSchema {
    InputSchema {
        id: id.to_string(),
        utxo_source: UTXOSource::Wallet {
            filter: WalletSourceFilter {
                asset: AssetFilter::Exact { asset_id },
                amount: amount_filter,
                lock: LockFilter::default(),
            },
        },
        blinder: InputBlinder::default(),
        sequence: Sequence::default(),
        issuance,
        finalizer: FinalizerSpec::default(),
    }
}

fn output_to_address_with_asset_variant(
    id: &str,
    amount_sat: u64,
    asset: AssetVariant,
    address: &Address,
) -> OutputSchema {
    let blinder = address
        .blinding_pubkey
        .map_or_else(BlinderVariant::default, |pubkey| BlinderVariant::Provided {
            pubkey,
        });

    OutputSchema {
        id: id.to_string(),
        amount_sat,
        lock: LockVariant::Script {
            script: address.script_pubkey(),
        },
        asset,
        blinder,
    }
}
