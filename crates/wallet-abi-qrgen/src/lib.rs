#![warn(clippy::all, clippy::pedantic)]

pub mod cli;
pub mod option_offer;
pub mod qr;
pub mod relay_connect;
pub mod request;
pub mod transport;

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use wallet_abi::schema::tx_create::TxCreateRequest;

use crate::cli::{
    CallbackModeArg, Cli, Command, CommonRequestArgs, IssueAssetArgs, ParseKindArg,
    ParsePayloadArgs, ReissueAssetArgs, RelayConnectArgs, RelayIssueAssetArgs,
    RelayOptionOfferCommand, RelayOptionOfferCreateArgs, RelayOptionOfferExerciseArgs,
    RelayOptionOfferExpiryArgs, RelayOptionOfferWithdrawArgs, RelayReissueAssetArgs,
    RelayRequestCommand, RelaySimpleTransferArgs, RelaySplitTransferArgs, SimpleTransferArgs,
    SplitTransferArgs,
};
use crate::cli::{OptionOfferStateArgs, OptionOfferStateCommand};
use crate::option_offer::{
    OptionOfferCreateBuildInput, OptionOfferCreateBuildOutput, OptionOfferExerciseBuildInput,
    OptionOfferExpiryBuildInput, OptionOfferRefArtifact, OptionOfferWithdrawBuildInput,
    ResolveOptionOfferReferenceInput, build_option_offer_create_request,
    build_option_offer_exercise_request, build_option_offer_expiry_request,
    build_option_offer_withdraw_request, option_offer_state_export, option_offer_state_import,
    persist_option_offer_reference, resolve_option_offer_reference,
};
use crate::qr::{render_png_qr, render_text_qr};
use crate::relay_connect::{RelayConnectRunInput, run_relay_connect as run_relay_connect_flow};
use crate::request::{
    IssueAssetRequestInput, ReissueAssetRequestInput, SimpleTransferRequestInput,
    SplitTransferRequestInput, build_issue_asset_request, build_reissue_asset_request,
    build_simple_transfer_request, build_split_transfer_request, validate_request_id,
};
use crate::transport::{
    TransportBuildInput, WALLET_ABI_TRANSPORT_REQUEST_PARAM, WALLET_ABI_TRANSPORT_RESPONSE_PARAM,
    WalletAbiTransportCallbackMode, build_deep_link, build_transport_request,
    decode_transport_request, decode_transport_response, encode_transport_request,
    extract_fragment_param,
};

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::SimpleTransfer(args) => run_simple_transfer(args),
        Command::SplitTransfer(args) => run_split_transfer(args),
        Command::IssueAsset(args) => run_issue_asset(args),
        Command::ReissueAsset(args) => run_reissue_asset(args),
        Command::ParsePayload(args) => run_parse_payload(args),
        Command::RelayConnect(args) => run_relay_connect(args),
        Command::OptionOfferState(args) => run_option_offer_state(args),
    }
}

fn run_simple_transfer(args: SimpleTransferArgs) -> Result<()> {
    let request_id = resolve_request_id(&args.common)?;
    let tx_create_request = build_simple_transfer_request(SimpleTransferRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        amount_sat: args.amount_sat,
        asset_id: args.asset_id.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    emit_transport_artifacts(&args.common, tx_create_request)
}

fn run_split_transfer(args: SplitTransferArgs) -> Result<()> {
    let request_id = resolve_request_id(&args.common)?;
    let tx_create_request = build_split_transfer_request(SplitTransferRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        split_parts: args.split_parts,
        part_amount_sat: args.part_amount_sat,
        asset_id: args.asset_id.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    emit_transport_artifacts(&args.common, tx_create_request)
}

fn run_issue_asset(args: IssueAssetArgs) -> Result<()> {
    let request_id = resolve_request_id(&args.common)?;
    let tx_create_request = build_issue_asset_request(IssueAssetRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        issue_amount_sat: args.issue_amount_sat,
        token_amount_sat: args.token_amount_sat,
        issuance_entropy_hex: &args.issuance_entropy_hex,
        funding_asset_id: args.funding_asset_id.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    emit_transport_artifacts(&args.common, tx_create_request)
}

fn run_reissue_asset(args: ReissueAssetArgs) -> Result<()> {
    let request_id = resolve_request_id(&args.common)?;
    let tx_create_request = build_reissue_asset_request(ReissueAssetRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        reissue_token_asset_id: &args.reissue_token_asset_id,
        reissue_amount_sat: args.reissue_amount_sat,
        asset_entropy_hex: &args.asset_entropy_hex,
        token_change_sat: args.token_change_sat,
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    emit_transport_artifacts(&args.common, tx_create_request)
}

fn run_relay_connect(args: RelayConnectArgs) -> Result<()> {
    let build_output = match args.request {
        RelayRequestCommand::SimpleTransfer(command) => build_relay_simple_transfer(command)?,
        RelayRequestCommand::SplitTransfer(command) => build_relay_split_transfer(command)?,
        RelayRequestCommand::IssueAsset(command) => build_relay_issue_asset(command)?,
        RelayRequestCommand::ReissueAsset(command) => build_relay_reissue_asset(command)?,
        RelayRequestCommand::OptionOffer(command) => build_relay_option_offer(command)?,
    };

    if let Some(reference) = &build_output.option_offer_ref_artifact {
        println!(
            "option_offer_taproot_pubkey_gen: {}",
            reference.taproot_pubkey_gen
        );
        println!("option_offer_address: {}", reference.option_offer_address);
        println!(
            "encoded_option_offer_arguments: {}",
            reference.encoded_option_offer_arguments
        );
    }

    run_relay_connect_flow(RelayConnectRunInput {
        relay_http_url: args.relay_http_url,
        base_link: args.base_link,
        out_dir: args.out_dir,
        pixel_per_module: args.pixel_per_module,
        wait_timeout_ms: args.wait_timeout_ms,
        request_id: build_output.request_id,
        origin: build_output.origin,
        ttl_ms: build_output.ttl_ms,
        tx_create_request: build_output.tx_create_request,
        option_offer_ref_artifact: build_output.option_offer_ref_artifact,
    })
}

fn run_option_offer_state(args: OptionOfferStateArgs) -> Result<()> {
    match args.command {
        OptionOfferStateCommand::Import(command) => option_offer_state_import(
            command.store_path.as_deref(),
            command.network,
            &command.option_offer_taproot_pubkey_gen,
            &command.encoded_option_offer_arguments,
        ),
        OptionOfferStateCommand::Export(command) => {
            let encoded = option_offer_state_export(
                command.store_path.as_deref(),
                &command.option_offer_taproot_pubkey_gen,
            )?;
            println!("{encoded}");
            Ok(())
        }
    }
}

fn resolve_request_id(args: &CommonRequestArgs) -> Result<String> {
    let request_id = args.request_id.clone();
    resolve_optional_request_id(request_id)
}

fn resolve_optional_request_id(request_id: Option<String>) -> Result<String> {
    let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_request_id(&request_id)?;
    Ok(request_id)
}

#[derive(Debug, Clone)]
struct RelayRequestBuildOutput {
    request_id: String,
    origin: String,
    ttl_ms: u64,
    tx_create_request: TxCreateRequest,
    option_offer_ref_artifact: Option<OptionOfferRefArtifact>,
}

fn build_relay_simple_transfer(args: RelaySimpleTransferArgs) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let tx_create_request = build_simple_transfer_request(SimpleTransferRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        amount_sat: args.amount_sat,
        asset_id: args.asset_id.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn build_relay_split_transfer(args: RelaySplitTransferArgs) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let tx_create_request = build_split_transfer_request(SplitTransferRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        split_parts: args.split_parts,
        part_amount_sat: args.part_amount_sat,
        asset_id: args.asset_id.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn build_relay_issue_asset(args: RelayIssueAssetArgs) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let tx_create_request = build_issue_asset_request(IssueAssetRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        issue_amount_sat: args.issue_amount_sat,
        token_amount_sat: args.token_amount_sat,
        issuance_entropy_hex: &args.issuance_entropy_hex,
        funding_asset_id: args.funding_asset_id.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn build_relay_reissue_asset(args: RelayReissueAssetArgs) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let tx_create_request = build_reissue_asset_request(ReissueAssetRequestInput {
        request_id: &request_id,
        network: args.common.network,
        to_address: &args.to_address,
        reissue_token_asset_id: &args.reissue_token_asset_id,
        reissue_amount_sat: args.reissue_amount_sat,
        asset_entropy_hex: &args.asset_entropy_hex,
        token_change_sat: args.token_change_sat,
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn build_relay_option_offer(command: RelayOptionOfferCommand) -> Result<RelayRequestBuildOutput> {
    match command {
        RelayOptionOfferCommand::Create(args) => build_relay_option_offer_create(args),
        RelayOptionOfferCommand::Exercise(args) => build_relay_option_offer_exercise(args),
        RelayOptionOfferCommand::Withdraw(args) => build_relay_option_offer_withdraw(args),
        RelayOptionOfferCommand::Expiry(args) => build_relay_option_offer_expiry(args),
    }
}

fn build_relay_option_offer_create(
    args: RelayOptionOfferCreateArgs,
) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let create_output: OptionOfferCreateBuildOutput =
        build_option_offer_create_request(OptionOfferCreateBuildInput {
            request_id: &request_id,
            network: args.common.network,
            collateral_asset_id: args.collateral_asset_id,
            premium_asset_id: args.premium_asset_id,
            settlement_asset_id: args.settlement_asset_id,
            expected_to_deposit_collateral: args.expected_to_deposit_collateral,
            expected_to_deposit_premium: args.expected_to_deposit_premium,
            expected_to_get_settlement: args.expected_to_get_settlement,
            expiry_time: args.expiry_time,
            user_xonly_pubkey_hex: &args.user_xonly_pubkey_hex,
            fee_rate_sat_vb: args.common.fee_rate_sat_vb,
            broadcast: args.common.broadcast,
        })?;

    persist_option_offer_reference(
        args.store_path.as_deref(),
        &create_output.taproot_pubkey_gen,
        &create_output.args,
    )?;

    let option_offer_ref_artifact = OptionOfferRefArtifact {
        taproot_pubkey_gen: create_output.taproot_pubkey_gen.clone(),
        option_offer_address: create_output.option_offer_address.clone(),
        encoded_option_offer_arguments: create_output.encoded_option_offer_arguments.clone(),
        collateral_per_contract: create_output.collateral_per_contract,
        premium_per_collateral: create_output.premium_per_collateral,
        expiry_time: args.expiry_time,
    };

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request: create_output.tx_create_request,
        option_offer_ref_artifact: Some(option_offer_ref_artifact),
    })
}

fn build_relay_option_offer_exercise(
    args: RelayOptionOfferExerciseArgs,
) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let resolved = resolve_option_offer_reference(ResolveOptionOfferReferenceInput {
        network: args.common.network,
        option_offer_taproot_pubkey_gen: &args.option_offer_taproot_pubkey_gen,
        encoded_option_offer_arguments: args.encoded_option_offer_arguments.as_deref(),
        store_path: args.store_path.as_deref(),
    })?;

    let tx_create_request = build_option_offer_exercise_request(OptionOfferExerciseBuildInput {
        request_id: &request_id,
        network: args.common.network,
        tap: &resolved.tap,
        arguments: &resolved.arguments,
        creation_tx_id: args.creation_tx_id,
        collateral_amount: args.collateral_amount,
        to_address: &args.to_address,
        available_collateral_amount: args.available_collateral_amount,
        available_premium_amount: args.available_premium_amount,
        esplora_url: args.esplora_url.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn build_relay_option_offer_withdraw(
    args: RelayOptionOfferWithdrawArgs,
) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let resolved = resolve_option_offer_reference(ResolveOptionOfferReferenceInput {
        network: args.common.network,
        option_offer_taproot_pubkey_gen: &args.option_offer_taproot_pubkey_gen,
        encoded_option_offer_arguments: args.encoded_option_offer_arguments.as_deref(),
        store_path: args.store_path.as_deref(),
    })?;

    let tx_create_request = build_option_offer_withdraw_request(OptionOfferWithdrawBuildInput {
        request_id: &request_id,
        network: args.common.network,
        tap: &resolved.tap,
        arguments: &resolved.arguments,
        exercise_tx_id: args.exercise_tx_id,
        to_address: &args.to_address,
        settlement_vout: args.settlement_vout,
        settlement_amount_sat: args.settlement_amount_sat,
        esplora_url: args.esplora_url.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn build_relay_option_offer_expiry(
    args: RelayOptionOfferExpiryArgs,
) -> Result<RelayRequestBuildOutput> {
    let request_id = resolve_optional_request_id(args.common.request_id)?;
    let resolved = resolve_option_offer_reference(ResolveOptionOfferReferenceInput {
        network: args.common.network,
        option_offer_taproot_pubkey_gen: &args.option_offer_taproot_pubkey_gen,
        encoded_option_offer_arguments: args.encoded_option_offer_arguments.as_deref(),
        store_path: args.store_path.as_deref(),
    })?;

    let tx_create_request = build_option_offer_expiry_request(OptionOfferExpiryBuildInput {
        request_id: &request_id,
        network: args.common.network,
        tap: &resolved.tap,
        arguments: &resolved.arguments,
        creation_tx_id: args.creation_tx_id,
        to_address: &args.to_address,
        collateral_amount: args.collateral_amount,
        premium_amount: args.premium_amount,
        esplora_url: args.esplora_url.as_deref(),
        fee_rate_sat_vb: args.common.fee_rate_sat_vb,
        broadcast: args.common.broadcast,
    })?;

    Ok(RelayRequestBuildOutput {
        request_id,
        origin: args.common.origin,
        ttl_ms: args.common.ttl_ms,
        tx_create_request,
        option_offer_ref_artifact: None,
    })
}

fn emit_transport_artifacts(
    args: &CommonRequestArgs,
    tx_create_request: TxCreateRequest,
) -> Result<()> {
    let callback_mode = match args.callback_mode {
        CallbackModeArg::SameDeviceHttps => WalletAbiTransportCallbackMode::SameDeviceHttps,
        CallbackModeArg::BackendPush => WalletAbiTransportCallbackMode::BackendPush,
        CallbackModeArg::QrRoundtrip => WalletAbiTransportCallbackMode::QrRoundtrip,
    };

    let created_at_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_millis()
        .try_into()
        .context("current timestamp does not fit in u64")?;

    let request_id = tx_create_request.request_id.clone();
    let transport_request = build_transport_request(TransportBuildInput {
        request_id: request_id.clone(),
        origin: args.origin.clone(),
        created_at_ms,
        ttl_ms: args.ttl_ms,
        callback_mode,
        callback_url: args.callback_url.clone(),
        tx_create_request: tx_create_request.clone(),
    })?;

    let encoded_payload = encode_transport_request(&transport_request)?;
    let deep_link = build_deep_link(&args.base_link, &encoded_payload);

    let qr_text = render_text_qr(&deep_link)?;
    let qr_png = render_png_qr(&deep_link, args.pixel_per_module)?;

    fs::create_dir_all(&args.out_dir).with_context(|| {
        format!(
            "failed to create output directory '{}'",
            args.out_dir.display()
        )
    })?;

    let tx_request_path = args
        .out_dir
        .join(format!("{request_id}.tx_create_request.json"));
    let transport_request_path = args
        .out_dir
        .join(format!("{request_id}.transport_request.json"));
    let deep_link_path = args.out_dir.join(format!("{request_id}.deep_link.txt"));
    let qr_png_path = args.out_dir.join(format!("{request_id}.qr.png"));

    write_json_file(&tx_request_path, &tx_create_request)?;
    write_json_file(&transport_request_path, &transport_request)?;
    write_text_file(&deep_link_path, format!("{deep_link}\n"))?;
    write_binary_file(&qr_png_path, &qr_png)?;

    println!("request_id: {request_id}");
    println!("deep_link: {deep_link}");
    println!("wa_v1_length: {}", encoded_payload.len());
    println!("expires_at_ms: {}", transport_request.expires_at_ms);
    println!("qr_png: {}", qr_png_path.display());
    println!("qr_text:\n{qr_text}");

    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParsedPayloadKind {
    Request,
    Response,
}

fn run_parse_payload(args: ParsePayloadArgs) -> Result<()> {
    let input = read_parse_input(&args)?;
    let (hinted_kind, payload) = extract_payload_from_input(&input);
    if payload.trim().is_empty() {
        bail!("payload input is empty");
    }

    let forced_kind = match args.kind {
        ParseKindArg::Auto => None,
        ParseKindArg::Request => Some(ParsedPayloadKind::Request),
        ParseKindArg::Response => Some(ParsedPayloadKind::Response),
    };

    let decode_order = match (forced_kind, hinted_kind) {
        (Some(kind), _) => vec![kind],
        (None, Some(kind)) => {
            if kind == ParsedPayloadKind::Response {
                vec![ParsedPayloadKind::Response, ParsedPayloadKind::Request]
            } else {
                vec![ParsedPayloadKind::Request, ParsedPayloadKind::Response]
            }
        }
        (None, None) => vec![ParsedPayloadKind::Response, ParsedPayloadKind::Request],
    };

    let mut errors = Vec::new();
    for kind in decode_order {
        match kind {
            ParsedPayloadKind::Response => match decode_transport_response(&payload) {
                Ok(response) => {
                    println!("kind: response");
                    println!("request_id: {}", response.request_id);
                    println!("origin: {}", response.origin);
                    println!("processed_at_ms: {}", response.processed_at_ms);
                    println!(
                        "decoded_json:\n{}",
                        serde_json::to_string_pretty(&response)
                            .context("failed to format decoded response JSON")?
                    );
                    return Ok(());
                }
                Err(error) => errors.push(format!("response decode failed: {error}")),
            },
            ParsedPayloadKind::Request => match decode_transport_request(&payload) {
                Ok(request) => {
                    println!("kind: request");
                    println!("request_id: {}", request.request_id);
                    println!("origin: {}", request.origin);
                    println!("expires_at_ms: {}", request.expires_at_ms);
                    println!(
                        "decoded_json:\n{}",
                        serde_json::to_string_pretty(&request)
                            .context("failed to format decoded request JSON")?
                    );
                    return Ok(());
                }
                Err(error) => errors.push(format!("request decode failed: {error}")),
            },
        }
    }

    bail!("failed to decode payload; {}", errors.join(" | "));
}

fn read_parse_input(args: &ParsePayloadArgs) -> Result<String> {
    if let Some(input_file) = &args.input_file {
        return fs::read_to_string(input_file)
            .with_context(|| format!("failed to read '{}'", input_file.display()));
    }

    args.input
        .as_ref()
        .map(ToString::to_string)
        .context("missing payload input")
}

fn extract_payload_from_input(input: &str) -> (Option<ParsedPayloadKind>, String) {
    let trimmed = input.trim().trim_matches(|c| matches!(c, '"' | '\''));

    if let Some(value) = extract_fragment_param(trimmed, WALLET_ABI_TRANSPORT_RESPONSE_PARAM) {
        return (Some(ParsedPayloadKind::Response), value);
    }

    if let Some(value) = extract_fragment_param(trimmed, WALLET_ABI_TRANSPORT_REQUEST_PARAM) {
        return (Some(ParsedPayloadKind::Request), value);
    }

    if let Some(value) = trimmed.strip_prefix(&format!("{WALLET_ABI_TRANSPORT_RESPONSE_PARAM}=")) {
        return (Some(ParsedPayloadKind::Response), value.to_string());
    }

    if let Some(value) = trimmed.strip_prefix(&format!("{WALLET_ABI_TRANSPORT_REQUEST_PARAM}=")) {
        return (Some(ParsedPayloadKind::Request), value.to_string());
    }

    (None, trimmed.trim_start_matches('#').to_string())
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
    use crate::request::parse_and_validate_address;
    use crate::transport::{
        WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS, WALLET_ABI_TRANSPORT_RESPONSE_PARAM,
        WalletAbiTransportResponseV1, decode_transport_request, decode_transport_response,
        encode_transport_response, extract_fragment_param,
    };
    use serde_json::json;

    const TESTNET_ADDRESS: &str = "tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m";
    const MAINNET_ADDRESS: &str = "lq1qqvp9g33gw9y05xava3dvcpq8pnkv82yj3tdnzp547eyp9yrztz2lkyxrhscd55ev4p7lj2n72jtkn5u4xnj4v577c42jhf3ww";
    const ENTROPY_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const REISSUE_TOKEN_ASSET_ID: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn transport_encode_decode_roundtrip() {
        let tx_request = build_simple_transfer_request(SimpleTransferRequestInput {
            request_id: "req-1",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            amount_sat: 1000,
            asset_id: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("request should build");

        let envelope = build_transport_request(TransportBuildInput {
            request_id: "req-1".to_string(),
            origin: "https://dapp.example".to_string(),
            created_at_ms: 1_700_000_000_000,
            ttl_ms: 120_000,
            callback_mode: WalletAbiTransportCallbackMode::QrRoundtrip,
            callback_url: None,
            tx_create_request: tx_request,
        })
        .expect("transport request should build");

        let encoded = encode_transport_request(&envelope).expect("encoded");
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let decoded = decode_transport_request(&encoded).expect("decoded");
        assert_eq!(decoded.request_id, "req-1");
        assert_eq!(decoded.tx_create_request.request_id, "req-1");
    }

    #[test]
    fn ttl_validation_rejects_values_over_limit() {
        let tx_request = build_simple_transfer_request(SimpleTransferRequestInput {
            request_id: "req-ttl",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            amount_sat: 1000,
            asset_id: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("request should build");

        let err = build_transport_request(TransportBuildInput {
            request_id: "req-ttl".to_string(),
            origin: "https://dapp.example".to_string(),
            created_at_ms: 1,
            ttl_ms: WALLET_ABI_TRANSPORT_MAX_REQUEST_TTL_MS + 1,
            callback_mode: WalletAbiTransportCallbackMode::QrRoundtrip,
            callback_url: None,
            tx_create_request: tx_request,
        })
        .expect_err("should fail ttl validation");

        assert!(err.to_string().contains("ttl_ms"));
    }

    #[test]
    fn callback_mode_rules_are_enforced() {
        let tx_request = build_simple_transfer_request(SimpleTransferRequestInput {
            request_id: "req-cb",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            amount_sat: 1000,
            asset_id: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("request should build");

        let same_device_missing_url = build_transport_request(TransportBuildInput {
            request_id: "req-cb".to_string(),
            origin: "https://dapp.example".to_string(),
            created_at_ms: 1,
            ttl_ms: 120_000,
            callback_mode: WalletAbiTransportCallbackMode::SameDeviceHttps,
            callback_url: None,
            tx_create_request: tx_request.clone(),
        });
        assert!(same_device_missing_url.is_err());

        let qr_with_url = build_transport_request(TransportBuildInput {
            request_id: "req-cb".to_string(),
            origin: "https://dapp.example".to_string(),
            created_at_ms: 1,
            ttl_ms: 120_000,
            callback_mode: WalletAbiTransportCallbackMode::QrRoundtrip,
            callback_url: Some("https://dapp.example/callback".to_string()),
            tx_create_request: tx_request,
        });
        assert!(qr_with_url.is_err());
    }

    #[test]
    fn request_id_mismatch_between_transport_and_tx_request_is_rejected() {
        let tx_request = build_simple_transfer_request(SimpleTransferRequestInput {
            request_id: "req-a",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            amount_sat: 1000,
            asset_id: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("request should build");

        let err = build_transport_request(TransportBuildInput {
            request_id: "req-b".to_string(),
            origin: "https://dapp.example".to_string(),
            created_at_ms: 1,
            ttl_ms: 120_000,
            callback_mode: WalletAbiTransportCallbackMode::QrRoundtrip,
            callback_url: None,
            tx_create_request: tx_request,
        })
        .expect_err("request id mismatch should fail");

        assert!(err.to_string().contains("request_id mismatch"));
    }

    #[test]
    fn address_network_mismatch_is_rejected() {
        let err = parse_and_validate_address(MAINNET_ADDRESS, wallet_abi::Network::TestnetLiquid)
            .expect_err("network mismatch should fail");

        assert!(err.to_string().contains("address network mismatch"));
    }

    #[test]
    fn generated_png_has_png_signature() {
        let png = render_png_qr("https://blockstream.com/walletabi/request#wa_v1=abc", 8)
            .expect("png should be generated");

        assert!(png.len() > 8);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn transport_response_encode_decode_roundtrip() {
        let response = WalletAbiTransportResponseV1 {
            v: 1,
            request_id: "req-resp-1".to_string(),
            origin: "https://dapp.example".to_string(),
            processed_at_ms: 1_700_000_000_123,
            tx_create_response: Some(json!({
                "request_id": "req-resp-1",
                "status": "ok",
            })),
            error: None,
        };

        let encoded = encode_transport_response(&response).expect("encoded");
        let decoded = decode_transport_response(&encoded).expect("decoded");

        assert_eq!(decoded.request_id, "req-resp-1");
        assert_eq!(decoded.origin, "https://dapp.example");
        assert!(decoded.error.is_none());
        assert_eq!(
            decoded
                .tx_create_response
                .expect("response payload")
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("ok")
        );
    }

    #[test]
    fn fragment_param_extraction_works_for_response() {
        let uri = "https://dapp.example/callback#wa_resp_v1=abc123&foo=bar";
        let extracted = extract_fragment_param(uri, WALLET_ABI_TRANSPORT_RESPONSE_PARAM)
            .expect("should extract param");
        assert_eq!(extracted, "abc123");
    }

    #[test]
    fn split_transfer_builder_creates_requested_output_count() {
        let request = build_split_transfer_request(SplitTransferRequestInput {
            request_id: "req-split",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            split_parts: 3,
            part_amount_sat: 1234,
            asset_id: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("split request should build");

        assert_eq!(request.params.outputs.len(), 3);
    }

    #[test]
    fn issue_asset_builder_creates_asset_and_token_outputs() {
        let request = build_issue_asset_request(IssueAssetRequestInput {
            request_id: "req-issue",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            issue_amount_sat: 5000,
            token_amount_sat: 1,
            issuance_entropy_hex: ENTROPY_HEX,
            funding_asset_id: None,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("issue request should build");

        assert_eq!(request.params.outputs.len(), 2);
    }

    #[test]
    fn reissue_asset_builder_creates_asset_and_token_change_outputs() {
        let request = build_reissue_asset_request(ReissueAssetRequestInput {
            request_id: "req-reissue",
            network: wallet_abi::Network::TestnetLiquid,
            to_address: TESTNET_ADDRESS,
            reissue_token_asset_id: REISSUE_TOKEN_ASSET_ID,
            reissue_amount_sat: 2000,
            asset_entropy_hex: ENTROPY_HEX,
            token_change_sat: 1,
            fee_rate_sat_vb: 0.1,
            broadcast: false,
        })
        .expect("reissue request should build");

        assert_eq!(request.params.outputs.len(), 2);
    }
}
