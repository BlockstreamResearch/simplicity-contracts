#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::similar_names
)]

use std::collections::HashMap;

use crate::common::filters::{
    AmountFilter, filter_signer_utxos_by_asset_and_amount, require_covenant_utxo,
};
use crate::common::issuance::issue_asset;
use crate::common::signer::{
    ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo, split_first_signer_utxo,
};
use crate::common::{locked_input, locktime_from, offset_timestamp};

use anyhow::Context;
use contracts::programs::options::{
    Options, OptionsBranch, OptionsFundingBlinders, OptionsParameters,
};
use contracts::programs::program::SimplexProgram;

use simplex::program::{ProgramTrait, WitnessTrait};
use simplex::signer::SignerTrait;
use simplex::simplicityhl::elements::secp256k1_zkp::Tweak;
use simplex::simplicityhl::elements::{
    AssetId, ContractHash, EcdsaSighashType, OutPoint, Script, TxOutSecrets, Txid,
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    pset::PartiallySignedTransaction,
    secp256k1_zkp::{Secp256k1, rand::thread_rng},
};
use simplex::simplicityhl::simplicity::hashes::Hash;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, UTXO,
};

const OPTION_ISSUANCE_CONTRACT_HASH: [u8; 32] = [1; 32];
const GRANTOR_ISSUANCE_CONTRACT_HASH: [u8; 32] = [2; 32];

/// Standard options contract sizing shared by the regtest scenarios.
pub const TOTAL_COLLATERAL_AMOUNT: u64 = 1_000;
pub const EXPECTED_SETTLEMENT_AMOUNT: u64 = 500;
pub const CONTRACT_COUNT: u64 = 10;

pub struct PreparedOptionsState {
    pub options: Options,
    pub option_issuance_entropy: [u8; 32],
    pub grantor_issuance_entropy: [u8; 32],
    pub option_issuance_source: UTXO,
    pub grantor_issuance_source: UTXO,
    pub creation_fee_source: UTXO,
}

pub struct CreatedOptionsState {
    pub options: Options,
    pub option_issuance_entropy: [u8; 32],
    pub grantor_issuance_entropy: [u8; 32],
    pub creation_txid: Txid,
    pub option_reissuance_token: UTXO,
    pub grantor_reissuance_token: UTXO,
}

pub struct FundedOptionsState {
    pub options: Options,
    pub option_issuance_entropy: [u8; 32],
    pub grantor_issuance_entropy: [u8; 32],
    pub funding_txid: Txid,
    pub option_reissuance_token: UTXO,
    pub grantor_reissuance_token: UTXO,
    pub locked_collateral: UTXO,
    pub option_token: UTXO,
    pub grantor_token: UTXO,
}

pub fn prepare_options(
    context: &simplex::TestContext,
    total_collateral_amount: u64,
    expected_settlement_amount: u64,
    contract_count: u64,
    start_delta_timestamp: i32,
    expiry_delta_timestamp: i32,
) -> anyhow::Result<PreparedOptionsState> {
    let network = context.get_network();
    let policy_asset = network.policy_asset();
    let tip_timestamp = context.get_default_provider().fetch_tip_timestamp()?;

    let start_time = offset_timestamp(tip_timestamp, start_delta_timestamp)?;
    let expiry_time = offset_timestamp(tip_timestamp, expiry_delta_timestamp)?;

    let _ = split_first_signer_utxo(context, vec![1_000, 1_000, 1_000, 1_000])
        .context("prepare_options split policy setup utxos")?;

    let (_, settlement_asset_id) = issue_asset(context, 5 * expected_settlement_amount)
        .context("prepare_options issue settlement asset")?;

    let signer = context.get_default_signer();
    let setup_policy_utxos =
        filter_signer_utxos_by_asset_and_amount(signer, policy_asset, 1_000, AmountFilter::EqualTo);
    let option_issuance_source = setup_policy_utxos
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing option issuance source utxo"))?;
    let grantor_issuance_source = setup_policy_utxos
        .iter()
        .find(|utxo| utxo.outpoint != option_issuance_source.outpoint)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing grantor issuance source utxo"))?;
    let creation_fee_source = setup_policy_utxos
        .iter()
        .find(|utxo| {
            utxo.outpoint != option_issuance_source.outpoint
                && utxo.outpoint != grantor_issuance_source.outpoint
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing creation fee source utxo"))?;

    let (option_token_asset, option_reissuance_token_asset, option_issuance_entropy) = issuance_ids(
        option_issuance_source.outpoint,
        OPTION_ISSUANCE_CONTRACT_HASH,
    );
    let (grantor_token_asset, grantor_reissuance_token_asset, grantor_issuance_entropy) =
        issuance_ids(
            grantor_issuance_source.outpoint,
            GRANTOR_ISSUANCE_CONTRACT_HASH,
        );

    let (collateral_per_contract, settlement_per_contract) = Options::calculate_per_contract_params(
        total_collateral_amount,
        expected_settlement_amount,
        contract_count,
    );

    let collateral_per_contract = collateral_per_contract
        .ok_or_else(|| anyhow::anyhow!("failed to derive collateral_per_contract"))?;
    let settlement_per_contract = settlement_per_contract
        .ok_or_else(|| anyhow::anyhow!("failed to derive settlement_per_contract"))?;

    if collateral_per_contract
        .checked_mul(contract_count)
        .ok_or_else(|| anyhow::anyhow!("collateral amount overflow"))?
        != total_collateral_amount
    {
        return Err(anyhow::anyhow!(
            "total collateral must be an exact multiple of contract_count"
        ));
    }

    if settlement_per_contract
        .checked_mul(contract_count)
        .ok_or_else(|| anyhow::anyhow!("settlement amount overflow"))?
        != expected_settlement_amount
    {
        return Err(anyhow::anyhow!(
            "expected settlement must be an exact multiple of contract_count"
        ));
    }

    Ok(PreparedOptionsState {
        options: Options::new(OptionsParameters {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id: policy_asset,
            settlement_asset_id,
            option_token_asset,
            option_reissuance_token_asset,
            grantor_token_asset,
            grantor_reissuance_token_asset,
            network: *network,
        }),
        option_issuance_entropy,
        grantor_issuance_entropy,
        option_issuance_source,
        grantor_issuance_source,
        creation_fee_source,
    })
}

pub fn create_options(
    context: &simplex::TestContext,
    prepared: PreparedOptionsState,
) -> anyhow::Result<CreatedOptionsState> {
    let signer = context.get_default_signer();
    let creation_fee = 500_u64;
    let creation_input_total = prepared.option_issuance_source.amount()
        + prepared.grantor_issuance_source.amount()
        + prepared.creation_fee_source.amount();
    let creation_change = creation_input_total
        .checked_sub(creation_fee)
        .ok_or_else(|| anyhow::anyhow!("creation inputs do not cover the fee"))?;

    let mut option_input = PartialInput::new(prepared.option_issuance_source.clone()).to_input();
    option_input.issuance_asset_entropy = Some(OPTION_ISSUANCE_CONTRACT_HASH);
    option_input.issuance_inflation_keys = Some(1);
    option_input.blinded_issuance = Some(0x00);

    let mut grantor_input = PartialInput::new(prepared.grantor_issuance_source.clone()).to_input();
    grantor_input.issuance_asset_entropy = Some(GRANTOR_ISSUANCE_CONTRACT_HASH);
    grantor_input.issuance_inflation_keys = Some(1);
    grantor_input.blinded_issuance = Some(0x00);

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.add_input(option_input);
    pst.add_input(grantor_input);
    pst.add_input(PartialInput::new(prepared.creation_fee_source.clone()).to_input());
    pst.add_output(
        PartialOutput::new(
            prepared.options.get_script_pubkey(),
            1,
            prepared.options.parameters.option_reissuance_token_asset,
        )
        .with_blinding_key(signer.get_blinding_public_key())
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            prepared.options.get_script_pubkey(),
            1,
            prepared.options.parameters.grantor_reissuance_token_asset,
        )
        .with_blinding_key(signer.get_blinding_public_key())
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            signer.get_address().script_pubkey(),
            creation_change,
            prepared.options.parameters.collateral_asset_id,
        )
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            Script::new(),
            creation_fee,
            prepared.options.parameters.collateral_asset_id,
        )
        .to_output(),
    );

    let input_secrets = HashMap::from([
        (
            0_usize,
            TxOutSecrets::new(
                prepared.option_issuance_source.asset(),
                AssetBlindingFactor::zero(),
                prepared.option_issuance_source.amount(),
                ValueBlindingFactor::zero(),
            ),
        ),
        (
            1_usize,
            TxOutSecrets::new(
                prepared.grantor_issuance_source.asset(),
                AssetBlindingFactor::zero(),
                prepared.grantor_issuance_source.amount(),
                ValueBlindingFactor::zero(),
            ),
        ),
        (
            2_usize,
            TxOutSecrets::new(
                prepared.creation_fee_source.asset(),
                AssetBlindingFactor::zero(),
                prepared.creation_fee_source.amount(),
                ValueBlindingFactor::zero(),
            ),
        ),
    ]);
    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &input_secrets)
        .context("create_options blind outputs")?;

    for input_index in 0..pst.inputs().len() {
        let (public_key, signature) = signer
            .sign_input(&pst, input_index)
            .context("create_options sign input")?;
        let mut raw_sig = signature.serialize_der().to_vec();
        raw_sig.push(EcdsaSighashType::All as u8);
        pst.inputs_mut()[input_index].final_script_witness =
            Some(vec![raw_sig, public_key.to_bytes()]);
    }

    let creation_tx = pst.extract_tx().context("create_options extract tx")?;
    let creation_txid = context
        .get_default_provider()
        .broadcast_transaction(&creation_tx)
        .context("create_options broadcast")?;

    let secp = Secp256k1::new();
    let blinding_key = signer.get_blinding_private_key();
    let option_reissuance_txout = creation_tx
        .output
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing option reissuance creation output"))?;
    let grantor_reissuance_txout = creation_tx
        .output
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing grantor reissuance creation output"))?;
    let option_reissuance_secrets = option_reissuance_txout
        .unblind(&secp, blinding_key.inner)
        .context("create_options unblind option reissuance output")?;
    let grantor_reissuance_secrets = grantor_reissuance_txout
        .unblind(&secp, blinding_key.inner)
        .context("create_options unblind grantor reissuance output")?;

    Ok(CreatedOptionsState {
        options: prepared.options,
        option_issuance_entropy: prepared.option_issuance_entropy,
        grantor_issuance_entropy: prepared.grantor_issuance_entropy,
        creation_txid: creation_txid.txid(),
        option_reissuance_token: UTXO {
            outpoint: OutPoint::new(creation_txid.txid(), 0),
            txout: option_reissuance_txout,
            secrets: Some(option_reissuance_secrets),
        },
        grantor_reissuance_token: UTXO {
            outpoint: OutPoint::new(creation_txid.txid(), 1),
            txout: grantor_reissuance_txout,
            secrets: Some(grantor_reissuance_secrets),
        },
    })
}

#[allow(clippy::too_many_lines)]
pub fn fund_options(
    context: &simplex::TestContext,
    created: CreatedOptionsState,
    collateral_amount: u64,
    contract_count: u64,
) -> anyhow::Result<FundedOptionsState> {
    let expected_settlement_amount = contract_count
        .checked_mul(created.options.parameters.settlement_per_contract)
        .ok_or_else(|| anyhow::anyhow!("settlement amount overflow"))?;
    let expected_collateral_amount = contract_count
        .checked_mul(created.options.parameters.collateral_per_contract)
        .ok_or_else(|| anyhow::anyhow!("collateral amount overflow"))?;

    if collateral_amount != expected_collateral_amount {
        return Err(anyhow::anyhow!(
            "collateral amount does not match collateral_per_contract * contract_count"
        ));
    }

    let option_input_secrets = created
        .option_reissuance_token
        .secrets
        .ok_or_else(|| anyhow::anyhow!("missing option reissuance input secrets"))?;
    let grantor_input_secrets = created
        .grantor_reissuance_token
        .secrets
        .ok_or_else(|| anyhow::anyhow!("missing grantor reissuance input secrets"))?;
    let option_input_abf = tweak_to_bytes(option_input_secrets.asset_bf.into_inner());
    let option_input_vbf = tweak_to_bytes(option_input_secrets.value_bf.into_inner());
    let grantor_input_abf = tweak_to_bytes(grantor_input_secrets.asset_bf.into_inner());
    let grantor_input_vbf = tweak_to_bytes(grantor_input_secrets.value_bf.into_inner());

    let signer = context.get_default_signer();
    let collateral_input = ensure_exact_signer_utxo(
        context,
        created.options.parameters.collateral_asset_id,
        collateral_amount,
    )?;
    let fee_input = signer
        .get_utxos_asset(created.options.parameters.collateral_asset_id)
        .context("fund_options fetch fee utxos")?
        .into_iter()
        .find(|utxo| utxo.outpoint != collateral_input.outpoint)
        .ok_or_else(|| anyhow::anyhow!("missing funding fee input"))?;
    let funding_fee = 500_u64;
    let funding_change = fee_input
        .amount()
        .checked_sub(funding_fee)
        .ok_or_else(|| anyhow::anyhow!("funding fee input does not cover the fee"))?;

    let mut option_input = PartialInput::new(created.option_reissuance_token.clone()).to_input();
    let option_issuance =
        IssuanceInput::new_reissuance(contract_count, created.option_issuance_entropy).to_input();
    option_input.issuance_blinding_nonce = Some(Tweak::from_inner(option_input_abf)?);
    option_input.issuance_value_amount = option_issuance.issuance_value_amount;
    option_input.issuance_asset_entropy = option_issuance.issuance_asset_entropy;
    option_input.blinded_issuance = option_issuance.blinded_issuance;

    let mut grantor_input = PartialInput::new(created.grantor_reissuance_token.clone()).to_input();
    let grantor_issuance =
        IssuanceInput::new_reissuance(contract_count, created.grantor_issuance_entropy).to_input();
    grantor_input.issuance_blinding_nonce = Some(Tweak::from_inner(grantor_input_abf)?);
    grantor_input.issuance_value_amount = grantor_issuance.issuance_value_amount;
    grantor_input.issuance_asset_entropy = grantor_issuance.issuance_asset_entropy;
    grantor_input.blinded_issuance = grantor_issuance.blinded_issuance;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.add_input(option_input);
    pst.add_input(grantor_input);
    pst.add_input(PartialInput::new(collateral_input.clone()).to_input());
    pst.add_input(PartialInput::new(fee_input.clone()).to_input());
    pst.add_output(
        PartialOutput::new(
            created.options.get_script_pubkey(),
            1,
            created.options.parameters.option_reissuance_token_asset,
        )
        .with_blinding_key(signer.get_blinding_public_key())
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            created.options.get_script_pubkey(),
            1,
            created.options.parameters.grantor_reissuance_token_asset,
        )
        .with_blinding_key(signer.get_blinding_public_key())
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            created.options.get_script_pubkey(),
            collateral_amount,
            created.options.parameters.collateral_asset_id,
        )
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            signer_script(context),
            contract_count,
            created.options.parameters.option_token_asset,
        )
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            signer_script(context),
            contract_count,
            created.options.parameters.grantor_token_asset,
        )
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            signer_script(context),
            funding_change,
            created.options.parameters.collateral_asset_id,
        )
        .to_output(),
    );
    pst.add_output(
        PartialOutput::new(
            Script::new(),
            funding_fee,
            created.options.parameters.collateral_asset_id,
        )
        .to_output(),
    );

    let input_secrets = HashMap::from([
        (0_usize, option_input_secrets),
        (1_usize, grantor_input_secrets),
        (2_usize, explicit_txout_secrets(&collateral_input)),
        (3_usize, explicit_txout_secrets(&fee_input)),
    ]);
    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &input_secrets)
        .context("fund_options blind outputs")?;

    let blinded_tx = pst
        .extract_tx()
        .context("fund_options extract blinded tx")?;
    let blinding_key = signer.get_blinding_private_key();
    let secp = Secp256k1::new();
    let option_output_secrets = blinded_tx.output[0]
        .unblind(&secp, blinding_key.inner)
        .context("fund_options unblind option reissuance output")?;
    let grantor_output_secrets = blinded_tx.output[1]
        .unblind(&secp, blinding_key.inner)
        .context("fund_options unblind grantor reissuance output")?;
    let funding_witness = Options::get_witness(OptionsBranch::Fund {
        expected_settlement_amount,
        blinders: OptionsFundingBlinders {
            input_option_abf: option_input_abf,
            input_option_vbf: option_input_vbf,
            input_grantor_abf: grantor_input_abf,
            input_grantor_vbf: grantor_input_vbf,
            output_option_abf: tweak_to_bytes(option_output_secrets.asset_bf.into_inner()),
            output_option_vbf: tweak_to_bytes(option_output_secrets.value_bf.into_inner()),
            output_grantor_abf: tweak_to_bytes(grantor_output_secrets.asset_bf.into_inner()),
            output_grantor_vbf: tweak_to_bytes(grantor_output_secrets.value_bf.into_inner()),
        },
    })
    .build_witness();

    let program = created.options.get_program().clone();
    pst.inputs_mut()[0].final_script_witness = Some(
        program
            .finalize(&pst, &funding_witness, 0, context.get_network())
            .context("fund_options finalize option reissuance input")?,
    );
    pst.inputs_mut()[1].final_script_witness = Some(
        program
            .finalize(&pst, &funding_witness, 1, context.get_network())
            .context("fund_options finalize grantor reissuance input")?,
    );

    for input_index in [2_usize, 3_usize] {
        let (public_key, signature) = signer
            .sign_input(&pst, input_index)
            .context("fund_options sign input")?;
        let mut raw_sig = signature.serialize_der().to_vec();
        raw_sig.push(EcdsaSighashType::All as u8);
        pst.inputs_mut()[input_index].final_script_witness =
            Some(vec![raw_sig, public_key.to_bytes()]);
    }

    let funding_tx = pst.extract_tx().context("fund_options extract final tx")?;
    let funding_txid = context
        .get_default_provider()
        .broadcast_transaction(&funding_tx)
        .context("fund_options broadcast")?;

    Ok(FundedOptionsState {
        options: created.options,
        option_issuance_entropy: created.option_issuance_entropy,
        grantor_issuance_entropy: created.grantor_issuance_entropy,
        funding_txid: funding_txid.txid(),
        option_reissuance_token: UTXO {
            outpoint: OutPoint::new(funding_txid.txid(), 0),
            txout: funding_tx.output[0].clone(),
            secrets: Some(option_output_secrets),
        },
        grantor_reissuance_token: UTXO {
            outpoint: OutPoint::new(funding_txid.txid(), 1),
            txout: funding_tx.output[1].clone(),
            secrets: Some(grantor_output_secrets),
        },
        locked_collateral: UTXO {
            outpoint: OutPoint::new(funding_txid.txid(), 2),
            txout: funding_tx.output[2].clone(),
            secrets: None,
        },
        option_token: UTXO {
            outpoint: OutPoint::new(funding_txid.txid(), 3),
            txout: funding_tx.output[3].clone(),
            secrets: None,
        },
        grantor_token: UTXO {
            outpoint: OutPoint::new(funding_txid.txid(), 4),
            txout: funding_tx.output[4].clone(),
            secrets: None,
        },
    })
}

/// Prepare, create, and fund an options contract with the standard sizing
/// ([`TOTAL_COLLATERAL_AMOUNT`], [`EXPECTED_SETTLEMENT_AMOUNT`],
/// [`CONTRACT_COUNT`]).
pub fn setup_funded_options(
    context: &simplex::TestContext,
    start_delta_timestamp: i32,
    expiry_delta_timestamp: i32,
) -> anyhow::Result<FundedOptionsState> {
    let prepared = prepare_options(
        context,
        TOTAL_COLLATERAL_AMOUNT,
        EXPECTED_SETTLEMENT_AMOUNT,
        CONTRACT_COUNT,
        start_delta_timestamp,
        expiry_delta_timestamp,
    )?;
    let created = create_options(context, prepared)?;
    fund_options(context, created, TOTAL_COLLATERAL_AMOUNT, CONTRACT_COUNT)
}

/// Build a covenant input spending `utxo` on the given options branch.
#[must_use]
pub fn options_program_input(options: &Options, branch: OptionsBranch) -> ProgramInput {
    ProgramInput::new(
        Box::new(options.get_program().clone()),
        Box::new(Options::get_witness(branch)),
    )
}

/// Fetch the covenant UTXO holding the full locked collateral.
pub fn require_locked_collateral(
    context: &simplex::TestContext,
    funded: &FundedOptionsState,
) -> anyhow::Result<UTXO> {
    require_covenant_utxo(
        context,
        &funded.options.get_script_pubkey(),
        funded.options.parameters.collateral_asset_id,
        TOTAL_COLLATERAL_AMOUNT,
        "missing locked collateral covenant utxo",
    )
}

/// Exercise the full collateral of a contract funded via
/// [`setup_funded_options`].
///
/// Burns all option tokens, locks the expected settlement amount in the
/// covenant, and pays the collateral to the default signer.
pub fn exercise_options_fully(
    context: &simplex::TestContext,
    funded: &FundedOptionsState,
) -> anyhow::Result<Txid> {
    let parameters = &funded.options.parameters;
    let option_token_input =
        ensure_exact_signer_utxo(context, parameters.option_token_asset, CONTRACT_COUNT)?;
    let settlement_input = ensure_exact_signer_utxo(
        context,
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;
    let locktime = locktime_from(parameters.start_time)?;
    let locked_collateral = require_locked_collateral(context, funded)?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        locked_input(locked_collateral, locktime),
        options_program_input(
            &funded.options,
            OptionsBranch::Exercise {
                is_change_needed: false,
                amount_to_burn: CONTRACT_COUNT,
                collateral_amount: TOTAL_COLLATERAL_AMOUNT,
                settlement_amount: EXPECTED_SETTLEMENT_AMOUNT,
            },
        ),
        RequiredSignature::None,
    );
    for input in [
        option_token_input,
        settlement_input,
        get_lbtc_utxo(context)?,
    ] {
        ft.add_input(
            locked_input(input, locktime),
            RequiredSignature::NativeEcdsa,
        );
    }
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        CONTRACT_COUNT,
        parameters.option_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        funded.options.get_script_pubkey(),
        EXPECTED_SETTLEMENT_AMOUNT,
        parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        signer_script(context),
        TOTAL_COLLATERAL_AMOUNT,
        parameters.collateral_asset_id,
    ));

    finalize_and_broadcast(context, &ft)
}

fn issuance_ids(
    issuance_outpoint: OutPoint,
    contract_hash_bytes: [u8; 32],
) -> (AssetId, AssetId, [u8; 32]) {
    let issuance_entropy = AssetId::generate_asset_entropy(
        issuance_outpoint,
        ContractHash::from_byte_array(contract_hash_bytes),
    );

    (
        AssetId::from_entropy(issuance_entropy),
        AssetId::reissuance_token_from_entropy(issuance_entropy, false),
        issuance_entropy.to_byte_array(),
    )
}

fn signer_script(context: &simplex::TestContext) -> Script {
    context.get_default_signer().get_address().script_pubkey()
}

fn tweak_to_bytes(tweak: Tweak) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(tweak.as_ref());
    bytes
}

fn explicit_txout_secrets(utxo: &UTXO) -> TxOutSecrets {
    TxOutSecrets::new(
        utxo.asset(),
        AssetBlindingFactor::zero(),
        utxo.amount(),
        ValueBlindingFactor::zero(),
    )
}
