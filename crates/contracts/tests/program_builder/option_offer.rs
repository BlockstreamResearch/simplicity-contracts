#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use crate::common::filters::{
    AmountFilter, filter_signer_utxos_by_asset_and_amount, require_covenant_utxo,
};
use crate::common::issuance::issue_asset;
use crate::common::offset_timestamp;
use crate::common::signer::{
    ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo, split_first_signer_utxo,
};

use std::collections::HashMap;

use simplex::program::WitnessTrait;
use simplex::signer::SignerTrait;
use simplex::simplicityhl::elements::Txid;
use simplex::simplicityhl::elements::pset::PartiallySignedTransaction;
use simplex::simplicityhl::str::WitnessName;
use simplex::simplicityhl::value::ValueConstructible;
use simplex::simplicityhl::{Value, WitnessValues};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, UTXO,
};

use contracts::programs::option_offer::{OptionOffer, OptionOfferBranch, OptionOfferParameters};
use contracts::programs::program::SimplexProgram;

/// Standard offer sizing shared by the regtest scenarios.
pub const DEPOSIT_LBTC_AMOUNT: u64 = 1_000;
pub const EXPECTED_PREMIUM_AMOUNT: u64 = 10_000;
pub const EXPECTED_SETTLEMENT_AMOUNT: u64 = 10_000;

/// Standard partial exercise of the offer: 600 of 1000 collateral for 6000
/// settlement, with 6000 premium released and change locked back.
pub const PARTIAL_COLLATERAL_AMOUNT: u64 = 600;
pub const REMAINING_COLLATERAL_AMOUNT: u64 = DEPOSIT_LBTC_AMOUNT - PARTIAL_COLLATERAL_AMOUNT;
pub const EXERCISED_PREMIUM_AMOUNT: u64 = 6_000;
pub const REMAINING_PREMIUM_AMOUNT: u64 = EXPECTED_PREMIUM_AMOUNT - EXERCISED_PREMIUM_AMOUNT;
pub const EXERCISED_SETTLEMENT_AMOUNT: u64 = 6_000;

pub fn prepare_option_offer(
    context: &simplex::TestContext,
    deposit_lbtc_amount: u64,
    expected_premium_amount: u64,
    expected_settlement_amount: u64,
    delta_timestamp: i32,
) -> anyhow::Result<OptionOffer> {
    let _ = split_first_signer_utxo(context, vec![1_000])?;

    build_option_offer_program(
        context,
        deposit_lbtc_amount,
        expected_premium_amount,
        expected_settlement_amount,
        delta_timestamp,
    )
}

pub fn build_option_offer_program(
    context: &simplex::TestContext,
    deposit_lbtc_amount: u64,
    expected_premium_amount: u64,
    expected_settlement_amount: u64,
    delta_timestamp: i32,
) -> anyhow::Result<OptionOffer> {
    let signer = context.get_default_signer();
    let network = context.get_network();
    let tip_timestamp = context.get_default_provider().fetch_tip_timestamp()?;
    let expiry_time = offset_timestamp(tip_timestamp, delta_timestamp)?;

    let (_, premium_asset_id) = issue_asset(context, 5 * expected_premium_amount)?;
    let (_, settlement_asset_id) = issue_asset(context, 5 * expected_settlement_amount)?;

    let (collateral_per_contract, premium_per_collateral) = OptionOffer::calculate_per_params(
        deposit_lbtc_amount,
        expected_settlement_amount,
        expected_premium_amount,
    );

    Ok(OptionOffer::new(OptionOfferParameters {
        collateral_asset_id: network.policy_asset(),
        premium_asset_id,
        settlement_asset_id,
        collateral_per_contract: collateral_per_contract
            .ok_or_else(|| anyhow::anyhow!("failed to derive collateral_per_contract"))?,
        premium_per_collateral: premium_per_collateral
            .ok_or_else(|| anyhow::anyhow!("failed to derive premium_per_collateral"))?,
        expiry_time,
        user_pubkey: signer.get_schnorr_public_key(),
        network: *network,
    }))
}

pub fn create_option_offer_with_premium(
    context: &simplex::TestContext,
    option_offer: &OptionOffer,
    collateral_amount: u64,
    premium_amount: u64,
) -> anyhow::Result<Txid> {
    let collateral_input = get_lbtc_utxo(context)?;
    let premium_input = ensure_exact_signer_utxo(
        context,
        option_offer.parameters.premium_asset_id,
        premium_amount,
    )?;

    let mut ft = FinalTransaction::new();
    ft.add_input(
        PartialInput::new(collateral_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_input(
        PartialInput::new(premium_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    finalize_and_broadcast(context, &ft)
}

/// Prepare an offer with the standard sizing ([`DEPOSIT_LBTC_AMOUNT`],
/// [`EXPECTED_PREMIUM_AMOUNT`], [`EXPECTED_SETTLEMENT_AMOUNT`]) and lock the
/// collateral and premium in the covenant.
pub fn setup_offer_with_premium(
    context: &simplex::TestContext,
    delta_timestamp: i32,
) -> anyhow::Result<OptionOffer> {
    let option_offer = prepare_option_offer(
        context,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
        EXPECTED_SETTLEMENT_AMOUNT,
        delta_timestamp,
    )?;

    create_option_offer_with_premium(
        context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    Ok(option_offer)
}

pub fn deposit_to_option_offer(
    context: &simplex::TestContext,
    deposit_lbtc_amount: u64,
    expected_premium_amount: u64,
    expected_settlement_amount: u64,
    delta_timestamp: i32,
) -> anyhow::Result<(OptionOffer, Txid)> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();
    let policy_asset = context.get_network().policy_asset();

    let option_offer = prepare_option_offer(
        context,
        deposit_lbtc_amount,
        expected_premium_amount,
        expected_settlement_amount,
        delta_timestamp,
    )?;

    let mut ft = FinalTransaction::new();

    let signer_utxos = filter_signer_utxos_by_asset_and_amount(
        signer,
        policy_asset,
        deposit_lbtc_amount,
        AmountFilter::GreaterThan,
    );
    let first_utxo = signer_utxos.first().ok_or_else(|| {
        anyhow::anyhow!("Signer does not have a policy UTXO large enough to deposit and pay fees")
    })?;

    ft.add_input(
        PartialInput::new(first_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        deposit_lbtc_amount,
        policy_asset,
    ));

    let txid = finalize_and_broadcast(context, &ft)?;
    provider.wait(&txid)?;

    Ok((option_offer, txid))
}

/// Build a covenant input spending `utxo` on the given offer branch.
#[must_use]
pub fn offer_program_input(option_offer: &OptionOffer, branch: OptionOfferBranch) -> ProgramInput {
    ProgramInput::new(
        Box::new(option_offer.get_program().clone()),
        Box::new(OptionOffer::get_witness(branch)),
    )
}

/// Fetch the covenant UTXOs holding the offered collateral and premium.
pub fn require_offer_utxos(
    context: &simplex::TestContext,
    option_offer: &OptionOffer,
    collateral_amount: u64,
    premium_amount: u64,
) -> anyhow::Result<[UTXO; 2]> {
    let script_pubkey = option_offer.get_script_pubkey();
    let collateral = require_covenant_utxo(
        context,
        &script_pubkey,
        option_offer.parameters.collateral_asset_id,
        collateral_amount,
        "missing collateral covenant utxo",
    )?;
    let premium = require_covenant_utxo(
        context,
        &script_pubkey,
        option_offer.parameters.premium_asset_id,
        premium_amount,
        "missing premium covenant utxo",
    )?;
    Ok([collateral, premium])
}

/// Partially exercise an offer created via [`setup_offer_with_premium`]
/// using the standard partial amounts, leaving settlement, remaining
/// collateral, and remaining premium locked in the covenant.
pub fn exercise_offer_partially(
    context: &simplex::TestContext,
    option_offer: &OptionOffer,
) -> anyhow::Result<Txid> {
    let receiver_script_pubkey = context.get_default_signer().get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        context,
        option_offer.parameters.settlement_asset_id,
        EXERCISED_SETTLEMENT_AMOUNT,
    )?;

    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: PARTIAL_COLLATERAL_AMOUNT,
        is_change_needed: true,
    };
    let offer_utxos = require_offer_utxos(
        context,
        option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    let mut ft = FinalTransaction::new();
    for utxo in offer_utxos {
        ft.add_program_input(
            PartialInput::new(utxo),
            offer_program_input(option_offer, exercise_branch),
            RequiredSignature::None,
        );
    }
    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        REMAINING_COLLATERAL_AMOUNT,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        REMAINING_PREMIUM_AMOUNT,
        option_offer.parameters.premium_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        EXERCISED_SETTLEMENT_AMOUNT,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        PARTIAL_COLLATERAL_AMOUNT,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        EXERCISED_PREMIUM_AMOUNT,
        option_offer.parameters.premium_asset_id,
    ));

    finalize_and_broadcast(context, &ft)
}

/// Build the witness for an offer branch with the user's `SIGHASH_ALL`
/// signature filled in.
pub fn witness_with_user_sighash(
    context: &simplex::TestContext,
    option_offer: &OptionOffer,
    branch: OptionOfferBranch,
    pst: &PartiallySignedTransaction,
) -> anyhow::Result<WitnessValues> {
    let signature = context.get_default_signer().sign_program(
        pst,
        option_offer.get_program(),
        0,
        context.get_network(),
    )?;

    let mut signed_witness = HashMap::new();
    for (name, value) in OptionOffer::get_witness(branch).build_witness().iter() {
        signed_witness.insert(name.clone(), value.clone());
    }
    signed_witness.insert(
        WitnessName::from_str_unchecked("USER_SIGHASH_ALL"),
        Value::byte_array(signature.serialize()),
    );

    Ok(WitnessValues::from(signed_witness))
}
