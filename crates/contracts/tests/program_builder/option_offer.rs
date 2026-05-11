#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use crate::common::filters::{AmountFilter, filter_signer_utxos_by_asset_and_amount};
use crate::common::issuance::issue_asset;
use crate::common::signer::{
    ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo, split_first_signer_utxo,
};

use simplex::simplicityhl::elements::Txid;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::programs::option_offer::{OptionOffer, OptionOfferParameters};
use contracts::programs::program::SimplexProgram;

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
    let policy_asset = network.policy_asset();
    let tip_timestamp = context.get_default_provider().fetch_tip_timestamp()?;

    let expiry_time = if delta_timestamp < 0 {
        u32::try_from(tip_timestamp)
            .map_err(|_| anyhow::anyhow!("tip timestamp {tip_timestamp} exceeds u32 range"))?
            .checked_sub(delta_timestamp.unsigned_abs())
            .ok_or_else(|| anyhow::anyhow!("expiry timestamp overflow"))?
    } else {
        u32::try_from(tip_timestamp)
            .map_err(|_| anyhow::anyhow!("tip timestamp {tip_timestamp} exceeds u32 range"))?
            .checked_add(delta_timestamp.unsigned_abs())
            .ok_or_else(|| anyhow::anyhow!("expiry timestamp overflow"))?
    };

    let (_, premium_asset_id) = issue_asset(context, 5 * expected_premium_amount)?;

    let (_, settlement_asset_id) = issue_asset(context, 5 * expected_settlement_amount)?;

    let (collateral_per_contract, premium_per_collateral) = OptionOffer::calculate_per_params(
        deposit_lbtc_amount,
        expected_settlement_amount,
        expected_premium_amount,
    );

    let option_offer_params: OptionOfferParameters = OptionOfferParameters {
        collateral_asset_id: policy_asset,
        premium_asset_id,
        settlement_asset_id,
        collateral_per_contract: collateral_per_contract.unwrap(),
        premium_per_collateral: premium_per_collateral.unwrap(),
        expiry_time,
        user_pubkey: signer.get_schnorr_public_key(),
        network: *network,
    };

    Ok(OptionOffer::new(option_offer_params))
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

    let txid = finalize_and_broadcast(context, &ft)?;

    Ok(txid)
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
    let network = context.get_network();
    let policy_asset = network.policy_asset();

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
