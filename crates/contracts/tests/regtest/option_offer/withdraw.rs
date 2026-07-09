use crate::common::filters::{
    assert_covenant_utxo, assert_has_utxo_by_asset_amount_and_script, require_covenant_utxo,
};
use crate::common::signer::{finalize_and_broadcast, get_lbtc_utxo};
use crate::program_builder::option_offer::{
    DEPOSIT_LBTC_AMOUNT, EXERCISED_SETTLEMENT_AMOUNT, EXPECTED_PREMIUM_AMOUNT,
    EXPECTED_SETTLEMENT_AMOUNT, REMAINING_COLLATERAL_AMOUNT, REMAINING_PREMIUM_AMOUNT,
    create_option_offer_with_premium, exercise_offer_partially, offer_program_input,
    prepare_option_offer, setup_offer_with_premium, witness_with_user_sighash,
};

use simplex::program::{ProgramError, ProgramTrait};
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::programs::option_offer::{OptionOffer, OptionOfferBranch};
use contracts::programs::program::SimplexProgram;

/// Build a withdraw transaction spending the settlement covenant UTXO left by
/// [`exercise_offer_partially`] into the given outputs.
fn build_withdraw_ft(
    context: &simplex::TestContext,
    option_offer: &OptionOffer,
    outputs: Vec<PartialOutput>,
) -> anyhow::Result<FinalTransaction> {
    let settlement_program_utxo = require_covenant_utxo(
        context,
        &option_offer.get_script_pubkey(),
        option_offer.parameters.settlement_asset_id,
        EXERCISED_SETTLEMENT_AMOUNT,
        "missing settlement covenant utxo",
    )?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(settlement_program_utxo),
        offer_program_input(option_offer, OptionOfferBranch::Withdraw),
        RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
    );
    ft.add_input(
        PartialInput::new(get_lbtc_utxo(context)?),
        RequiredSignature::NativeEcdsa,
    );
    for output in outputs {
        ft.add_output(output);
    }

    Ok(ft)
}

fn assert_covenant_untouched_after_rejection(
    context: &simplex::TestContext,
    option_offer: &OptionOffer,
) -> anyhow::Result<()> {
    let script_pubkey = option_offer.get_script_pubkey();
    assert_covenant_utxo(
        context,
        &script_pubkey,
        option_offer.parameters.collateral_asset_id,
        REMAINING_COLLATERAL_AMOUNT,
    )?;
    assert_covenant_utxo(
        context,
        &script_pubkey,
        option_offer.parameters.premium_asset_id,
        REMAINING_PREMIUM_AMOUNT,
    )?;
    assert_covenant_utxo(
        context,
        &script_pubkey,
        option_offer.parameters.settlement_asset_id,
        EXERCISED_SETTLEMENT_AMOUNT,
    )?;
    Ok(())
}

#[simplex::test]
fn withdraw_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, 1_000)?;
    let _ = exercise_offer_partially(&context, &option_offer)?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let withdraw_ft = build_withdraw_ft(
        &context,
        &option_offer,
        vec![PartialOutput::new(
            receiver_script_pubkey.clone(),
            EXERCISED_SETTLEMENT_AMOUNT,
            option_offer.parameters.settlement_asset_id,
        )],
    )?;

    let withdraw_txid = finalize_and_broadcast(&context, &withdraw_ft)?;

    let script_pubkey = option_offer.get_script_pubkey();
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.collateral_asset_id,
        REMAINING_COLLATERAL_AMOUNT,
    )?;
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.premium_asset_id,
        REMAINING_PREMIUM_AMOUNT,
    )?;

    let signer_utxos = signer.get_utxos_txid(withdraw_txid)?;
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.settlement_asset_id,
        EXERCISED_SETTLEMENT_AMOUNT,
        &receiver_script_pubkey,
    );

    Ok(())
}

#[simplex::test]
fn withdraw_option_offer_rejects_invalid_signature(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    // Lock the offer to a pubkey that does not belong to the default signer.
    let prepared_option_offer = prepare_option_offer(
        &context,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
        EXPECTED_SETTLEMENT_AMOUNT,
        1_000,
    )?;
    let mismatched_user_signer = context.create_signer(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    let mut option_offer_parameters = prepared_option_offer.parameters;
    option_offer_parameters.user_pubkey = mismatched_user_signer.get_schnorr_public_key();
    let option_offer = OptionOffer::new(option_offer_parameters);

    create_option_offer_with_premium(
        &context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;
    let _ = exercise_offer_partially(&context, &option_offer)?;

    let withdraw_ft = build_withdraw_ft(
        &context,
        &option_offer,
        vec![PartialOutput::new(
            signer.get_address().script_pubkey(),
            EXERCISED_SETTLEMENT_AMOUNT,
            option_offer.parameters.settlement_asset_id,
        )],
    )?;

    let (pst, _) = withdraw_ft.extract_pst();
    let witness =
        witness_with_user_sighash(&context, &option_offer, OptionOfferBranch::Withdraw, &pst)?;
    let program_error = option_offer
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("withdraw should reject a mismatched user signature");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_untouched_after_rejection(&context, &option_offer)?;

    Ok(())
}

#[simplex::test]
fn withdraw_option_offer_rejects_partial_output_amount(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, 1_000)?;
    let _ = exercise_offer_partially(&context, &option_offer)?;

    // Split the settlement across two outputs; the covenant requires the full
    // amount at output index 0.
    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let withdraw_ft = build_withdraw_ft(
        &context,
        &option_offer,
        vec![
            PartialOutput::new(
                receiver_script_pubkey.clone(),
                EXERCISED_SETTLEMENT_AMOUNT - 1,
                option_offer.parameters.settlement_asset_id,
            ),
            PartialOutput::new(
                receiver_script_pubkey,
                1,
                option_offer.parameters.settlement_asset_id,
            ),
        ],
    )?;

    let (pst, _) = withdraw_ft.extract_pst();
    let witness =
        witness_with_user_sighash(&context, &option_offer, OptionOfferBranch::Withdraw, &pst)?;
    let program_error = option_offer
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("withdraw should reject a partial settlement output at index 0");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_untouched_after_rejection(&context, &option_offer)?;

    Ok(())
}
