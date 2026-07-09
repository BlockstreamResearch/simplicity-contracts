use crate::common::filters::{assert_covenant_utxo, assert_has_utxo_by_asset_amount_and_script};
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast};
use crate::program_builder::option_offer::{
    DEPOSIT_LBTC_AMOUNT, EXERCISED_PREMIUM_AMOUNT, EXERCISED_SETTLEMENT_AMOUNT,
    EXPECTED_PREMIUM_AMOUNT, EXPECTED_SETTLEMENT_AMOUNT, PARTIAL_COLLATERAL_AMOUNT,
    REMAINING_COLLATERAL_AMOUNT, REMAINING_PREMIUM_AMOUNT, exercise_offer_partially,
    offer_program_input, require_offer_utxos, setup_offer_with_premium,
};

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::programs::option_offer::{OptionOffer, OptionOfferBranch};
use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn exercise_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, 1_000)?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        option_offer.parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;

    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: DEPOSIT_LBTC_AMOUNT,
        is_change_needed: false,
    };
    let offer_utxos = require_offer_utxos(
        &context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    let mut ft = FinalTransaction::new();
    for utxo in offer_utxos {
        ft.add_program_input(
            PartialInput::new(utxo),
            offer_program_input(&option_offer, exercise_branch),
            RequiredSignature::None,
        );
    }
    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        EXPECTED_SETTLEMENT_AMOUNT,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        DEPOSIT_LBTC_AMOUNT,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        EXPECTED_PREMIUM_AMOUNT,
        option_offer.parameters.premium_asset_id,
    ));

    let exercise_txid = finalize_and_broadcast(&context, &ft)?;

    assert_covenant_utxo(
        &context,
        &option_offer.get_script_pubkey(),
        option_offer.parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;

    let signer_utxos = signer.get_utxos_txid(exercise_txid)?;
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.collateral_asset_id,
        DEPOSIT_LBTC_AMOUNT,
        &receiver_script_pubkey,
    );
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.premium_asset_id,
        EXPECTED_PREMIUM_AMOUNT,
        &receiver_script_pubkey,
    );

    Ok(())
}

#[simplex::test]
fn exercise_option_offer_with_change(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, 0)?;
    let exercise_txid = exercise_offer_partially(&context, &option_offer)?;

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
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.settlement_asset_id,
        EXERCISED_SETTLEMENT_AMOUNT,
    )?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let signer_utxos = signer.get_utxos_txid(exercise_txid)?;
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.collateral_asset_id,
        PARTIAL_COLLATERAL_AMOUNT,
        &receiver_script_pubkey,
    );
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.premium_asset_id,
        EXERCISED_PREMIUM_AMOUNT,
        &receiver_script_pubkey,
    );

    Ok(())
}

#[simplex::test]
fn exercise_option_offer_rejects_wrong_settlement_amount(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, 1_000)?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        option_offer.parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;

    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: DEPOSIT_LBTC_AMOUNT,
        is_change_needed: false,
    };
    let offer_utxos = require_offer_utxos(
        &context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    let mut ft = FinalTransaction::new();
    for utxo in offer_utxos {
        ft.add_program_input(
            PartialInput::new(utxo),
            offer_program_input(&option_offer, exercise_branch),
            RequiredSignature::None,
        );
    }
    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        EXPECTED_SETTLEMENT_AMOUNT - 1,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        DEPOSIT_LBTC_AMOUNT,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        EXPECTED_PREMIUM_AMOUNT,
        option_offer.parameters.premium_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        1,
        option_offer.parameters.settlement_asset_id,
    ));

    let (pst, _) = ft.extract_pst();
    let witness = OptionOffer::get_witness(exercise_branch).build_witness();
    let program_error = option_offer
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("exercise should reject short settlement");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_utxo(
        &context,
        &option_offer.get_script_pubkey(),
        option_offer.parameters.collateral_asset_id,
        DEPOSIT_LBTC_AMOUNT,
    )?;
    assert_covenant_utxo(
        &context,
        &option_offer.get_script_pubkey(),
        option_offer.parameters.premium_asset_id,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    Ok(())
}

#[simplex::test]
fn exercise_option_offer_rejects_partial_exercise_without_change_flag(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, 1_000)?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        option_offer.parameters.settlement_asset_id,
        EXERCISED_SETTLEMENT_AMOUNT,
    )?;

    // Partial exercise, but the change flag is not set.
    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: PARTIAL_COLLATERAL_AMOUNT,
        is_change_needed: false,
    };
    let offer_utxos = require_offer_utxos(
        &context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    let mut ft = FinalTransaction::new();
    for utxo in offer_utxos {
        ft.add_program_input(
            PartialInput::new(utxo),
            offer_program_input(&option_offer, exercise_branch),
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

    let (pst, _) = ft.extract_pst();
    let witness = OptionOffer::get_witness(exercise_branch).build_witness();
    let program_error = option_offer
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("exercise should reject missing change flag");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_utxo(
        &context,
        &option_offer.get_script_pubkey(),
        option_offer.parameters.collateral_asset_id,
        DEPOSIT_LBTC_AMOUNT,
    )?;
    assert_covenant_utxo(
        &context,
        &option_offer.get_script_pubkey(),
        option_offer.parameters.premium_asset_id,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    Ok(())
}
