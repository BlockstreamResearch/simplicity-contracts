use crate::common::filters::{
    assert_has_utxo_by_asset_amount_and_script, assert_has_utxo_by_asset_and_amount,
    require_utxo_by_asset_and_amount,
};
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo};
use crate::program_builder::option_offer::{
    create_option_offer_with_premium, prepare_option_offer,
};

use std::collections::HashMap;

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::signer::SignerTrait;
use simplex::simplicityhl::str::WitnessName;
use simplex::simplicityhl::value::ValueConstructible;
use simplex::simplicityhl::{Value, WitnessValues};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::programs::option_offer::{OptionOffer, OptionOfferBranch};
use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn withdraw_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let deposit_lbtc_amount = 1_000_u64;
    let expected_premium_amount = 10_000_u64;
    let expected_settlement_amount = 10_000_u64;
    let partial_collateral_amount = 600_u64;
    let remaining_collateral_amount = deposit_lbtc_amount - partial_collateral_amount;
    let exercised_premium_amount = 6_000_u64;
    let remaining_premium_amount = expected_premium_amount - exercised_premium_amount;
    let exercised_settlement_amount = 6_000_u64;

    let option_offer = prepare_option_offer(
        &context,
        deposit_lbtc_amount,
        expected_premium_amount,
        expected_settlement_amount,
        1_000,
    )?;

    create_option_offer_with_premium(
        &context,
        &option_offer,
        deposit_lbtc_amount,
        expected_premium_amount,
    )?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: partial_collateral_amount,
        is_change_needed: true,
    };
    let collateral_program_utxo = require_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
        "missing collateral covenant utxo",
    )?;
    let premium_program_utxo = require_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
        "missing premium covenant utxo",
    )?;

    let mut exercise_ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        exercise_ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    exercise_ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        partial_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        exercised_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    let _ = finalize_and_broadcast(&context, &exercise_ft)?;

    let exercised_program_utxos =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let settlement_program_utxo = require_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
        "missing settlement covenant utxo",
    )?;

    let mut withdraw_ft = FinalTransaction::new();
    withdraw_ft.add_program_input(
        PartialInput::new(settlement_program_utxo),
        ProgramInput::new(
            Box::new(option_offer.get_program().clone()),
            Box::new(OptionOffer::get_witness(OptionOfferBranch::Withdraw)),
        ),
        RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
    );
    withdraw_ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?),
        RequiredSignature::NativeEcdsa,
    );
    withdraw_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));

    let withdraw_txid = finalize_and_broadcast(&context, &withdraw_ft)?;

    let program_utxos_after_withdraw =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_withdraw,
        option_offer.parameters.collateral_asset_id,
        remaining_collateral_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_withdraw,
        option_offer.parameters.premium_asset_id,
        remaining_premium_amount,
    );

    let signer_utxos = signer.get_utxos_txid(withdraw_txid)?;
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
        &receiver_script_pubkey,
    );

    Ok(())
}

#[simplex::test]
fn withdraw_option_offer_rejects_invalid_signature(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let deposit_lbtc_amount = 1_000_u64;
    let expected_premium_amount = 10_000_u64;
    let expected_settlement_amount = 10_000_u64;
    let partial_collateral_amount = 600_u64;
    let remaining_collateral_amount = deposit_lbtc_amount - partial_collateral_amount;
    let exercised_premium_amount = 6_000_u64;
    let remaining_premium_amount = expected_premium_amount - exercised_premium_amount;
    let exercised_settlement_amount = 6_000_u64;

    let prepared_option_offer = prepare_option_offer(
        &context,
        deposit_lbtc_amount,
        expected_premium_amount,
        expected_settlement_amount,
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
        deposit_lbtc_amount,
        expected_premium_amount,
    )?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: partial_collateral_amount,
        is_change_needed: true,
    };
    let collateral_program_utxo = require_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
        "missing collateral covenant utxo",
    )?;
    let premium_program_utxo = require_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
        "missing premium covenant utxo",
    )?;

    let mut exercise_ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        exercise_ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    exercise_ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        partial_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        exercised_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    let _ = finalize_and_broadcast(&context, &exercise_ft)?;

    let exercised_program_utxos =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let settlement_program_utxo = require_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
        "missing settlement covenant utxo",
    )?;

    let mut withdraw_ft = FinalTransaction::new();
    withdraw_ft.add_program_input(
        PartialInput::new(settlement_program_utxo),
        ProgramInput::new(
            Box::new(option_offer.get_program().clone()),
            Box::new(OptionOffer::get_witness(OptionOfferBranch::Withdraw)),
        ),
        RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
    );
    withdraw_ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?),
        RequiredSignature::NativeEcdsa,
    );
    withdraw_ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));

    let (pst, _) = withdraw_ft.extract_pst();
    let signature =
        signer.sign_program(&pst, option_offer.get_program(), 0, context.get_network())?;
    let mut signed_witness = HashMap::new();
    let witness = OptionOffer::get_witness(OptionOfferBranch::Withdraw).build_witness();
    witness.iter().for_each(|(name, value)| {
        signed_witness.insert(name.clone(), value.clone());
    });
    signed_witness.insert(
        WitnessName::from_str_unchecked("USER_SIGHASH_ALL"),
        Value::byte_array(signature.serialize()),
    );
    let program_error = option_offer
        .get_program()
        .finalize(
            &pst,
            &WitnessValues::from(signed_witness),
            0,
            context.get_network(),
        )
        .expect_err("withdraw should reject a mismatched user signature");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    let program_utxos_after_rejection =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.collateral_asset_id,
        remaining_collateral_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.premium_asset_id,
        remaining_premium_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
    );

    Ok(())
}

#[simplex::test]
fn withdraw_option_offer_rejects_partial_output_amount(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let deposit_lbtc_amount = 1_000_u64;
    let expected_premium_amount = 10_000_u64;
    let expected_settlement_amount = 10_000_u64;
    let partial_collateral_amount = 600_u64;
    let remaining_collateral_amount = deposit_lbtc_amount - partial_collateral_amount;
    let exercised_premium_amount = 6_000_u64;
    let remaining_premium_amount = expected_premium_amount - exercised_premium_amount;
    let exercised_settlement_amount = 6_000_u64;

    let option_offer = prepare_option_offer(
        &context,
        deposit_lbtc_amount,
        expected_premium_amount,
        expected_settlement_amount,
        1_000,
    )?;

    create_option_offer_with_premium(
        &context,
        &option_offer,
        deposit_lbtc_amount,
        expected_premium_amount,
    )?;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: partial_collateral_amount,
        is_change_needed: true,
    };
    let collateral_program_utxo = require_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
        "missing collateral covenant utxo",
    )?;
    let premium_program_utxo = require_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
        "missing premium covenant utxo",
    )?;

    let mut exercise_ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        exercise_ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    exercise_ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        partial_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    exercise_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        exercised_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    let _ = finalize_and_broadcast(&context, &exercise_ft)?;

    let exercised_program_utxos =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let settlement_program_utxo = require_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
        "missing settlement covenant utxo",
    )?;

    let mut withdraw_ft = FinalTransaction::new();
    withdraw_ft.add_program_input(
        PartialInput::new(settlement_program_utxo),
        ProgramInput::new(
            Box::new(option_offer.get_program().clone()),
            Box::new(OptionOffer::get_witness(OptionOfferBranch::Withdraw)),
        ),
        RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
    );
    withdraw_ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?),
        RequiredSignature::NativeEcdsa,
    );
    withdraw_ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        exercised_settlement_amount - 1,
        option_offer.parameters.settlement_asset_id,
    ));
    withdraw_ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        1,
        option_offer.parameters.settlement_asset_id,
    ));

    let (pst, _) = withdraw_ft.extract_pst();
    let signature =
        signer.sign_program(&pst, option_offer.get_program(), 0, context.get_network())?;
    let mut signed_witness = HashMap::new();
    let witness = OptionOffer::get_witness(OptionOfferBranch::Withdraw).build_witness();
    witness.iter().for_each(|(name, value)| {
        signed_witness.insert(name.clone(), value.clone());
    });
    signed_witness.insert(
        WitnessName::from_str_unchecked("USER_SIGHASH_ALL"),
        Value::byte_array(signature.serialize()),
    );
    let program_error = option_offer
        .get_program()
        .finalize(
            &pst,
            &WitnessValues::from(signed_witness),
            0,
            context.get_network(),
        )
        .expect_err("withdraw should reject a partial settlement output at index 0");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    let program_utxos_after_rejection =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.collateral_asset_id,
        remaining_collateral_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.premium_asset_id,
        remaining_premium_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
    );

    Ok(())
}
