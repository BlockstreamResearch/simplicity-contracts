use crate::common::filters::{
    assert_has_utxo_by_asset_amount_and_script, assert_has_utxo_by_asset_and_amount,
    require_utxo_by_asset_and_amount,
};
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast};
use crate::program_builder::option_offer::{
    create_option_offer_with_premium, prepare_option_offer,
};

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::programs::option_offer::{OptionOffer, OptionOfferBranch};
use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn exercise_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let deposit_lbtc_amount = 1_000_u64;
    let expected_premium_amount = 10_000_u64;
    let expected_settlement_amount = 10_000_u64;

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
        expected_settlement_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: deposit_lbtc_amount,
        is_change_needed: false,
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

    let mut ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        expected_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        deposit_lbtc_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        expected_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    let exercise_txid = finalize_and_broadcast(&context, &ft)?;

    let exercised_program_utxos =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.settlement_asset_id,
        expected_settlement_amount,
    );

    let signer_utxos = signer.get_utxos_txid(exercise_txid)?;
    let receiver_script_pubkey = signer.get_address().script_pubkey();
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
        &receiver_script_pubkey,
    );
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
        &receiver_script_pubkey,
    );

    Ok(())
}

#[simplex::test]
fn exercise_option_offer_with_change(context: simplex::TestContext) -> anyhow::Result<()> {
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
        0,
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

    let mut ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        partial_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        exercised_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    let exercise_txid = finalize_and_broadcast(&context, &ft)?;

    let exercised_program_utxos =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.collateral_asset_id,
        remaining_collateral_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.premium_asset_id,
        remaining_premium_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &exercised_program_utxos,
        option_offer.parameters.settlement_asset_id,
        exercised_settlement_amount,
    );

    let signer_utxos = signer.get_utxos_txid(exercise_txid)?;
    let receiver_script_pubkey = signer.get_address().script_pubkey();
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.collateral_asset_id,
        partial_collateral_amount,
        &receiver_script_pubkey,
    );
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        option_offer.parameters.premium_asset_id,
        exercised_premium_amount,
        &receiver_script_pubkey,
    );

    Ok(())
}

#[simplex::test]
fn exercise_option_offer_rejects_wrong_settlement_amount(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let deposit_lbtc_amount = 1_000_u64;
    let expected_premium_amount = 10_000_u64;
    let expected_settlement_amount = 10_000_u64;

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
        expected_settlement_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    let exercise_branch = OptionOfferBranch::Exercise {
        collateral_amount: deposit_lbtc_amount,
        is_change_needed: false,
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

    let mut ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        expected_settlement_amount - 1,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        deposit_lbtc_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        expected_premium_amount,
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

    let covenant_utxos_after_rejection =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &covenant_utxos_after_rejection,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &covenant_utxos_after_rejection,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
    );

    Ok(())
}

#[simplex::test]
fn exercise_option_offer_rejects_partial_exercise_without_change_flag(
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
        is_change_needed: false,
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

    let mut ft = FinalTransaction::new();

    for utxo in [collateral_program_utxo, premium_program_utxo] {
        ft.add_program_input(
            PartialInput::new(utxo),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(exercise_branch)),
            ),
            RequiredSignature::None,
        );
    }

    ft.add_input(
        PartialInput::new(settlement_input),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        remaining_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        option_offer.get_script_pubkey(),
        exercised_settlement_amount,
        option_offer.parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        partial_collateral_amount,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        exercised_premium_amount,
        option_offer.parameters.premium_asset_id,
    ));

    let (pst, _) = ft.extract_pst();
    let witness = OptionOffer::get_witness(exercise_branch).build_witness();
    let program_error = option_offer
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("exercise should reject missing change flag");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    let covenant_utxos_after_rejection =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &covenant_utxos_after_rejection,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &covenant_utxos_after_rejection,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
    );

    Ok(())
}
