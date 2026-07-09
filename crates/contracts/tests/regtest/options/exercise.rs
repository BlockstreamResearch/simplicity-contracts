use crate::common::filters::assert_covenant_utxo;
use crate::common::filters::assert_has_utxo_by_asset_and_amount;
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo};
use crate::common::{locked_input, locktime_from};
use crate::program_builder::options::{
    CONTRACT_COUNT, EXPECTED_SETTLEMENT_AMOUNT, TOTAL_COLLATERAL_AMOUNT, exercise_options_fully,
    options_program_input, require_locked_collateral, setup_funded_options,
};

use contracts::programs::options::{Options, OptionsBranch};
use contracts::programs::program::SimplexProgram;

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::simplicityhl::elements::{Script, Sequence};
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

#[simplex::test]
fn exercise_options(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let funded = setup_funded_options(&context, -100, 1_000)?;
    let exercise_txid = exercise_options_fully(&context, &funded)?;

    let parameters = &funded.options.parameters;
    let receiver_script_pubkey = signer.get_address().script_pubkey();

    let transaction = provider.fetch_transaction(&exercise_txid)?;
    assert_eq!(
        transaction.output[0].asset.explicit(),
        Some(parameters.option_token_asset)
    );
    assert_eq!(transaction.output[0].value.explicit(), Some(CONTRACT_COUNT));
    assert_eq!(
        transaction.output[0].script_pubkey,
        Script::new_op_return(b"burn")
    );

    assert_eq!(
        transaction.output[1].asset.explicit(),
        Some(parameters.settlement_asset_id)
    );
    assert_eq!(
        transaction.output[1].value.explicit(),
        Some(EXPECTED_SETTLEMENT_AMOUNT)
    );
    assert_eq!(
        transaction.output[1].script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(
        transaction.output[2].asset.explicit(),
        Some(parameters.collateral_asset_id)
    );
    assert_eq!(
        transaction.output[2].value.explicit(),
        Some(TOTAL_COLLATERAL_AMOUNT)
    );
    assert_eq!(transaction.output[2].script_pubkey, receiver_script_pubkey);

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;

    let signer_utxos = signer.get_utxos_txid(exercise_txid)?;
    assert_has_utxo_by_asset_and_amount(
        &signer_utxos,
        parameters.collateral_asset_id,
        TOTAL_COLLATERAL_AMOUNT,
    );

    Ok(())
}

#[simplex::test]
fn exercise_options_with_change(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let exercised_contract_count = 6_u64;
    let exercised_collateral_amount = 600_u64;
    let exercised_settlement_amount = 300_u64;
    let remaining_collateral_amount = TOTAL_COLLATERAL_AMOUNT - exercised_collateral_amount;

    let funded = setup_funded_options(&context, -100, 1_000)?;
    let parameters = &funded.options.parameters;

    let receiver_script_pubkey = signer.get_address().script_pubkey();
    let option_token_input = ensure_exact_signer_utxo(
        &context,
        parameters.option_token_asset,
        exercised_contract_count,
    )?;
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        parameters.settlement_asset_id,
        exercised_settlement_amount,
    )?;
    let locktime = locktime_from(parameters.start_time)?;
    let locked_collateral = require_locked_collateral(&context, &funded)?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        locked_input(locked_collateral, locktime),
        options_program_input(
            &funded.options,
            OptionsBranch::Exercise {
                is_change_needed: true,
                amount_to_burn: exercised_contract_count,
                collateral_amount: exercised_collateral_amount,
                settlement_amount: exercised_settlement_amount,
            },
        ),
        RequiredSignature::None,
    );
    for input in [
        option_token_input,
        settlement_input,
        get_lbtc_utxo(&context)?,
    ] {
        ft.add_input(
            locked_input(input, locktime),
            RequiredSignature::NativeEcdsa,
        );
    }
    ft.add_output(PartialOutput::new(
        funded.options.get_script_pubkey(),
        remaining_collateral_amount,
        parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        exercised_contract_count,
        parameters.option_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        funded.options.get_script_pubkey(),
        exercised_settlement_amount,
        parameters.settlement_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey.clone(),
        exercised_collateral_amount,
        parameters.collateral_asset_id,
    ));

    let exercise_txid = finalize_and_broadcast(&context, &ft)?;

    let transaction = provider.fetch_transaction(&exercise_txid)?;
    assert_eq!(
        transaction.output[0].value.explicit(),
        Some(remaining_collateral_amount)
    );
    assert_eq!(
        transaction.output[0].script_pubkey,
        funded.options.get_script_pubkey()
    );
    assert_eq!(
        transaction.output[1].script_pubkey,
        Script::new_op_return(b"burn")
    );
    assert_eq!(
        transaction.output[2].value.explicit(),
        Some(exercised_settlement_amount)
    );
    assert_eq!(
        transaction.output[2].script_pubkey,
        funded.options.get_script_pubkey()
    );
    assert_eq!(
        transaction.output[3].value.explicit(),
        Some(exercised_collateral_amount)
    );
    assert_eq!(transaction.output[3].script_pubkey, receiver_script_pubkey);

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.collateral_asset_id,
        remaining_collateral_amount,
    )?;
    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        exercised_settlement_amount,
    )?;

    Ok(())
}

#[simplex::test]
fn exercise_options_rejects_missing_locktime(context: simplex::TestContext) -> anyhow::Result<()> {
    let funded = setup_funded_options(&context, -100, 1_000)?;
    let parameters = &funded.options.parameters;

    let option_token_input =
        ensure_exact_signer_utxo(&context, parameters.option_token_asset, CONTRACT_COUNT)?;
    let settlement_input = ensure_exact_signer_utxo(
        &context,
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;
    let locked_collateral = require_locked_collateral(&context, &funded)?;

    let exercise_branch = OptionsBranch::Exercise {
        is_change_needed: false,
        amount_to_burn: CONTRACT_COUNT,
        collateral_amount: TOTAL_COLLATERAL_AMOUNT,
        settlement_amount: EXPECTED_SETTLEMENT_AMOUNT,
    };
    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(locked_collateral).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        options_program_input(&funded.options, exercise_branch),
        RequiredSignature::None,
    );
    for input in [
        option_token_input,
        settlement_input,
        get_lbtc_utxo(&context)?,
    ] {
        ft.add_input(
            PartialInput::new(input).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
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
        context.get_default_signer().get_address().script_pubkey(),
        TOTAL_COLLATERAL_AMOUNT,
        parameters.collateral_asset_id,
    ));

    let (pst, _) = ft.extract_pst();
    let witness = Options::get_witness(exercise_branch).build_witness();
    let program_error = funded
        .options
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("exercise should reject a missing absolute locktime");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.collateral_asset_id,
        TOTAL_COLLATERAL_AMOUNT,
    )?;

    Ok(())
}
