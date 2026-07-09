use crate::common::filters::{
    assert_covenant_utxo, assert_has_utxo_by_asset_and_amount, require_covenant_utxo,
};
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo};
use crate::common::{locked_input, locktime_from};
use crate::program_builder::options::{
    CONTRACT_COUNT, EXPECTED_SETTLEMENT_AMOUNT, exercise_options_fully, options_program_input,
    setup_funded_options,
};

use contracts::programs::options::{Options, OptionsBranch};
use contracts::programs::program::SimplexProgram;

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::simplicityhl::elements::{Script, Sequence};
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

#[simplex::test]
fn settle_options(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let funded = setup_funded_options(&context, -100, 1_000)?;
    let _ = exercise_options_fully(&context, &funded)?;

    let parameters = &funded.options.parameters;
    let locktime = locktime_from(parameters.start_time)?;
    let locked_settlement = require_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
        "missing locked settlement covenant utxo",
    )?;
    let grantor_token_input =
        ensure_exact_signer_utxo(&context, parameters.grantor_token_asset, CONTRACT_COUNT)?;

    let mut settlement_ft = FinalTransaction::new();
    settlement_ft.add_program_input(
        locked_input(locked_settlement, locktime),
        options_program_input(
            &funded.options,
            OptionsBranch::Settlement {
                is_change_needed: false,
                amount_to_burn: CONTRACT_COUNT,
                settlement_amount: EXPECTED_SETTLEMENT_AMOUNT,
            },
        ),
        RequiredSignature::None,
    );
    settlement_ft.add_input(
        locked_input(grantor_token_input, locktime),
        RequiredSignature::NativeEcdsa,
    );
    settlement_ft.add_input(
        locked_input(get_lbtc_utxo(&context)?, locktime),
        RequiredSignature::NativeEcdsa,
    );
    settlement_ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        CONTRACT_COUNT,
        parameters.grantor_token_asset,
    ));
    settlement_ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        EXPECTED_SETTLEMENT_AMOUNT,
        parameters.settlement_asset_id,
    ));

    let settlement_txid = finalize_and_broadcast(&context, &settlement_ft)?;

    let transaction = provider.fetch_transaction(&settlement_txid)?;
    assert_eq!(
        transaction.output[0].script_pubkey,
        Script::new_op_return(b"burn")
    );
    assert_eq!(
        transaction.output[0].asset.explicit(),
        Some(parameters.grantor_token_asset)
    );
    assert_eq!(transaction.output[0].value.explicit(), Some(CONTRACT_COUNT));
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
        signer.get_address().script_pubkey()
    );

    let signer_utxos = signer.get_utxos_txid(settlement_txid)?;
    assert_has_utxo_by_asset_and_amount(
        &signer_utxos,
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    );

    Ok(())
}

#[simplex::test]
fn settle_options_with_change(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let settled_contract_count = 6_u64;
    let settled_settlement_amount = 300_u64;
    let remaining_settlement_amount = EXPECTED_SETTLEMENT_AMOUNT - settled_settlement_amount;

    let funded = setup_funded_options(&context, -100, 1_000)?;
    let _ = exercise_options_fully(&context, &funded)?;

    let parameters = &funded.options.parameters;
    let locktime = locktime_from(parameters.start_time)?;
    let locked_settlement = require_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
        "missing locked settlement covenant utxo",
    )?;
    let grantor_token_input = ensure_exact_signer_utxo(
        &context,
        parameters.grantor_token_asset,
        settled_contract_count,
    )?;

    let mut settlement_ft = FinalTransaction::new();
    settlement_ft.add_program_input(
        locked_input(locked_settlement, locktime),
        options_program_input(
            &funded.options,
            OptionsBranch::Settlement {
                is_change_needed: true,
                amount_to_burn: settled_contract_count,
                settlement_amount: settled_settlement_amount,
            },
        ),
        RequiredSignature::None,
    );
    settlement_ft.add_input(
        locked_input(grantor_token_input, locktime),
        RequiredSignature::NativeEcdsa,
    );
    settlement_ft.add_input(
        locked_input(get_lbtc_utxo(&context)?, locktime),
        RequiredSignature::NativeEcdsa,
    );
    settlement_ft.add_output(PartialOutput::new(
        funded.options.get_script_pubkey(),
        remaining_settlement_amount,
        parameters.settlement_asset_id,
    ));
    settlement_ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        settled_contract_count,
        parameters.grantor_token_asset,
    ));
    settlement_ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        settled_settlement_amount,
        parameters.settlement_asset_id,
    ));

    let settlement_txid = finalize_and_broadcast(&context, &settlement_ft)?;

    let transaction = provider.fetch_transaction(&settlement_txid)?;
    assert_eq!(
        transaction.output[0].value.explicit(),
        Some(remaining_settlement_amount)
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
        Some(settled_settlement_amount)
    );
    assert_eq!(
        transaction.output[2].script_pubkey,
        signer.get_address().script_pubkey()
    );

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        remaining_settlement_amount,
    )?;

    Ok(())
}

#[simplex::test]
fn settle_options_rejects_missing_locktime(context: simplex::TestContext) -> anyhow::Result<()> {
    let funded = setup_funded_options(&context, -100, 1_000)?;
    let _ = exercise_options_fully(&context, &funded)?;

    let parameters = &funded.options.parameters;
    let locked_settlement = require_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
        "missing locked settlement covenant utxo",
    )?;
    let grantor_token_input =
        ensure_exact_signer_utxo(&context, parameters.grantor_token_asset, CONTRACT_COUNT)?;

    let settlement_branch = OptionsBranch::Settlement {
        is_change_needed: false,
        amount_to_burn: CONTRACT_COUNT,
        settlement_amount: EXPECTED_SETTLEMENT_AMOUNT,
    };
    let mut settlement_ft = FinalTransaction::new();
    settlement_ft.add_program_input(
        PartialInput::new(locked_settlement).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        options_program_input(&funded.options, settlement_branch),
        RequiredSignature::None,
    );
    settlement_ft.add_input(
        PartialInput::new(grantor_token_input).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        RequiredSignature::NativeEcdsa,
    );
    settlement_ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        RequiredSignature::NativeEcdsa,
    );
    settlement_ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        CONTRACT_COUNT,
        parameters.grantor_token_asset,
    ));
    settlement_ft.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        EXPECTED_SETTLEMENT_AMOUNT,
        parameters.settlement_asset_id,
    ));

    let (pst, _) = settlement_ft.extract_pst();
    let witness = Options::get_witness(settlement_branch).build_witness();
    let program_error = funded
        .options
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("settlement should reject a missing absolute locktime");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.settlement_asset_id,
        EXPECTED_SETTLEMENT_AMOUNT,
    )?;

    Ok(())
}
