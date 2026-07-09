use crate::common::filters::{assert_covenant_utxo, assert_has_utxo_by_asset_and_amount};
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo};
use crate::common::{locked_input, locktime_from};
use crate::program_builder::options::{
    CONTRACT_COUNT, TOTAL_COLLATERAL_AMOUNT, options_program_input, require_locked_collateral,
    setup_funded_options,
};

use contracts::programs::options::{Options, OptionsBranch};
use contracts::programs::program::SimplexProgram;

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::simplicityhl::elements::{Script, Sequence};
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

#[simplex::test]
fn expire_options(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let funded = setup_funded_options(&context, -100, -50)?;
    let parameters = &funded.options.parameters;

    let grantor_token_input =
        ensure_exact_signer_utxo(&context, parameters.grantor_token_asset, CONTRACT_COUNT)?;
    let locktime = locktime_from(parameters.expiry_time)?;
    let locked_collateral = require_locked_collateral(&context, &funded)?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        locked_input(locked_collateral, locktime),
        options_program_input(
            &funded.options,
            OptionsBranch::Expiry {
                is_change_needed: false,
                amount_to_burn: CONTRACT_COUNT,
                collateral_amount: TOTAL_COLLATERAL_AMOUNT,
            },
        ),
        RequiredSignature::None,
    );
    for input in [grantor_token_input, get_lbtc_utxo(&context)?] {
        ft.add_input(
            locked_input(input, locktime),
            RequiredSignature::NativeEcdsa,
        );
    }
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        CONTRACT_COUNT,
        parameters.grantor_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        TOTAL_COLLATERAL_AMOUNT,
        parameters.collateral_asset_id,
    ));

    let expiry_txid = finalize_and_broadcast(&context, &ft)?;

    let transaction = provider.fetch_transaction(&expiry_txid)?;
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
        Some(parameters.collateral_asset_id)
    );
    assert_eq!(
        transaction.output[1].value.explicit(),
        Some(TOTAL_COLLATERAL_AMOUNT)
    );
    assert_eq!(
        transaction.output[1].script_pubkey,
        signer.get_address().script_pubkey()
    );

    let signer_utxos = signer.get_utxos_txid(expiry_txid)?;
    assert_has_utxo_by_asset_and_amount(
        &signer_utxos,
        parameters.collateral_asset_id,
        TOTAL_COLLATERAL_AMOUNT,
    );

    Ok(())
}

#[simplex::test]
fn expire_options_with_change(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();

    let expired_contract_count = 6_u64;
    let returned_collateral_amount = 600_u64;
    let remaining_collateral_amount = TOTAL_COLLATERAL_AMOUNT - returned_collateral_amount;

    let funded = setup_funded_options(&context, -100, -50)?;
    let parameters = &funded.options.parameters;

    let grantor_token_input = ensure_exact_signer_utxo(
        &context,
        parameters.grantor_token_asset,
        expired_contract_count,
    )?;
    let locktime = locktime_from(parameters.expiry_time)?;
    let locked_collateral = require_locked_collateral(&context, &funded)?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        locked_input(locked_collateral, locktime),
        options_program_input(
            &funded.options,
            OptionsBranch::Expiry {
                is_change_needed: true,
                amount_to_burn: expired_contract_count,
                collateral_amount: returned_collateral_amount,
            },
        ),
        RequiredSignature::None,
    );
    for input in [grantor_token_input, get_lbtc_utxo(&context)?] {
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
        expired_contract_count,
        parameters.grantor_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        returned_collateral_amount,
        parameters.collateral_asset_id,
    ));

    let expiry_txid = finalize_and_broadcast(&context, &ft)?;

    let transaction = provider.fetch_transaction(&expiry_txid)?;
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
        Some(returned_collateral_amount)
    );

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.collateral_asset_id,
        remaining_collateral_amount,
    )?;

    Ok(())
}

#[simplex::test]
fn expire_options_rejects_missing_locktime(context: simplex::TestContext) -> anyhow::Result<()> {
    let funded = setup_funded_options(&context, -100, -50)?;
    let parameters = &funded.options.parameters;

    let grantor_token_input =
        ensure_exact_signer_utxo(&context, parameters.grantor_token_asset, CONTRACT_COUNT)?;
    let locked_collateral = require_locked_collateral(&context, &funded)?;

    let expiry_branch = OptionsBranch::Expiry {
        is_change_needed: false,
        amount_to_burn: CONTRACT_COUNT,
        collateral_amount: TOTAL_COLLATERAL_AMOUNT,
    };
    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(locked_collateral).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        options_program_input(&funded.options, expiry_branch),
        RequiredSignature::None,
    );
    for input in [grantor_token_input, get_lbtc_utxo(&context)?] {
        ft.add_input(
            PartialInput::new(input).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
            RequiredSignature::NativeEcdsa,
        );
    }
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        CONTRACT_COUNT,
        parameters.grantor_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        TOTAL_COLLATERAL_AMOUNT,
        parameters.collateral_asset_id,
    ));

    let (pst, _) = ft.extract_pst();
    let witness = Options::get_witness(expiry_branch).build_witness();
    let program_error = funded
        .options
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("expiry should reject a missing absolute locktime");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.collateral_asset_id,
        TOTAL_COLLATERAL_AMOUNT,
    )?;

    Ok(())
}
