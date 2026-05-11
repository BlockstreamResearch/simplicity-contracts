use crate::common::filters::{
    assert_has_utxo_by_asset_and_amount, require_utxo_by_asset_and_amount,
};
use crate::common::signer::{ensure_exact_signer_utxo, finalize_and_broadcast, get_lbtc_utxo};
use crate::program_builder::options::{create_options, fund_options, prepare_options};

use contracts::programs::options::{Options, OptionsBranch};
use contracts::programs::program::SimplexProgram;

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::simplicityhl::elements::{LockTime, Script, Sequence};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

#[simplex::test]
fn expire_options(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let total_collateral_amount = 1_000_u64;
    let expected_settlement_amount = 500_u64;
    let contract_count = 10_u64;

    let prepared = prepare_options(
        &context,
        total_collateral_amount,
        expected_settlement_amount,
        contract_count,
        -100,
        -50,
    )?;
    let created = create_options(&context, prepared)?;
    let funded = fund_options(&context, created, total_collateral_amount, contract_count)?;

    let grantor_token_input = ensure_exact_signer_utxo(
        &context,
        funded.options.parameters.grantor_token_asset,
        contract_count,
    )?;
    let locktime = LockTime::from_time(funded.options.parameters.expiry_time)
        .map_err(|error| anyhow::anyhow!(error))?;

    let program_utxos = provider.fetch_scripthash_utxos(&funded.options.get_script_pubkey())?;
    let locked_collateral = require_utxo_by_asset_and_amount(
        &program_utxos,
        funded.options.parameters.collateral_asset_id,
        total_collateral_amount,
        "missing locked collateral covenant utxo",
    )?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(locked_collateral)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        ProgramInput::new(
            Box::new(funded.options.get_program().clone()),
            Box::new(Options::get_witness(OptionsBranch::Expiry {
                is_change_needed: false,
                amount_to_burn: contract_count,
                collateral_amount: total_collateral_amount,
            })),
        ),
        RequiredSignature::None,
    );
    ft.add_input(
        PartialInput::new(grantor_token_input)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        contract_count,
        funded.options.parameters.grantor_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        total_collateral_amount,
        funded.options.parameters.collateral_asset_id,
    ));

    let expiry_txid = finalize_and_broadcast(&context, &ft)?;

    let transaction = provider.fetch_transaction(&expiry_txid)?;
    assert_eq!(
        transaction.output[0].script_pubkey,
        Script::new_op_return(b"burn")
    );
    assert_eq!(
        transaction.output[0].asset.explicit(),
        Some(funded.options.parameters.grantor_token_asset)
    );
    assert_eq!(transaction.output[0].value.explicit(), Some(contract_count));
    assert_eq!(
        transaction.output[1].asset.explicit(),
        Some(funded.options.parameters.collateral_asset_id)
    );
    assert_eq!(
        transaction.output[1].value.explicit(),
        Some(total_collateral_amount)
    );
    assert_eq!(
        transaction.output[1].script_pubkey,
        signer.get_address().script_pubkey()
    );

    let signer_utxos = signer.get_utxos_txid(expiry_txid)?;
    assert_has_utxo_by_asset_and_amount(
        &signer_utxos,
        funded.options.parameters.collateral_asset_id,
        total_collateral_amount,
    );

    Ok(())
}

#[simplex::test]
fn expire_options_with_change(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();

    let total_collateral_amount = 1_000_u64;
    let expected_settlement_amount = 500_u64;
    let contract_count = 10_u64;
    let expired_contract_count = 6_u64;
    let returned_collateral_amount = 600_u64;
    let remaining_collateral_amount = total_collateral_amount - returned_collateral_amount;

    let prepared = prepare_options(
        &context,
        total_collateral_amount,
        expected_settlement_amount,
        contract_count,
        -100,
        -50,
    )?;
    let created = create_options(&context, prepared)?;
    let funded = fund_options(&context, created, total_collateral_amount, contract_count)?;

    let grantor_token_input = ensure_exact_signer_utxo(
        &context,
        funded.options.parameters.grantor_token_asset,
        expired_contract_count,
    )?;
    let locktime = LockTime::from_time(funded.options.parameters.expiry_time)
        .map_err(|error| anyhow::anyhow!(error))?;

    let program_utxos = provider.fetch_scripthash_utxos(&funded.options.get_script_pubkey())?;
    let locked_collateral = require_utxo_by_asset_and_amount(
        &program_utxos,
        funded.options.parameters.collateral_asset_id,
        total_collateral_amount,
        "missing locked collateral covenant utxo",
    )?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(locked_collateral)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        ProgramInput::new(
            Box::new(funded.options.get_program().clone()),
            Box::new(Options::get_witness(OptionsBranch::Expiry {
                is_change_needed: true,
                amount_to_burn: expired_contract_count,
                collateral_amount: returned_collateral_amount,
            })),
        ),
        RequiredSignature::None,
    );
    ft.add_input(
        PartialInput::new(grantor_token_input)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        funded.options.get_script_pubkey(),
        remaining_collateral_amount,
        funded.options.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        expired_contract_count,
        funded.options.parameters.grantor_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        returned_collateral_amount,
        funded.options.parameters.collateral_asset_id,
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

    let covenant_utxos_after_expiry =
        provider.fetch_scripthash_utxos(&funded.options.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &covenant_utxos_after_expiry,
        funded.options.parameters.collateral_asset_id,
        remaining_collateral_amount,
    );

    Ok(())
}

#[simplex::test]
fn expire_options_rejects_missing_locktime(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();

    let total_collateral_amount = 1_000_u64;
    let expected_settlement_amount = 500_u64;
    let contract_count = 10_u64;

    let prepared = prepare_options(
        &context,
        total_collateral_amount,
        expected_settlement_amount,
        contract_count,
        -100,
        -50,
    )?;
    let created = create_options(&context, prepared)?;
    let funded = fund_options(&context, created, total_collateral_amount, contract_count)?;

    let grantor_token_input = ensure_exact_signer_utxo(
        &context,
        funded.options.parameters.grantor_token_asset,
        contract_count,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&funded.options.get_script_pubkey())?;
    let locked_collateral = require_utxo_by_asset_and_amount(
        &program_utxos,
        funded.options.parameters.collateral_asset_id,
        total_collateral_amount,
        "missing locked collateral covenant utxo",
    )?;

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        PartialInput::new(locked_collateral).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        ProgramInput::new(
            Box::new(funded.options.get_program().clone()),
            Box::new(Options::get_witness(OptionsBranch::Expiry {
                is_change_needed: false,
                amount_to_burn: contract_count,
                collateral_amount: total_collateral_amount,
            })),
        ),
        RequiredSignature::None,
    );
    ft.add_input(
        PartialInput::new(grantor_token_input).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        Script::new_op_return(b"burn"),
        contract_count,
        funded.options.parameters.grantor_token_asset,
    ));
    ft.add_output(PartialOutput::new(
        context.get_default_signer().get_address().script_pubkey(),
        total_collateral_amount,
        funded.options.parameters.collateral_asset_id,
    ));

    let (pst, _) = ft.extract_pst();
    let witness = Options::get_witness(OptionsBranch::Expiry {
        is_change_needed: false,
        amount_to_burn: contract_count,
        collateral_amount: total_collateral_amount,
    })
    .build_witness();
    let program_error = funded
        .options
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("expiry should reject a missing absolute locktime");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    let covenant_utxos_after_rejection =
        provider.fetch_scripthash_utxos(&funded.options.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &covenant_utxos_after_rejection,
        funded.options.parameters.collateral_asset_id,
        total_collateral_amount,
    );

    Ok(())
}
