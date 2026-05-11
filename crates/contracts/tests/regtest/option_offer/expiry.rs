use crate::common::filters::{
    assert_has_utxo_by_asset_amount_and_script, assert_has_utxo_by_asset_and_amount,
    require_utxo_by_asset_and_amount,
};
use crate::common::signer::{finalize_and_broadcast, get_lbtc_utxo};
use crate::program_builder::option_offer::{
    create_option_offer_with_premium, prepare_option_offer,
};

use std::collections::HashMap;

use simplex::program::{ProgramError, ProgramTrait, WitnessTrait};
use simplex::signer::SignerTrait;
use simplex::simplicityhl::elements::{LockTime, Sequence};
use simplex::simplicityhl::str::WitnessName;
use simplex::simplicityhl::value::ValueConstructible;
use simplex::simplicityhl::{Value, WitnessValues};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::programs::option_offer::{OptionOffer, OptionOfferBranch};
use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn expiry_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
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
        -50,
    )?;

    create_option_offer_with_premium(
        &context,
        &option_offer,
        deposit_lbtc_amount,
        expected_premium_amount,
    )?;

    let locktime = LockTime::from_time(option_offer.parameters.expiry_time)
        .map_err(|error| anyhow::anyhow!(error))?;
    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
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
            PartialInput::new(utxo)
                .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
                .with_locktime(locktime),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(OptionOfferBranch::Expiry)),
            ),
            RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
        );
    }
    ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?)
            .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
            .with_locktime(locktime),
        RequiredSignature::NativeEcdsa,
    );

    let receiver_script_pubkey = signer.get_address().script_pubkey();
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

    let expiry_txid = finalize_and_broadcast(&context, &ft)?;

    let signer_utxos = signer.get_utxos_txid(expiry_txid)?;
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
fn expiry_option_offer_rejects_missing_locktime(
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
        -50,
    )?;

    create_option_offer_with_premium(
        &context,
        &option_offer,
        deposit_lbtc_amount,
        expected_premium_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
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
            PartialInput::new(utxo).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
            ProgramInput::new(
                Box::new(option_offer.get_program().clone()),
                Box::new(OptionOffer::get_witness(OptionOfferBranch::Expiry)),
            ),
            RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
        );
    }
    ft.add_input(
        PartialInput::new(get_lbtc_utxo(&context)?).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
        RequiredSignature::NativeEcdsa,
    );

    let receiver_script_pubkey = signer.get_address().script_pubkey();
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

    let (pst, _) = ft.extract_pst();
    let signature =
        signer.sign_program(&pst, option_offer.get_program(), 0, context.get_network())?;
    let mut signed_witness = HashMap::new();
    let witness = OptionOffer::get_witness(OptionOfferBranch::Expiry).build_witness();
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
        .expect_err("expiry should reject a missing absolute locktime");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    let program_utxos_after_rejection =
        provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos_after_rejection,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
    );

    Ok(())
}
