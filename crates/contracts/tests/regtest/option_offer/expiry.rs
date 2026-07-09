use crate::common::filters::{assert_covenant_utxo, assert_has_utxo_by_asset_amount_and_script};
use crate::common::signer::{finalize_and_broadcast, get_lbtc_utxo};
use crate::common::{locked_input, locktime_from};
use crate::program_builder::option_offer::{
    DEPOSIT_LBTC_AMOUNT, EXPECTED_PREMIUM_AMOUNT, offer_program_input, require_offer_utxos,
    setup_offer_with_premium, witness_with_user_sighash,
};

use simplex::program::{ProgramError, ProgramTrait};
use simplex::simplicityhl::elements::Sequence;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::programs::option_offer::OptionOfferBranch;
use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn expiry_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, -50)?;

    let locktime = locktime_from(option_offer.parameters.expiry_time)?;
    let offer_utxos = require_offer_utxos(
        &context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    let mut ft = FinalTransaction::new();
    for utxo in offer_utxos {
        ft.add_program_input(
            locked_input(utxo, locktime),
            offer_program_input(&option_offer, OptionOfferBranch::Expiry),
            RequiredSignature::Witness("USER_SIGHASH_ALL".to_string()),
        );
    }
    ft.add_input(
        locked_input(get_lbtc_utxo(&context)?, locktime),
        RequiredSignature::NativeEcdsa,
    );

    let receiver_script_pubkey = signer.get_address().script_pubkey();
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

    let expiry_txid = finalize_and_broadcast(&context, &ft)?;

    let signer_utxos = signer.get_utxos_txid(expiry_txid)?;
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
fn expiry_option_offer_rejects_missing_locktime(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let option_offer = setup_offer_with_premium(&context, -50)?;

    let offer_utxos = require_offer_utxos(
        &context,
        &option_offer,
        DEPOSIT_LBTC_AMOUNT,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    let mut ft = FinalTransaction::new();
    for utxo in offer_utxos {
        ft.add_program_input(
            PartialInput::new(utxo).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
            offer_program_input(&option_offer, OptionOfferBranch::Expiry),
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
        DEPOSIT_LBTC_AMOUNT,
        option_offer.parameters.collateral_asset_id,
    ));
    ft.add_output(PartialOutput::new(
        receiver_script_pubkey,
        EXPECTED_PREMIUM_AMOUNT,
        option_offer.parameters.premium_asset_id,
    ));

    let (pst, _) = ft.extract_pst();
    let witness =
        witness_with_user_sighash(&context, &option_offer, OptionOfferBranch::Expiry, &pst)?;
    let program_error = option_offer
        .get_program()
        .finalize(&pst, &witness, 0, context.get_network())
        .expect_err("expiry should reject a missing absolute locktime");
    assert!(matches!(program_error, ProgramError::Pruning(_)));

    let script_pubkey = option_offer.get_script_pubkey();
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.collateral_asset_id,
        DEPOSIT_LBTC_AMOUNT,
    )?;
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.premium_asset_id,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    Ok(())
}
