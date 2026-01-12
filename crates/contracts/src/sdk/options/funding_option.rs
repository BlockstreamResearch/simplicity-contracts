use crate::options::OptionsArguments;
use crate::options::build_witness::OptionBranch;

use crate::error::TransactionBuildError;

use crate::sdk::validation::TxOutExt;

use std::collections::HashMap;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::PublicKey;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{OutPoint, Script, Sequence, TxOut, TxOutSecrets};

/// Fund an option contract by depositing collateral and reissuing tokens.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (ALL amounts and assets are expected to be explicit)
/// - Transaction blinding fails
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn build_option_funding(
    blinding_key: &PublicKey,
    option_asset_utxo: (OutPoint, TxOut, TxOutSecrets),
    grantor_asset_utxo: (OutPoint, TxOut, TxOutSecrets),
    collateral_utxo: (OutPoint, TxOut),
    fee_utxo: Option<&(OutPoint, TxOut)>,
    option_arguments: &OptionsArguments,
    collateral_amount: u64,
    fee_amount: u64,
) -> Result<(PartiallySignedTransaction, OptionBranch), TransactionBuildError> {
    let (option_out_point, option_tx_out, option_tx_out_unblinded) = option_asset_utxo;
    let (grantor_out_point, grantor_tx_out, grantor_tx_out_unblinded) = grantor_asset_utxo;
    let (collateral_out_point, collateral_tx_out) = collateral_utxo;

    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;

    let (option_asset_id, option_token_id) = option_arguments.get_option_token_ids();
    let (grantor_asset_id, grantor_token_id) = option_arguments.get_grantor_token_ids();

    let option_token_amount = collateral_amount / option_arguments.collateral_per_contract();

    let change_recipient_script = collateral_tx_out.script_pubkey.clone();
    let contract_script = option_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut first_reissuance_tx = Input::from_prevout(option_out_point);
    first_reissuance_tx.witness_utxo = Some(option_tx_out.clone());
    first_reissuance_tx.issuance_value_amount = Some(option_token_amount);
    first_reissuance_tx.issuance_inflation_keys = None;
    first_reissuance_tx.issuance_asset_entropy = Some(option_arguments.option_token_entropy());
    first_reissuance_tx.blinded_issuance = Some(0x00);
    first_reissuance_tx.issuance_blinding_nonce =
        Some(option_tx_out_unblinded.asset_bf.into_inner());
    first_reissuance_tx.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    let mut second_reissuance_tx = Input::from_prevout(grantor_out_point);
    second_reissuance_tx.witness_utxo = Some(grantor_tx_out.clone());
    second_reissuance_tx.issuance_value_amount = Some(option_token_amount);
    second_reissuance_tx.issuance_inflation_keys = None;
    second_reissuance_tx.issuance_asset_entropy = Some(option_arguments.grantor_token_entropy());
    second_reissuance_tx.blinded_issuance = Some(0x00);
    second_reissuance_tx.issuance_blinding_nonce =
        Some(grantor_tx_out_unblinded.asset_bf.into_inner());
    second_reissuance_tx.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    let mut collateral_tx = Input::from_prevout(collateral_out_point);
    collateral_tx.witness_utxo = Some(collateral_tx_out.clone());
    collateral_tx.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    pst.add_input(first_reissuance_tx);
    pst.add_input(second_reissuance_tx);
    pst.add_input(collateral_tx);

    if let Some((fee_out_point, fee_tx_out)) = fee_utxo {
        // todo!(
        //     "Because of this issue https://github.com/BlockstreamResearch/simplicity-contracts/issues/21, alternative collaterals are not supported!"
        // )

        let mut fee_tx = Input::from_prevout(*fee_out_point);
        fee_tx.witness_utxo = Some(fee_tx_out.clone());
        fee_tx.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
        pst.add_input(fee_tx);
    }

    let mut output = Output::new_explicit(
        contract_script.clone(),
        1,
        option_token_id,
        Some((*blinding_key).into()),
    );
    output.blinder_index = Some(0);
    pst.add_output(output);

    let mut output = Output::new_explicit(
        contract_script.clone(),
        1,
        grantor_token_id,
        Some((*blinding_key).into()),
    );
    output.blinder_index = Some(1);
    pst.add_output(output);

    pst.add_output(Output::new_explicit(
        contract_script,
        collateral_amount,
        collateral_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        option_token_amount,
        option_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        option_token_amount,
        grantor_asset_id,
        None,
    ));

    let utxos = if let Some((_, fee_tx_out)) = fee_utxo {
        // todo!(
        //     "Because of this issue https://github.com/BlockstreamResearch/simplicity-contracts/issues/21, alternative collaterals are not supported!"
        // )
        let total_fee = fee_tx_out.validate_amount(fee_amount)?;

        let is_collateral_change_needed = total_collateral != collateral_amount;
        let is_fee_change_needed = total_fee != 0;

        if is_collateral_change_needed {
            pst.add_output(Output::new_explicit(
                change_recipient_script.clone(),
                total_collateral - collateral_amount,
                collateral_asset_id,
                None,
            ));
        }

        if is_fee_change_needed {
            pst.add_output(Output::new_explicit(
                change_recipient_script,
                total_fee,
                collateral_asset_id,
                None,
            ));
        }

        pst.add_output(Output::new_explicit(
            Script::new(),
            fee_amount,
            fee_tx_out.explicit_asset()?,
            None,
        ));

        vec![option_tx_out, grantor_tx_out, collateral_tx_out, fee_tx_out.clone()]
    } else {
        let is_collateral_change_needed = total_collateral != (collateral_amount + fee_amount);

        if is_collateral_change_needed {
            pst.add_output(Output::new_explicit(
                change_recipient_script,
                total_collateral - collateral_amount - fee_amount,
                collateral_asset_id,
                None,
            ));
        }

        pst.add_output(Output::new_explicit(
            Script::new(),
            fee_amount,
            collateral_asset_id,
            None,
        ));

        vec![option_tx_out, grantor_tx_out, collateral_tx_out]
    };

    let mut inp_tx_out_sec = HashMap::new();
    inp_tx_out_sec.insert(0, option_tx_out_unblinded);
    inp_tx_out_sec.insert(1, grantor_tx_out_unblinded);

    pst.blind_last(&mut thread_rng(), secp256k1::SECP256K1, &inp_tx_out_sec)?;

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    let expected_asset_amount = option_token_amount * option_arguments.settlement_per_contract();
    let option_branch = OptionBranch::Funding {
        expected_asset_amount,
    };

    Ok((pst, option_branch))
}
