use crate::finance::options::OptionsArguments;
use crate::finance::options::build_witness::{OptionBranch, blinding_factors_from_secrets};

use crate::error::TransactionBuildError;

use crate::sdk::PartialPset;
use crate::sdk::validation::TxOutExt;

use std::collections::HashMap;

use simplicityhl::elements::bitcoin::secp256k1::Keypair;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::SECP256K1;
use simplicityhl::elements::{OutPoint, Sequence, Transaction, TxOut, TxOutSecrets};

pub type ExpectedAssetAmount = u64;

/// Fund an option contract by depositing collateral and reissuing tokens.
///
/// Returns a tuple of (PST, `OptionBranch::Funding`) with all blinding factors extracted.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (ALL amounts and assets are expected to be explicit)
/// - Transaction blinding fails
/// - Transaction extraction or amount proof verification fails
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::similar_names
)]
pub fn build_option_funding(
    blinding_keypair: &Keypair,
    option_asset_utxo: (OutPoint, TxOut, TxOutSecrets),
    grantor_asset_utxo: (OutPoint, TxOut, TxOutSecrets),
    collateral_utxo: (OutPoint, TxOut),
    fee_utxo: Option<&(OutPoint, TxOut)>,
    option_arguments: &OptionsArguments,
    collateral_amount: u64,
) -> Result<(PartialPset, ExpectedAssetAmount), TransactionBuildError> {
    let blinding_key = blinding_keypair.public_key();

    let (option_out_point, option_tx_out, input_option_secrets) = option_asset_utxo;
    let (grantor_out_point, grantor_tx_out, input_grantor_secrets) = grantor_asset_utxo;

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
    first_reissuance_tx.issuance_blinding_nonce = Some(input_option_secrets.asset_bf.into_inner());
    first_reissuance_tx.sequence = Some(Sequence::ZERO);

    let mut second_reissuance_tx = Input::from_prevout(grantor_out_point);
    second_reissuance_tx.witness_utxo = Some(grantor_tx_out.clone());
    second_reissuance_tx.issuance_value_amount = Some(option_token_amount);
    second_reissuance_tx.issuance_inflation_keys = None;
    second_reissuance_tx.issuance_asset_entropy = Some(option_arguments.grantor_token_entropy());
    second_reissuance_tx.blinded_issuance = Some(0x00);
    second_reissuance_tx.issuance_blinding_nonce =
        Some(input_grantor_secrets.asset_bf.into_inner());
    second_reissuance_tx.sequence = Some(Sequence::ZERO);

    let mut collateral_tx = Input::from_prevout(collateral_out_point);
    collateral_tx.witness_utxo = Some(collateral_tx_out.clone());
    collateral_tx.sequence = Some(Sequence::ZERO);

    pst.add_input(first_reissuance_tx);
    pst.add_input(second_reissuance_tx);
    pst.add_input(collateral_tx);

    if let Some((fee_out_point, fee_tx_out)) = fee_utxo {
        let mut fee_tx = Input::from_prevout(*fee_out_point);
        fee_tx.witness_utxo = Some(fee_tx_out.clone());
        fee_tx.sequence = Some(Sequence::ZERO);
        pst.add_input(fee_tx);
    }

    let mut output = Output::new_explicit(
        contract_script.clone(),
        1,
        option_token_id,
        Some(blinding_key.into()),
    );
    output.blinder_index = Some(0);
    pst.add_output(output);

    let mut output = Output::new_explicit(
        contract_script.clone(),
        1,
        grantor_token_id,
        Some(blinding_key.into()),
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
        let is_collateral_change_needed = total_collateral != collateral_amount;

        if is_collateral_change_needed {
            pst.add_output(Output::new_explicit(
                change_recipient_script.clone(),
                total_collateral - collateral_amount,
                collateral_asset_id,
                None,
            ));
        }

        vec![
            option_tx_out,
            grantor_tx_out,
            collateral_tx_out,
            fee_tx_out.clone(),
        ]
    } else {
        vec![option_tx_out, grantor_tx_out, collateral_tx_out]
    };

    let mut inp_tx_out_sec = HashMap::new();
    inp_tx_out_sec.insert(0, input_option_secrets);
    inp_tx_out_sec.insert(1, input_grantor_secrets);

    let expected_asset_amount = option_token_amount * option_arguments.settlement_per_contract();

    let non_finalized_pset =
        PartialPset::new(pst, change_recipient_script, utxos).inp_tx_out_secrets(inp_tx_out_sec);

    Ok((non_finalized_pset, expected_asset_amount))
}

/// Extracts the funding option branch with blinding factors from a blinded transaction.
///
/// This function should be called after creating a draft transaction using
/// `PartialPset::create_draft_transaction()` to extract the blinding factors
/// needed for the Simplicity witness.
///
/// # Arguments
///
/// * `blinding_keypair` - Keypair used for blinding the outputs
/// * `input_option_secrets` - Secrets for the option token input
/// * `input_grantor_secrets` - Secrets for the grantor token input
/// * `expected_asset_amount` - Expected settlement asset amount from `build_option_funding`
/// * `tx` - The draft transaction (blinded but not finalized)
///
/// # Errors
///
/// Returns an error if unblinding the outputs fails.
#[allow(clippy::similar_names)]
pub fn extract_funding_option_branch(
    blinding_keypair: &Keypair,
    non_finalized_pset: &PartialPset,
    tx: &Transaction,
    expected_asset_amount: ExpectedAssetAmount,
) -> Result<OptionBranch, TransactionBuildError> {
    let (
        (input_option_secrets, output_option_secrets),
        (input_grantor_secrets, output_grantor_secrets),
    ) = if let Some(inp_tx_out_sec) = non_finalized_pset.get_inp_tx_out_sec() {
        // option secrets
        let key1 = 0;
        let in1 =
            *inp_tx_out_sec
                .get(&key1)
                .ok_or_else(|| TransactionBuildError::NoTxOutSecret {
                    description: Some("input_option_secrets".into()),
                    id: key1,
                })?;
        let out1 = tx
            .output
            .get(key1)
            .ok_or_else(|| TransactionBuildError::NoTxOut {
                description: Some("output_option".into()),
                id: key1,
            })?;
        let out1 = out1.unblind(SECP256K1, blinding_keypair.secret_key())?;

        // grantor secrets
        let key2 = 1;
        let in2 =
            *inp_tx_out_sec
                .get(&key2)
                .ok_or_else(|| TransactionBuildError::NoTxOutSecret {
                    description: Some("output_grantor_secrets".into()),
                    id: key2,
                })?;
        let out2 = tx
            .output
            .get(key2)
            .ok_or_else(|| TransactionBuildError::NoTxOut {
                description: Some("output_grantor".into()),
                id: key2,
            })?;
        let out2 = out2.unblind(SECP256K1, blinding_keypair.secret_key())?;

        Ok(((in1, out1), (in2, out2)))
    } else {
        Err(TransactionBuildError::MissingTxOutSecrets)
    }?;

    let (input_option_abf, input_option_vbf) = blinding_factors_from_secrets(&input_option_secrets);
    let (input_grantor_abf, input_grantor_vbf) =
        blinding_factors_from_secrets(&input_grantor_secrets);

    let (output_option_abf, output_option_vbf) =
        blinding_factors_from_secrets(&output_option_secrets);
    let (output_grantor_abf, output_grantor_vbf) =
        blinding_factors_from_secrets(&output_grantor_secrets);

    let option_branch = OptionBranch::Funding {
        expected_asset_amount,
        input_option_abf,
        input_option_vbf,
        input_grantor_abf,
        input_grantor_vbf,
        output_option_abf,
        output_option_vbf,
        output_grantor_abf,
        output_grantor_vbf,
    };
    Ok(option_branch)
}
