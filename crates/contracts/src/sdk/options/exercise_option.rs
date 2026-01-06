use crate::options::OptionsArguments;
use crate::options::build_witness::OptionBranch;

use crate::error::TransactionBuildError;

use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{LockTime, OutPoint, Script, Sequence, TxOut};

/// Exercise an option by burning option tokens to withdraw collateral.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Insufficient collateral or settlement asset
/// - Settlement asset id mismatch
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_lines)]
pub fn build_option_exercise(
    collateral_utxo: (OutPoint, TxOut),
    option_asset_utxo: (OutPoint, TxOut),
    asset_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    amount_to_burn: u64,
    fee_amount: u64,
    option_arguments: &OptionsArguments,
) -> Result<(PartiallySignedTransaction, OptionBranch), TransactionBuildError> {
    let (collateral_out_point, collateral_tx_out) = collateral_utxo;
    let (option_out_point, option_tx_out) = option_asset_utxo;
    let (asset_out_point, asset_tx_out) = asset_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let (fee_asset_id, total_lbtc_left) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;
    let (option_token_id, total_option_token_amount) = option_tx_out.explicit()?;
    let (settlement_asset_id, total_asset_amount) = asset_tx_out.explicit()?;

    let collateral_amount_to_get = amount_to_burn * option_arguments.collateral_per_contract();
    let asset_amount_to_pay = amount_to_burn * option_arguments.settlement_per_contract();

    if collateral_amount_to_get > total_collateral {
        return Err(TransactionBuildError::InsufficientCollateral {
            required: collateral_amount_to_get,
            available: total_collateral,
        });
    }
    if asset_amount_to_pay > total_asset_amount {
        return Err(TransactionBuildError::InsufficientSettlementAsset {
            required: asset_amount_to_pay,
            available: total_asset_amount,
        });
    }

    let change_recipient_script = fee_tx_out.script_pubkey.clone();
    let contract_script = collateral_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.global.tx_data.fallback_locktime =
        Some(LockTime::from_time(option_arguments.start_time())?);

    let mut collateral_input = Input::from_prevout(collateral_out_point);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    collateral_input.sequence = Some(Sequence::ZERO);
    pst.add_input(collateral_input);

    let mut option_input = Input::from_prevout(option_out_point);
    option_input.witness_utxo = Some(option_tx_out.clone());
    option_input.sequence = Some(Sequence::ZERO);
    pst.add_input(option_input);

    let mut asset_input = Input::from_prevout(asset_out_point);
    asset_input.witness_utxo = Some(asset_tx_out.clone());
    asset_input.sequence = Some(Sequence::ZERO);
    pst.add_input(asset_input);

    let mut fee_input = Input::from_prevout(fee_out_point);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    fee_input.sequence = Some(Sequence::ZERO);
    pst.add_input(fee_input);

    let is_collateral_change_needed = total_collateral != collateral_amount_to_get;
    let is_option_token_change_needed = total_option_token_amount != amount_to_burn;
    let is_asset_change_needed = total_asset_amount != asset_amount_to_pay;
    let is_lbtc_change_needed = total_lbtc_left != 0;

    if is_collateral_change_needed {
        pst.add_output(Output::new_explicit(
            contract_script.clone(),
            total_collateral - collateral_amount_to_get,
            collateral_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        Script::new_op_return(b"burn"),
        amount_to_burn,
        option_token_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        contract_script,
        asset_amount_to_pay,
        settlement_asset_id,
        None,
    ));

    if is_option_token_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_option_token_amount - amount_to_burn,
            option_token_id,
            None,
        ));
    }

    if is_asset_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_asset_amount - asset_amount_to_pay,
            settlement_asset_id,
            None,
        ));
    }

    if is_lbtc_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_lbtc_left,
            fee_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        change_recipient_script,
        collateral_amount_to_get,
        collateral_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        fee_asset_id,
        None,
    ));

    pst.extract_tx()?.verify_tx_amt_proofs(
        secp256k1::SECP256K1,
        &[collateral_tx_out, option_tx_out, asset_tx_out, fee_tx_out],
    )?;

    Ok((
        pst,
        OptionBranch::Exercise {
            is_change_needed: is_collateral_change_needed,
            amount_to_burn,
            collateral_amount_to_get,
            asset_amount: asset_amount_to_pay,
        },
    ))
}
