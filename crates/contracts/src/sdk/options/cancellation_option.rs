use crate::options::OptionsArguments;
use crate::options::build_witness::OptionBranch;

use crate::error::TransactionBuildError;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{OutPoint, Script, Sequence, TxOut};

/// Cancel an option contract by burning option and grantor tokens.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Insufficient collateral in comparison to amount of option and grantor tokens to burn
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_lines)]
pub fn build_option_cancellation(
    collateral_utxo: (OutPoint, TxOut),
    option_asset_utxo: (OutPoint, TxOut),
    grantor_asset_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    option_arguments: &OptionsArguments,
    amount_to_burn: u64,
    fee_amount: u64,
) -> Result<(PartiallySignedTransaction, OptionBranch), TransactionBuildError> {
    let (collateral_out_point, collateral_tx_out) = collateral_utxo;
    let (option_out_point, option_tx_out) = option_asset_utxo;
    let (grantor_out_point, grantor_tx_out) = grantor_asset_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let (fee_asset_id, total_lbtc_left) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;

    let collateral_amount_to_withdraw = amount_to_burn * option_arguments.collateral_per_contract;

    if collateral_amount_to_withdraw > total_collateral {
        return Err(TransactionBuildError::InsufficientCollateral {
            required: collateral_amount_to_withdraw,
            available: total_collateral,
        });
    }

    let (option_token_id, total_option_token_amount) = option_tx_out.explicit()?;
    let (grantor_token_id, total_grantor_token_amount) = grantor_tx_out.explicit()?;

    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut collateral_input = Input::from_prevout(collateral_out_point);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    collateral_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(collateral_input);

    let mut option_input = Input::from_prevout(option_out_point);
    option_input.witness_utxo = Some(option_tx_out.clone());
    option_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(option_input);

    let mut grantor_input = Input::from_prevout(grantor_out_point);
    grantor_input.witness_utxo = Some(grantor_tx_out.clone());
    grantor_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(grantor_input);

    let mut fee_input = Input::from_prevout(fee_out_point);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    fee_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(fee_input);

    let is_collateral_change_needed = total_collateral != collateral_amount_to_withdraw;
    let is_option_change_needed = total_option_token_amount != amount_to_burn;
    let is_grantor_change_needed = total_grantor_token_amount != amount_to_burn;
    let is_lbtc_change_needed = total_lbtc_left != 0;

    if is_collateral_change_needed {
        pst.add_output(Output::new_explicit(
            collateral_tx_out.script_pubkey.clone(),
            total_collateral - collateral_amount_to_withdraw,
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
        Script::new_op_return(b"burn"),
        amount_to_burn,
        grantor_token_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        collateral_amount_to_withdraw,
        collateral_asset_id,
        None,
    ));

    if is_option_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_option_token_amount - amount_to_burn,
            option_token_id,
            None,
        ));
    }

    if is_grantor_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_grantor_token_amount - amount_to_burn,
            grantor_token_id,
            None,
        ));
    }

    if is_lbtc_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script,
            total_lbtc_left,
            fee_asset_id,
            None,
        ));
    }

    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, fee_asset_id)));

    pst.extract_tx()?.verify_tx_amt_proofs(
        secp256k1::SECP256K1,
        &[collateral_tx_out, option_tx_out, grantor_tx_out, fee_tx_out],
    )?;

    let option_branch = OptionBranch::Cancellation {
        is_change_needed: is_collateral_change_needed,
        amount_to_burn,
        collateral_amount_to_withdraw,
    };

    Ok((pst, option_branch))
}
