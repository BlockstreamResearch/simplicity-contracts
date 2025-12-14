use crate::OptionsArguments;
use crate::build_witness::OptionBranch;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{LockTime, OutPoint, Script, Sequence, TxOut};

/// Withdraw collateral at option expiry by burning grantor tokens.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Insufficient collateral in comparison to amount of grantor tokens to burn
/// - Transaction extraction or amount proof verification fails
pub fn build_option_expiry(
    collateral_utxo: (OutPoint, TxOut),
    grantor_asset_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    grantor_token_amount_to_burn: u64,
    fee_amount: u64,
    option_arguments: &OptionsArguments,
) -> anyhow::Result<(PartiallySignedTransaction, OptionBranch)> {
    let (collateral_out_point, collateral_tx_out) = collateral_utxo;
    let (grantor_out_point, grantor_tx_out) = grantor_asset_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let (fee_asset_id, total_lbtc_left) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;
    let (grantor_token_id, total_grantor_token_amount) = grantor_tx_out.explicit()?;

    let (expected_grantor_token_id, _) = option_arguments.get_grantor_token_ids();

    anyhow::ensure!(
        grantor_token_id == expected_grantor_token_id,
        "grantor-asset-utxo must be the grantor token"
    );

    let collateral_amount =
        grantor_token_amount_to_burn.saturating_mul(option_arguments.collateral_per_contract);

    anyhow::ensure!(
        collateral_amount <= total_collateral,
        "collateral exceeds input value"
    );

    let change_recipient_script = fee_tx_out.script_pubkey.clone();
    let contract_script = collateral_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.global.tx_data.fallback_locktime = Some(LockTime::from_time(option_arguments.start_time)?);

    let mut collateral_input = Input::from_prevout(collateral_out_point);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    collateral_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(collateral_input);

    let mut grantor_input = Input::from_prevout(grantor_out_point);
    grantor_input.witness_utxo = Some(grantor_tx_out.clone());
    grantor_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(grantor_input);

    let mut fee_input = Input::from_prevout(fee_out_point);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    fee_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(fee_input);

    let is_collateral_change_needed = total_collateral != collateral_amount;
    let is_grantor_change_needed = total_grantor_token_amount != grantor_token_amount_to_burn;
    let is_lbtc_change_needed = total_lbtc_left != 0;

    if is_collateral_change_needed {
        pst.add_output(Output::new_explicit(
            contract_script,
            total_collateral - collateral_amount,
            collateral_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        Script::new_op_return(b"burn"),
        grantor_token_amount_to_burn,
        grantor_token_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        collateral_amount,
        collateral_asset_id,
        None,
    ));

    if is_grantor_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_grantor_token_amount - grantor_token_amount_to_burn,
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

    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        fee_asset_id,
        None,
    ));

    pst.extract_tx()?.verify_tx_amt_proofs(
        secp256k1::SECP256K1,
        &[collateral_tx_out, grantor_tx_out, fee_tx_out],
    )?;

    let option_branch = OptionBranch::Expiry {
        is_change_needed: is_collateral_change_needed,
        grantor_token_amount_to_burn,
        collateral_amount_to_withdraw: collateral_amount,
    };

    Ok((pst, option_branch))
}
