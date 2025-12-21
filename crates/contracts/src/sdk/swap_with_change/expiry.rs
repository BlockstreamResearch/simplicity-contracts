use crate::swap_with_change::SwapWithChangeArguments;

use crate::error::TransactionBuildError;

use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{LockTime, OutPoint, Script, Sequence, TxOut};

/// Build PSET for user to reclaim collateral after expiry.
///
/// Only works after `EXPIRY_TIME` has passed.
/// Withdraws the full collateral amount - no partial withdrawal.
///
/// # Layout
///
/// - Input[0]: Collateral from covenant
/// - Output[0]: Collateral → user (full amount)
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (amounts and assets must be explicit)
/// - Collateral asset doesn't match expected
/// - Transaction extraction or amount proof verification fails
pub fn build_swap_expiry(
    collateral_covenant_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    fee_amount: u64,
    arguments: &SwapWithChangeArguments,
    user_recipient_script: Script,
) -> Result<PartiallySignedTransaction, TransactionBuildError> {
    let (collateral_outpoint, collateral_tx_out) = collateral_covenant_utxo;
    let (fee_outpoint, fee_tx_out) = fee_utxo;

    let (fee_asset_id, fee_change) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, collateral_amount) = collateral_tx_out.explicit()?;

    let expected_collateral = arguments.get_collateral_asset_id();
    if collateral_asset_id != expected_collateral {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_collateral.to_string(),
            actual: collateral_asset_id.to_string(),
        });
    }

    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    pst.global.tx_data.fallback_locktime = Some(LockTime::from_time(arguments.expiry_time)?);

    let mut collateral_input = Input::from_prevout(collateral_outpoint);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    collateral_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(collateral_input);

    let mut fee_input = Input::from_prevout(fee_outpoint);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    fee_input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(fee_input);

    let is_fee_change_needed = fee_change != 0;

    pst.add_output(Output::new_explicit(
        user_recipient_script,
        collateral_amount,
        collateral_asset_id,
        None,
    ));

    if is_fee_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script,
            fee_change,
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

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[collateral_tx_out, fee_tx_out])?;

    Ok(pst)
}
