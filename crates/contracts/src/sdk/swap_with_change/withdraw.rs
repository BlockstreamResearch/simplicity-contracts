use crate::swap_with_change::SwapWithChangeArguments;

use crate::error::TransactionBuildError;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{OutPoint, Script, TxOut};

/// Build PSET for user to withdraw settlement asset from the covenant.
///
/// Withdraws the full settlement asset amount - no partial withdrawal.
///
/// # Layout
///
/// - Input[0]: Settlement asset from covenant
/// - Output[0]: Settlement asset → user (full amount)
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (amounts and assets must be explicit)
/// - Settlement asset doesn't match expected
/// - Transaction extraction or amount proof verification fails
pub fn build_swap_withdraw(
    settlement_covenant_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    fee_amount: u64,
    arguments: &SwapWithChangeArguments,
    user_recipient_script: Script,
) -> Result<PartiallySignedTransaction, TransactionBuildError> {
    let (settlement_outpoint, settlement_tx_out) = settlement_covenant_utxo;
    let (fee_outpoint, fee_tx_out) = fee_utxo;

    let (fee_asset_id, fee_change) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (settlement_asset_id, settlement_amount) = settlement_tx_out.explicit()?;

    let expected_settlement = arguments.get_settlement_asset_id();
    if settlement_asset_id != expected_settlement {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_settlement.to_string(),
            actual: settlement_asset_id.to_string(),
        });
    }

    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut settlement_input = Input::from_prevout(settlement_outpoint);
    settlement_input.witness_utxo = Some(settlement_tx_out.clone());
    pst.add_input(settlement_input);

    let mut fee_input = Input::from_prevout(fee_outpoint);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    pst.add_input(fee_input);

    let is_fee_change_needed = fee_change != 0;

    pst.add_output(Output::new_explicit(
        user_recipient_script,
        settlement_amount,
        settlement_asset_id,
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
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[settlement_tx_out, fee_tx_out])?;

    Ok(pst)
}
