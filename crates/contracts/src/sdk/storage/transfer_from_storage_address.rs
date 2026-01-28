use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::OutPoint;
use simplicityhl::simplicity::elements::Script;
use simplicityhl::simplicity::elements::TxOut;

use crate::error::TransactionBuildError;
use crate::sdk::validation::TxOutExt as _;

/// Builds a transaction to transition the SMT storage to a new state.
///
/// This function spends the existing storage UTXO and creates a new output with the
/// same value at the `new_script_pubkey`. This represents an update of the contract's
/// internal state (e.g., a new SMT root).
///
/// # Errors
///
/// Returns an error if:
/// - The input UTXOs are not explicit or amount validation fails.
pub fn transfer_asset_with_storage(
    storage_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    fee_amount: u64,
    new_script_pubkey: &Script,
) -> Result<PartiallySignedTransaction, TransactionBuildError> {
    let (storage_out_point, storage_tx_out) = storage_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let (storage_asset_id, total_input_storage_amount) = storage_tx_out.explicit()?;
    let (fee_asset_id, change_amount) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );

    let mut pst = PartiallySignedTransaction::new_v2();
    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut storage_input = Input::from_prevout(storage_out_point);
    storage_input.witness_utxo = Some(storage_tx_out.clone());
    pst.add_input(storage_input);

    let mut fee_input = Input::from_prevout(fee_out_point);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    pst.add_input(fee_input);

    pst.add_output(Output::new_explicit(
        new_script_pubkey.clone(),
        total_input_storage_amount,
        storage_asset_id,
        None,
    ));

    if change_amount > 0 {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            change_amount,
            fee_asset_id,
            None,
        ));
    }

    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, fee_asset_id)));

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[storage_tx_out, fee_tx_out])?;

    Ok(pst)
}
