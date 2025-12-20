use crate::error::TransactionBuildError;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{Address, OutPoint, TxOut};

/// Transfer native asset (LBTC) to another address.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Transaction extraction or amount proof verification fails
pub fn transfer_native(
    utxo: (OutPoint, TxOut),
    to_address: &Address,
    amount_to_send: u64,
    fee_amount: u64,
) -> Result<PartiallySignedTransaction, TransactionBuildError> {
    let (out_point, tx_out) = utxo;

    let (asset_id, total_lbtc_left) = (
        tx_out.explicit_asset()?,
        tx_out.validate_amount(amount_to_send + fee_amount)?,
    );

    let change_recipient_script = tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut input = Input::from_prevout(out_point);
    input.witness_utxo = Some(tx_out.clone());
    pst.add_input(input);

    pst.add_output(Output::new_explicit(
        to_address.script_pubkey(),
        amount_to_send,
        asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient_script,
        total_lbtc_left,
        asset_id,
        None,
    ));

    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, asset_id)));

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[tx_out])?;

    Ok(pst)
}
