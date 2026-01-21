use crate::error::TransactionBuildError;

use crate::sdk::PartialPset;
use crate::sdk::validation::TxOutExt;

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
) -> Result<PartialPset, TransactionBuildError> {
    let (out_point, tx_out) = utxo;

    let asset_id = tx_out.explicit_asset()?;

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

    Ok(PartialPset::new(pst, change_recipient_script, vec![tx_out]))
}
