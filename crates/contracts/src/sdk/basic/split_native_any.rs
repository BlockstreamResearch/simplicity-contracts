use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{OutPoint, TxOut};

/// Split a native UTXO into any number of outputs + change.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Transaction extraction or amount proof verification fails
pub fn split_native_any(
    utxo: (OutPoint, TxOut),
    parts_to_split: u64,
    fee_amount: u64,
) -> anyhow::Result<PartiallySignedTransaction> {
    anyhow::ensure!(parts_to_split > 0, "parts_to_split must be greater than 0");

    let (out_point, tx_out) = utxo;

    let (asset_id, total_lbtc_left) = (
        tx_out.explicit_asset()?,
        tx_out.validate_amount(fee_amount)?,
    );

    let recipient_script = tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut input = Input::from_prevout(out_point);
    input.witness_utxo = Some(tx_out.clone());
    pst.add_input(input);

    let split_amount = total_lbtc_left / parts_to_split;
    let change_amount = total_lbtc_left - split_amount * (parts_to_split - 1);

    for _ in 0..(parts_to_split - 1) {
        pst.add_output(Output::new_explicit(
            recipient_script.clone(),
            split_amount,
            asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        recipient_script,
        change_amount,
        asset_id,
        None,
    ));

    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, asset_id)));

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[tx_out])?;

    Ok(pst)
}
