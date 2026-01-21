use crate::error::TransactionBuildError;

use crate::sdk::PartialPset;
use crate::sdk::validation::TxOutExt;
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
) -> Result<PartialPset, TransactionBuildError> {
    if parts_to_split == 0 {
        return Err(TransactionBuildError::InvalidSplitParts);
    }

    let (out_point, tx_out) = utxo;

    let (policy_asset_id, total_policy_asset_left) = tx_out.explicit()?;

    let recipient_script = tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut input = Input::from_prevout(out_point);
    input.witness_utxo = Some(tx_out.clone());
    pst.add_input(input);

    let split_amount = total_policy_asset_left / parts_to_split;

    for _ in 0..(parts_to_split - 1) {
        pst.add_output(Output::new_explicit(
            recipient_script.clone(),
            split_amount,
            policy_asset_id,
            None,
        ));
    }

    Ok(PartialPset::new(pst, recipient_script, vec![tx_out]))
}
