use crate::error::TransactionBuildError;

use crate::sdk::PartialPset;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{Address, OutPoint, TxOut};

/// Transfer an asset to another address.
///
/// # Errors
///
/// Returns an error if:
/// - The asset or fee UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Transaction extraction or amount proof verification fails
pub fn transfer_asset(
    asset_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    to_address: &Address,
    send_amount: u64,
) -> Result<PartialPset, TransactionBuildError> {
    let (asset_out_point, asset_tx_out) = asset_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let (asset_id, total_input_asset) = asset_tx_out.explicit()?;

    if send_amount > total_input_asset {
        return Err(TransactionBuildError::SendAmountExceedsUtxo {
            send_amount,
            available: total_input_asset,
        });
    }

    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut asset_input = Input::from_prevout(asset_out_point);
    asset_input.witness_utxo = Some(asset_tx_out.clone());
    pst.add_input(asset_input);

    let mut fee_input = Input::from_prevout(fee_out_point);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    pst.add_input(fee_input);

    pst.add_output(Output::new_explicit(
        to_address.script_pubkey(),
        send_amount,
        asset_id,
        None,
    ));

    let is_asset_change_needed = total_input_asset != send_amount;

    if is_asset_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_input_asset - send_amount,
            asset_id,
            None,
        ));
    }

    Ok(PartialPset::new(
        pst,
        change_recipient_script,
        vec![asset_tx_out, fee_tx_out],
    ))
}
