use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::OutPoint;
use simplicityhl::simplicity::elements::Script;
use simplicityhl::simplicity::elements::TxOut;

use crate::error::TransactionBuildError;
use crate::sdk::validation::TxOutExt as _;

/// Derives the Taproot address for the SMT storage contract.
///
/// This function constructs the Simplicity program committed to the provided `storage_bytes`
/// (initial state) and `path`. It then calculates the Taproot script pubkey by tweaking
/// the `storage_key` with the program's commitment (CMR) and converts it into a
/// human-readable address for the specified network.
///
/// Use this address to fund (mint) the contract by sending assets to it.
///
/// # Arguments
///
/// * `storage_key` - The internal X-only public key used for Taproot tweaking (usually an unspendable key).
/// * `storage_bytes` - The 32-byte data payload (SMT root hash) representing the initial state of the contract.
/// * `path` - The binary path in the Sparse Merkle Tree used to generate the witness data.
/// * `network` - The network parameters (e.g., Liquid Testnet, Mainnet) used to format the address.
///
///
/// # Errors
///
/// This function returns a `Result` to maintain consistency with the builder API,
/// though the current implementation is unlikely to return an `Err` variant unless
/// address generation logic changes.
///
/// # Panics
///
/// Panics if the generated script is not a valid witness program (this should theoretically
/// never happen with a valid `new_v1_p2tr_tweaked` script).
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
            change_recipient_script,
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
