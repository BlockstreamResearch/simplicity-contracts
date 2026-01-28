use simplicityhl::elements::TxOut;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::schnorr::XOnlyPublicKey;
use simplicityhl::simplicity::elements::OutPoint;
use simplicityhl::simplicity::elements::Script;
use simplicityhl::simplicity::elements::taproot::TaprootSpendInfo;

use crate::error::TransactionBuildError;
use crate::sdk::validation::TxOutExt as _;
use crate::smt_storage::{
    DEPTH, SparseMerkleTree, get_smt_storage_compiled_program, smt_storage_taproot_spend_info,
};

/// Creates a transaction to fund a Sparse Merkle Tree (SMT) storage contract.
///
/// This function calculates the Taproot address for the SMT contract based on the provided
/// `storage_bytes` and `path`, and then creates a transaction that locks
/// the `collateral_amount` into this address.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (expects explicit amounts).
/// - Transaction extraction or amount proof verification fails.
pub fn build_smt_mint(
    storage_key: &XOnlyPublicKey,
    collateral_utxo: (OutPoint, TxOut),
    collateral_amount: u64,
    fee_amount: u64,
    storage_bytes: &[u8; 32],
    path: [bool; DEPTH],
) -> Result<PartiallySignedTransaction, TransactionBuildError> {
    let (collateral_out_point, collateral_tx_out) = collateral_utxo;

    // TODO Change this validation to another func
    let (collateral_asset_id, change_amount) = (
        collateral_tx_out.explicit_asset()?,
        collateral_tx_out.validate_amount(collateral_amount + fee_amount)?,
    );

    // Build script and spend info
    let mut smt = SparseMerkleTree::new();
    let merkle_hashes = smt.update(storage_bytes, path);

    let merkle_data = std::array::from_fn(|i| (merkle_hashes[DEPTH - i - 1], path[DEPTH - i - 1]));

    let program = get_smt_storage_compiled_program();
    let cmr = program.commit().cmr();

    let mint_spend_info: TaprootSpendInfo =
        smt_storage_taproot_spend_info(*storage_key, storage_bytes, &merkle_data, cmr);

    let mint_script_pubkey = Script::new_v1_p2tr_tweaked(mint_spend_info.output_key());
    let change_recipient_script = collateral_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut collateral_input = Input::from_prevout(collateral_out_point);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    pst.add_input(collateral_input);

    pst.add_output(Output::new_explicit(
        mint_script_pubkey,
        collateral_amount,
        collateral_asset_id,
        None,
    ));

    if change_amount > 0 {
        pst.add_output(Output::new_explicit(
            change_recipient_script,
            change_amount,
            collateral_asset_id,
            None,
        ));
    }

    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        collateral_asset_id,
    )));

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[collateral_tx_out])?;

    Ok(pst)
}
