use crate::error::TransactionBuildError;
use crate::sdk::taproot_pubkey_gen::get_random_seed;
use crate::sdk::validation::TxOutExt;

use crate::sdk::finalization::PartialPset;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::PublicKey;
use simplicityhl::elements::{OutPoint, TxOut, TxOutSecrets};
use std::collections::HashMap;

/// Issue a new asset with given amount.
///
/// # Errors
///
/// Returns an error if:
/// - The fee UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Transaction blinding fails
/// - Transaction extraction or amount proof verification fails
pub fn issue_asset(
    blinding_key: &PublicKey,
    fee_utxo: (OutPoint, TxOut),
    issue_amount: u64,
) -> Result<PartialPset, TransactionBuildError> {
    let (fee_out_point, fee_tx_out) = fee_utxo;
    let fee_asset_id = fee_tx_out.explicit_asset()?;

    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut issuance_tx = Input::from_prevout(fee_out_point);
    issuance_tx.witness_utxo = Some(fee_tx_out.clone());
    issuance_tx.issuance_value_amount = Some(issue_amount);
    issuance_tx.issuance_inflation_keys = Some(1);
    issuance_tx.issuance_asset_entropy = Some(get_random_seed());
    issuance_tx.blinded_issuance = Some(0x00);

    let (asset_id, reissuance_asset_id) = issuance_tx.issuance_ids();

    pst.add_input(issuance_tx);

    let mut inp_txout_sec: HashMap<usize, TxOutSecrets> = HashMap::new();
    inp_txout_sec.insert(
        0,
        TxOutSecrets {
            asset_bf: AssetBlindingFactor::zero(),
            value_bf: ValueBlindingFactor::zero(),
            //TODO: replace placeholder value
            value: 0,
            asset: fee_asset_id,
        },
    );

    // Output with reissuance token
    let mut output = Output::new_explicit(
        change_recipient_script.clone(),
        1,
        reissuance_asset_id,
        Some((*blinding_key).into()),
    );
    output.blinder_index = Some(0);
    pst.add_output(output);

    // Output with issuance token
    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        issue_amount,
        asset_id,
        None,
    ));

    Ok(
        PartialPset::new(pst, change_recipient_script, vec![fee_tx_out])
            .inp_tx_out_secrets(inp_txout_sec),
    )
}
