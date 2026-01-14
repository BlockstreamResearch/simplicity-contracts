use crate::error::TransactionBuildError;

use std::collections::HashMap;

use crate::sdk::finalization::PartialPset;
use simplicityhl::elements::hashes::sha256::Midstate;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::PublicKey;
use simplicityhl::elements::{AssetId, OutPoint, TxOut, TxOutSecrets};

/// Reissue an existing asset by spending its reissuance token.
///
/// # Errors
///
/// Returns an error if:
/// - The fee UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - The reissuance UTXO unblinding fails
/// - Transaction blinding fails
/// - Transaction extraction or amount proof verification fails
pub fn reissue_asset(
    blinding_key: &PublicKey,
    reissue_utxo: (OutPoint, TxOut),
    reissue_utxo_secrets: TxOutSecrets,
    fee_utxo: (OutPoint, TxOut),
    reissue_amount: u64,
    asset_entropy: Midstate,
) -> Result<PartialPset, TransactionBuildError> {
    let (reissue_out_point, reissue_tx_out) = reissue_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let asset_bf = reissue_utxo_secrets.asset_bf;

    let asset_id = AssetId::from_entropy(asset_entropy);
    let reissuance_asset_id = AssetId::reissuance_token_from_entropy(asset_entropy, false);

    let mut inp_txout_sec: HashMap<usize, TxOutSecrets> = HashMap::new();

    let mut pst = PartiallySignedTransaction::new_v2();

    {
        let mut reissuance_tx = Input::from_prevout(reissue_out_point);
        reissuance_tx.witness_utxo = Some(reissue_tx_out.clone());
        reissuance_tx.issuance_value_amount = Some(reissue_amount);
        reissuance_tx.issuance_inflation_keys = None;
        reissuance_tx.issuance_asset_entropy = Some(asset_entropy.to_byte_array());

        reissuance_tx.blinded_issuance = Some(0x00);
        reissuance_tx.issuance_blinding_nonce = Some(asset_bf.into_inner());

        pst.add_input(reissuance_tx);

        inp_txout_sec.insert(0, reissue_utxo_secrets);
    }

    {
        let mut fee_input = Input::from_prevout(fee_out_point);
        fee_input.witness_utxo = Some(fee_tx_out.clone());

        pst.add_input(fee_input);
    }

    {
        let mut output = Output::new_explicit(
            change_recipient_script.clone(),
            1,
            reissuance_asset_id,
            Some((*blinding_key).into()),
        );
        output.blinder_index = Some(0);

        pst.add_output(output);
    }

    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        reissue_amount,
        asset_id,
        None,
    ));

    Ok(PartialPset::new(
        pst,
        change_recipient_script,
        vec![reissue_tx_out, fee_tx_out],
    )
    .inp_tx_out_secrets(inp_txout_sec))
}
