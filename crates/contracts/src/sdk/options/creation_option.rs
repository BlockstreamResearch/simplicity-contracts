use crate::sdk::taproot_pubkey_gen::TaprootPubkeyGen;
use crate::sdk::validation::TxOutExt;
use crate::{OptionsArguments, get_options_address};

use std::collections::HashMap;

use simplicityhl::elements::secp256k1_zkp::PublicKey;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{AddressParams, OutPoint, Script, Sequence, TxOut, TxOutSecrets};

/// Create a new option contract with option and grantor token issuance.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO values are not explicit
/// - The taproot pubkey generation fails
/// - Transaction blinding fails
/// - Transaction extraction or amount proof verification fails
pub fn build_option_creation(
    blinding_key: &PublicKey,
    first_fee_utxo: (OutPoint, TxOut),
    second_fee_utxo: (OutPoint, TxOut),
    option_arguments: &OptionsArguments,
    issuance_asset_entropy: [u8; 32],
    fee_amount: u64,
    address_params: &'static AddressParams,
) -> anyhow::Result<(PartiallySignedTransaction, TaprootPubkeyGen)> {
    let (first_out_point, first_tx_out) = first_fee_utxo;
    let (second_out_point, second_tx_out) = second_fee_utxo;

    let (first_asset_id, first_value) = first_tx_out.explicit()?;
    let (second_asset_id, second_value) = second_tx_out.explicit()?;

    anyhow::ensure!(
        first_asset_id == second_asset_id,
        "first and second fee UTXOs must have the same asset"
    );

    let total_input_fee = first_value + second_value;

    anyhow::ensure!(fee_amount <= total_input_fee, "fee exceeds input value");

    let change_recipient_script = first_tx_out.script_pubkey.clone();

    let mut first_issuance_tx = Input::from_prevout(first_out_point);
    first_issuance_tx.witness_utxo = Some(first_tx_out.clone());
    first_issuance_tx.issuance_value_amount = None;
    first_issuance_tx.issuance_inflation_keys = Some(1);
    first_issuance_tx.issuance_asset_entropy = Some(issuance_asset_entropy);
    first_issuance_tx.blinded_issuance = Some(0x00);
    first_issuance_tx.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    let mut second_issuance_tx = Input::from_prevout(second_out_point);
    second_issuance_tx.witness_utxo = Some(second_tx_out.clone());
    second_issuance_tx.issuance_value_amount = None;
    second_issuance_tx.issuance_inflation_keys = Some(1);
    second_issuance_tx.issuance_asset_entropy = Some(issuance_asset_entropy);
    second_issuance_tx.blinded_issuance = Some(0x00);
    second_issuance_tx.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    let (first_issuance_token, first_reissuance_asset) = first_issuance_tx.issuance_ids();
    let (second_issuance_token, second_reissuance_asset) = second_issuance_tx.issuance_ids();

    anyhow::ensure!(
        (first_issuance_token, first_reissuance_asset) == option_arguments.get_option_token_ids(),
        "first issuance token and reissuance asset must be the option token"
    );
    anyhow::ensure!(
        (second_issuance_token, second_reissuance_asset)
            == option_arguments.get_grantor_token_ids(),
        "second issuance token and reissuance asset must be the grantor token"
    );

    let options_taproot_pubkey_gen =
        TaprootPubkeyGen::from(option_arguments, address_params, &get_options_address)?;

    let mut pst = PartiallySignedTransaction::new_v2();

    pst.add_input(first_issuance_tx);
    pst.add_input(second_issuance_tx);

    let mut output = Output::new_explicit(
        options_taproot_pubkey_gen.address.script_pubkey(),
        1,
        first_reissuance_asset,
        Some((*blinding_key).into()),
    );
    output.blinder_index = Some(0);
    pst.add_output(output);

    let mut output = Output::new_explicit(
        options_taproot_pubkey_gen.address.script_pubkey(),
        1,
        second_reissuance_asset,
        Some((*blinding_key).into()),
    );
    output.blinder_index = Some(1);
    pst.add_output(output);

    pst.add_output(Output::new_explicit(
        change_recipient_script,
        total_input_fee - fee_amount,
        second_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        second_asset_id,
        None,
    ));

    let first_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: first_value,
        asset: second_asset_id,
    };
    let second_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: second_value,
        asset: second_asset_id,
    };

    let mut inp_txout_sec = HashMap::new();
    inp_txout_sec.insert(0, first_input_secrets);
    inp_txout_sec.insert(1, second_input_secrets);

    pst.blind_last(&mut thread_rng(), secp256k1::SECP256K1, &inp_txout_sec)?;

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[first_tx_out, second_tx_out])?;

    Ok((pst, options_taproot_pubkey_gen))
}
