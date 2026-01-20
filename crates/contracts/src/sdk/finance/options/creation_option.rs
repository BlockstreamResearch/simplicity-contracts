use crate::finance::options::OptionsArguments;
use crate::finance::options::get_options_address;

use crate::error::TransactionBuildError;

use crate::sdk::taproot_pubkey_gen::TaprootPubkeyGen;
use crate::sdk::validation::TxOutExt;

use std::collections::HashMap;

use simplicityhl::elements::secp256k1_zkp::PublicKey;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{OutPoint, Script, Sequence, TxOut, TxOutSecrets};
use simplicityhl_core::SimplicityNetwork;

/// Create a new option contract with option and grantor token issuance.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO values are not explicit
/// - The taproot pubkey generation fails
/// - Transaction blinding fails
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_lines)]
pub fn build_option_creation(
    blinding_key: &PublicKey,
    first_fee_utxo: (OutPoint, TxOut),
    second_fee_utxo: (OutPoint, TxOut),
    option_arguments: &OptionsArguments,
    issuance_asset_entropy: [u8; 32],
    fee_amount: u64,
    network: SimplicityNetwork,
) -> Result<(PartiallySignedTransaction, TaprootPubkeyGen), TransactionBuildError> {
    let (first_out_point, first_tx_out) = first_fee_utxo;
    let (second_out_point, second_tx_out) = second_fee_utxo;

    let (first_asset_id, first_value) = first_tx_out.explicit()?;
    let (second_asset_id, second_value) = second_tx_out.explicit()?;

    if first_asset_id != second_asset_id {
        return Err(TransactionBuildError::FeeUtxoAssetMismatch {
            first_script_hash: first_tx_out.script_pubkey.script_hash().to_string(),
            first_asset: first_asset_id.to_string(),
            second_script_hash: second_tx_out.script_pubkey.script_hash().to_string(),
            second_asset: second_asset_id.to_string(),
        });
    }

    let total_input_fee = first_value + second_value;

    first_tx_out.validate_amount(fee_amount.saturating_sub(second_value))?;

    let change_recipient_script = first_tx_out.script_pubkey.clone();

    let mut first_issuance_tx = Input::from_prevout(first_out_point);
    first_issuance_tx.witness_utxo = Some(first_tx_out.clone());
    first_issuance_tx.issuance_value_amount = None;
    first_issuance_tx.issuance_inflation_keys = Some(1);
    first_issuance_tx.issuance_asset_entropy = Some(issuance_asset_entropy);
    first_issuance_tx.blinded_issuance = Some(0x00);
    first_issuance_tx.sequence = Some(Sequence::ZERO);

    let mut second_issuance_tx = Input::from_prevout(second_out_point);
    second_issuance_tx.witness_utxo = Some(second_tx_out.clone());
    second_issuance_tx.issuance_value_amount = None;
    second_issuance_tx.issuance_inflation_keys = Some(1);
    second_issuance_tx.issuance_asset_entropy = Some(issuance_asset_entropy);
    second_issuance_tx.blinded_issuance = Some(0x00);
    second_issuance_tx.sequence = Some(Sequence::ZERO);

    let (first_issuance_token, first_reissuance_asset) = first_issuance_tx.issuance_ids();
    let (second_issuance_token, second_reissuance_asset) = second_issuance_tx.issuance_ids();

    let expected_option = option_arguments.get_option_token_ids();
    if (first_issuance_token, first_reissuance_asset) != expected_option {
        return Err(TransactionBuildError::OptionTokenMismatch {
            expected_token: expected_option.0.to_string(),
            expected_reissuance: expected_option.1.to_string(),
            actual_token: first_issuance_token.to_string(),
            actual_reissuance: first_reissuance_asset.to_string(),
        });
    }

    let expected_grantor = option_arguments.get_grantor_token_ids();
    if (second_issuance_token, second_reissuance_asset) != expected_grantor {
        return Err(TransactionBuildError::GrantorTokenMismatch {
            expected_token: expected_grantor.0.to_string(),
            expected_reissuance: expected_grantor.1.to_string(),
            actual_token: second_issuance_token.to_string(),
            actual_reissuance: second_reissuance_asset.to_string(),
        });
    }

    let options_taproot_pubkey_gen =
        TaprootPubkeyGen::from(option_arguments, network, &get_options_address)?;

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
