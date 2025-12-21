use crate::error::TransactionBuildError;
use crate::sdk::taproot_pubkey_gen::TaprootPubkeyGen;
use crate::sdk::validation::TxOutExt;
use crate::swap_with_change::{SwapWithChangeArguments, get_swap_with_change_address};

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{AddressParams, OutPoint, Script, TxOut};

/// Build PSET for user to deposit collateral into the swap covenant.
///
/// # Layout
///
/// - Input[0]: Collateral from user
/// - Input[1]: Fee
/// - Output[0]: Collateral → covenant
/// - Output[1]: Collateral change → user (if any)
/// - Output[2]: Fee change (if any)
/// - Output[3]: Fee
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (amounts and assets must be explicit)
/// - Collateral asset doesn't match expected
/// - Insufficient collateral for deposit
/// - Transaction extraction or amount proof verification fails
pub fn build_swap_deposit(
    collateral_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    deposit_amount: u64,
    fee_amount: u64,
    arguments: &SwapWithChangeArguments,
    address_params: &'static AddressParams,
) -> Result<(PartiallySignedTransaction, TaprootPubkeyGen), TransactionBuildError> {
    let (collateral_outpoint, collateral_tx_out) = collateral_utxo;
    let (fee_outpoint, fee_tx_out) = fee_utxo;

    let (fee_asset_id, fee_change) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;

    let expected_collateral = arguments.get_collateral_asset_id();
    if collateral_asset_id != expected_collateral {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_collateral.to_string(),
            actual: collateral_asset_id.to_string(),
        });
    }

    if deposit_amount > total_collateral {
        return Err(TransactionBuildError::InsufficientCollateral {
            required: deposit_amount,
            available: total_collateral,
        });
    }

    let change_recipient_script = collateral_tx_out.script_pubkey.clone();

    let swap_taproot_pubkey_gen =
        TaprootPubkeyGen::from(arguments, address_params, &get_swap_with_change_address)?;

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut collateral_input = Input::from_prevout(collateral_outpoint);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    pst.add_input(collateral_input);

    let mut fee_input = Input::from_prevout(fee_outpoint);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    pst.add_input(fee_input);

    let is_collateral_change_needed = total_collateral != deposit_amount;
    let is_fee_change_needed = fee_change != 0;

    pst.add_output(Output::new_explicit(
        swap_taproot_pubkey_gen.address.script_pubkey(),
        deposit_amount,
        collateral_asset_id,
        None,
    ));

    if is_collateral_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_collateral - deposit_amount,
            collateral_asset_id,
            None,
        ));
    }

    if is_fee_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script,
            fee_change,
            fee_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        fee_asset_id,
        None,
    ));

    pst.extract_tx()?
        .verify_tx_amt_proofs(secp256k1::SECP256K1, &[collateral_tx_out, fee_tx_out])?;

    Ok((pst, swap_taproot_pubkey_gen))
}
