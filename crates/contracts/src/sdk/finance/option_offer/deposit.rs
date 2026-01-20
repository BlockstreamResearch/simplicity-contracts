use crate::error::TransactionBuildError;
use crate::finance::option_offer::{OptionOfferArguments, get_option_offer_address};
use crate::sdk::taproot_pubkey_gen::TaprootPubkeyGen;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{OutPoint, Script, TxOut};
use simplicityhl_core::SimplicityNetwork;

/// Build PSET for user to deposit collateral and premium into the option offer covenant.
///
/// # Layout
///
/// - Input[0]: Collateral from user
/// - Input[1]: Premium from user
/// - Input[2]: Fee
/// - Output[0]: Collateral → covenant
/// - Output[1]: Premium → covenant
/// - Output[2]: Collateral change → user (if any)
/// - Output[3]: Premium change → user (if any)
/// - Output[4]: Fee change (if any)
/// - Output[5]: Fee
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (amounts and assets must be explicit)
/// - Collateral asset doesn't match expected
/// - Premium asset doesn't match expected
/// - Premium amount doesn't satisfy ratio constraint
/// - Insufficient collateral or premium for deposit
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn build_option_offer_deposit(
    collateral_utxo: (OutPoint, TxOut),
    premium_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    collateral_deposit_amount: u64,
    fee_amount: u64,
    arguments: &OptionOfferArguments,
    network: SimplicityNetwork,
) -> Result<(PartiallySignedTransaction, TaprootPubkeyGen), TransactionBuildError> {
    let (collateral_outpoint, collateral_tx_out) = collateral_utxo;
    let (premium_outpoint, premium_tx_out) = premium_utxo;
    let (fee_outpoint, fee_tx_out) = fee_utxo;

    let (fee_asset_id, fee_change) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;
    let (premium_asset_id, total_premium) = premium_tx_out.explicit()?;

    let expected_collateral = arguments.get_collateral_asset_id();
    if collateral_asset_id != expected_collateral {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_collateral.to_string(),
            actual: collateral_asset_id.to_string(),
        });
    }

    let expected_premium = arguments.get_premium_asset_id();
    if premium_asset_id != expected_premium {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_premium.to_string(),
            actual: premium_asset_id.to_string(),
        });
    }

    let premium_deposit_amount = collateral_deposit_amount
        .checked_mul(arguments.premium_per_collateral())
        .ok_or(TransactionBuildError::InsufficientSettlementAsset {
            required: u64::MAX,
            available: total_premium,
        })?;

    if collateral_deposit_amount > total_collateral {
        return Err(TransactionBuildError::InsufficientCollateral {
            required: collateral_deposit_amount,
            available: total_collateral,
        });
    }

    if premium_deposit_amount > total_premium {
        return Err(TransactionBuildError::InsufficientSettlementAsset {
            required: premium_deposit_amount,
            available: total_premium,
        });
    }

    let change_recipient_script = collateral_tx_out.script_pubkey.clone();

    let option_offer_taproot_pubkey_gen =
        TaprootPubkeyGen::from(arguments, network, &get_option_offer_address)?;

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut collateral_input = Input::from_prevout(collateral_outpoint);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    pst.add_input(collateral_input);

    let mut premium_input = Input::from_prevout(premium_outpoint);
    premium_input.witness_utxo = Some(premium_tx_out.clone());
    pst.add_input(premium_input);

    let mut fee_input = Input::from_prevout(fee_outpoint);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    pst.add_input(fee_input);

    let is_collateral_change_needed = total_collateral != collateral_deposit_amount;
    let is_premium_change_needed = total_premium != premium_deposit_amount;
    let is_fee_change_needed = fee_change != 0;

    pst.add_output(Output::new_explicit(
        option_offer_taproot_pubkey_gen.address.script_pubkey(),
        collateral_deposit_amount,
        collateral_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        option_offer_taproot_pubkey_gen.address.script_pubkey(),
        premium_deposit_amount,
        premium_asset_id,
        None,
    ));

    if is_collateral_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_collateral - collateral_deposit_amount,
            collateral_asset_id,
            None,
        ));
    }

    if is_premium_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_premium - premium_deposit_amount,
            premium_asset_id,
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

    pst.extract_tx()?.verify_tx_amt_proofs(
        secp256k1::SECP256K1,
        &[collateral_tx_out, premium_tx_out, fee_tx_out],
    )?;

    Ok((pst, option_offer_taproot_pubkey_gen))
}
