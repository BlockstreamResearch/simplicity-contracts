use crate::swap_with_change::SwapWithChangeArguments;
use crate::swap_with_change::build_witness::SwapWithChangeBranch;

use crate::error::TransactionBuildError;

use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{OutPoint, Script, TxOut};

/// Build PSET for counterparty to swap settlement asset for collateral.
///
/// # Layout
///
/// With change (partial swap):
/// - Input[0]: Collateral from covenant
/// - Output[0]: Collateral change → covenant
/// - Output[1]: Settlement asset → covenant
/// - Output[2]: Collateral → counterparty
///
/// Without change (full swap):
/// - Input[0]: Collateral from covenant
/// - Output[0]: Settlement asset → covenant
/// - Output[1]: Collateral → counterparty
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount validation fails (amounts and assets must be explicit)
/// - Insufficient collateral in covenant
/// - Insufficient settlement asset from counterparty
/// - Settlement amount doesn't satisfy constraint: `settlement` = `settlement_per_contract` * `collateral`
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_lines)]
pub fn build_swap_exercise(
    collateral_covenant_utxo: (OutPoint, TxOut),
    settlement_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    collateral_amount_to_receive: u64,
    fee_amount: u64,
    arguments: &SwapWithChangeArguments,
    counterparty_recipient_script: Script,
) -> Result<(PartiallySignedTransaction, SwapWithChangeBranch), TransactionBuildError> {
    let (collateral_outpoint, collateral_tx_out) = collateral_covenant_utxo;
    let (settlement_outpoint, settlement_tx_out) = settlement_utxo;
    let (fee_outpoint, fee_tx_out) = fee_utxo;

    let (fee_asset_id, fee_change) = (
        fee_tx_out.explicit_asset()?,
        fee_tx_out.validate_amount(fee_amount)?,
    );
    let (collateral_asset_id, total_collateral) = collateral_tx_out.explicit()?;
    let (settlement_asset_id, total_settlement) = settlement_tx_out.explicit()?;

    let expected_collateral = arguments.get_collateral_asset_id();
    if collateral_asset_id != expected_collateral {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_collateral.to_string(),
            actual: collateral_asset_id.to_string(),
        });
    }

    let expected_settlement = arguments.get_settlement_asset_id();
    if settlement_asset_id != expected_settlement {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_settlement.to_string(),
            actual: settlement_asset_id.to_string(),
        });
    }

    let settlement_amount_required = collateral_amount_to_receive
        .checked_mul(arguments.collateral_per_contract)
        .ok_or(TransactionBuildError::InsufficientSettlementAsset {
            required: u64::MAX,
            available: total_settlement,
        })?;

    if collateral_amount_to_receive > total_collateral {
        return Err(TransactionBuildError::InsufficientCollateral {
            required: collateral_amount_to_receive,
            available: total_collateral,
        });
    }

    if settlement_amount_required > total_settlement {
        return Err(TransactionBuildError::InsufficientSettlementAsset {
            required: settlement_amount_required,
            available: total_settlement,
        });
    }

    let contract_script = collateral_tx_out.script_pubkey.clone();
    let change_recipient_script = fee_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut collateral_input = Input::from_prevout(collateral_outpoint);
    collateral_input.witness_utxo = Some(collateral_tx_out.clone());
    pst.add_input(collateral_input);

    let mut settlement_input = Input::from_prevout(settlement_outpoint);
    settlement_input.witness_utxo = Some(settlement_tx_out.clone());
    pst.add_input(settlement_input);

    let mut fee_input = Input::from_prevout(fee_outpoint);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    pst.add_input(fee_input);

    let is_collateral_change_needed = total_collateral != collateral_amount_to_receive;
    let is_settlement_change_needed = total_settlement != settlement_amount_required;
    let is_fee_change_needed = fee_change != 0;

    if is_collateral_change_needed {
        pst.add_output(Output::new_explicit(
            contract_script.clone(),
            total_collateral - collateral_amount_to_receive,
            collateral_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        contract_script,
        settlement_amount_required,
        settlement_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        counterparty_recipient_script,
        collateral_amount_to_receive,
        collateral_asset_id,
        None,
    ));

    if is_settlement_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_settlement - settlement_amount_required,
            settlement_asset_id,
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
        &[collateral_tx_out, settlement_tx_out, fee_tx_out],
    )?;

    Ok((
        pst,
        SwapWithChangeBranch::Exercise {
            collateral_amount: collateral_amount_to_receive,
            is_change_needed: is_collateral_change_needed,
        },
    ))
}
