use crate::finance::options::OptionsArguments;
use crate::finance::options::build_witness::OptionBranch;

use crate::error::TransactionBuildError;

use crate::sdk::PartialPset;
use crate::sdk::validation::TxOutExt;

use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{LockTime, OutPoint, Script, Sequence, TxOut};

/// Settle an option by burning grantor tokens to withdraw settlement asset.
///
/// # Errors
///
/// Returns an error if:
/// - The UTXO asset or amount (fee included) validation fails (ALL amounts and assets are expected to be explicit)
/// - Insufficient settlement asset in comparison to amount of grantor tokens to burn
/// - Transaction extraction or amount proof verification fails
#[allow(clippy::too_many_lines)]
pub fn build_option_settlement(
    settlement_asset_utxo: (OutPoint, TxOut),
    grantor_asset_utxo: (OutPoint, TxOut),
    fee_utxo: (OutPoint, TxOut),
    grantor_token_amount_to_burn: u64,
    option_arguments: &OptionsArguments,
) -> Result<(PartialPset, OptionBranch), TransactionBuildError> {
    let (settlement_out_point, settlement_tx_out) = settlement_asset_utxo;
    let (grantor_out_point, grantor_tx_out) = grantor_asset_utxo;
    let (fee_out_point, fee_tx_out) = fee_utxo;

    let (settlement_asset_id, available_settlement_asset) = settlement_tx_out.explicit()?;
    let (grantor_token_id, total_grantor_token_amount) = grantor_tx_out.explicit()?;

    let (expected_grantor_token_id, _) = option_arguments.get_grantor_token_ids();
    let expected_settlement_asset_id = option_arguments.get_settlement_asset_id();

    if grantor_token_id != expected_grantor_token_id {
        return Err(TransactionBuildError::WrongGrantorToken {
            expected: expected_grantor_token_id.to_string(),
            actual: grantor_token_id.to_string(),
        });
    }
    if settlement_asset_id != expected_settlement_asset_id {
        return Err(TransactionBuildError::WrongSettlementAsset {
            expected: expected_settlement_asset_id.to_string(),
            actual: settlement_asset_id.to_string(),
        });
    }

    let asset_amount =
        grantor_token_amount_to_burn.saturating_mul(option_arguments.settlement_per_contract());

    if asset_amount > available_settlement_asset {
        return Err(TransactionBuildError::InsufficientSettlementAsset {
            required: asset_amount,
            available: available_settlement_asset,
        });
    }

    let change_recipient_script = fee_tx_out.script_pubkey.clone();
    let contract_script = settlement_tx_out.script_pubkey.clone();

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.global.tx_data.fallback_locktime =
        Some(LockTime::from_time(option_arguments.start_time())?);

    let mut settlement_input = Input::from_prevout(settlement_out_point);
    settlement_input.witness_utxo = Some(settlement_tx_out.clone());
    settlement_input.sequence = Some(Sequence::ZERO);
    pst.add_input(settlement_input);

    let mut grantor_input = Input::from_prevout(grantor_out_point);
    grantor_input.witness_utxo = Some(grantor_tx_out.clone());
    grantor_input.sequence = Some(Sequence::ZERO);
    pst.add_input(grantor_input);

    let mut fee_input = Input::from_prevout(fee_out_point);
    fee_input.witness_utxo = Some(fee_tx_out.clone());
    fee_input.sequence = Some(Sequence::ZERO);
    pst.add_input(fee_input);

    let is_settlement_change_needed = available_settlement_asset != asset_amount;
    let is_grantor_change_needed = total_grantor_token_amount != grantor_token_amount_to_burn;

    if is_settlement_change_needed {
        pst.add_output(Output::new_explicit(
            contract_script,
            available_settlement_asset - asset_amount,
            settlement_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        Script::new_op_return(b"burn"),
        grantor_token_amount_to_burn,
        grantor_token_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient_script.clone(),
        asset_amount,
        settlement_asset_id,
        None,
    ));

    if is_grantor_change_needed {
        pst.add_output(Output::new_explicit(
            change_recipient_script.clone(),
            total_grantor_token_amount - grantor_token_amount_to_burn,
            grantor_token_id,
            None,
        ));
    }

    let non_finalized_pset = PartialPset::new(
        pst,
        change_recipient_script,
        vec![settlement_tx_out, grantor_tx_out, fee_tx_out],
    );

    let option_branch = OptionBranch::Settlement {
        is_change_needed: is_settlement_change_needed,
        grantor_token_amount_to_burn,
        asset_amount,
    };

    Ok((non_finalized_pset, option_branch))
}
