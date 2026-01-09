use std::collections::HashMap;

use simplicityhl::{
    ResolvedType, WitnessValues, elements::TxOutSecrets, num::U256, parse::ParseFromStr,
    str::WitnessName, types::TypeConstructible, value::UIntValue,
};

#[derive(Debug, Clone, Copy)]
pub enum OptionBranch {
    Funding {
        expected_asset_amount: u64,
    },
    Exercise {
        is_change_needed: bool,
        amount_to_burn: u64,
        collateral_amount_to_get: u64,
        asset_amount: u64,
    },
    Settlement {
        is_change_needed: bool,
        grantor_token_amount_to_burn: u64,
        asset_amount: u64,
    },
    Expiry {
        is_change_needed: bool,
        grantor_token_amount_to_burn: u64,
        collateral_amount_to_withdraw: u64,
    },
    Cancellation {
        is_change_needed: bool,
        amount_to_burn: u64,
        collateral_amount_to_withdraw: u64,
    },
}

pub struct ExtraInputs {
    pub option_tx_out_secrets: TxOutSecrets,
    pub grantor_tx_out_secrets: TxOutSecrets,
}

/// Build witness values for options program execution.
///
/// # Panics
/// Panics if type parsing fails (should never happen with valid constants).
#[must_use]
pub fn build_option_witness(
    branch: OptionBranch,
    extra_inputs: Option<&ExtraInputs>,
) -> WitnessValues {
    let single = ResolvedType::parse_from_str("u64").unwrap();
    let quadruple = ResolvedType::parse_from_str("(bool, u64, u64, u64)").unwrap();
    let triple = ResolvedType::parse_from_str("(bool, u64, u64)").unwrap();

    let exercise_or_settlement_type = ResolvedType::either(quadruple, triple.clone());
    let left_type = ResolvedType::either(single, exercise_or_settlement_type);
    let right_type = ResolvedType::either(triple.clone(), triple);
    let path_type = ResolvedType::either(left_type, right_type);

    let branch_str = match branch {
        OptionBranch::Funding {
            expected_asset_amount,
        } => {
            format!("Left(Left({expected_asset_amount}))")
        }
        OptionBranch::Exercise {
            is_change_needed,
            amount_to_burn,
            collateral_amount_to_get: collateral_amount,
            asset_amount,
        } => {
            format!(
                "Left(Right(Left(({is_change_needed}, {amount_to_burn}, {collateral_amount}, {asset_amount}))))"
            )
        }
        OptionBranch::Settlement {
            is_change_needed,
            grantor_token_amount_to_burn,
            asset_amount,
        } => {
            format!(
                "Left(Right(Right(({is_change_needed}, {grantor_token_amount_to_burn}, {asset_amount}))))"
            )
        }
        OptionBranch::Expiry {
            is_change_needed,
            grantor_token_amount_to_burn,
            collateral_amount_to_withdraw: collateral_amount,
        } => {
            format!(
                "Right(Left(({is_change_needed}, {grantor_token_amount_to_burn}, {collateral_amount})))"
            )
        }
        OptionBranch::Cancellation {
            is_change_needed,
            amount_to_burn,
            collateral_amount_to_withdraw: collateral_amount,
        } => {
            format!("Right(Right(({is_change_needed}, {amount_to_burn}, {collateral_amount})))",)
        }
    };

    let mut witness_map = HashMap::new();

    witness_map.insert(
        WitnessName::from_str_unchecked("PATH"),
        simplicityhl::Value::parse_from_str(&branch_str, &path_type).unwrap(),
    );

    let (option_asset_blind, option_value_blind, grantor_asset_blind, grantor_value_blind) =
        if let Some(inputs) = extra_inputs {
            (
                U256::from_byte_array(*inputs.option_tx_out_secrets.asset_bf.into_inner().as_ref()),
                U256::from_byte_array(*inputs.option_tx_out_secrets.value_bf.into_inner().as_ref()),
                U256::from_byte_array(
                    *inputs.grantor_tx_out_secrets.asset_bf.into_inner().as_ref(),
                ),
                U256::from_byte_array(
                    *inputs.grantor_tx_out_secrets.value_bf.into_inner().as_ref(),
                ),
            )
        } else {
            let zero = U256::from(0u64);
            (zero, zero, zero, zero)
        };

    let mut insert_witness = |name: &str, val: U256| {
        witness_map.insert(
            WitnessName::from_str_unchecked(name),
            simplicityhl::Value::from(UIntValue::U256(val)),
        );
    };

    insert_witness("OPTION_ABF", option_asset_blind);
    insert_witness("OPTION_VBF", option_value_blind);

    insert_witness("GRANTOR_ABF", grantor_asset_blind);
    insert_witness("GRANTOR_VBF", grantor_value_blind);

    simplicityhl::WitnessValues::from(witness_map)
}
