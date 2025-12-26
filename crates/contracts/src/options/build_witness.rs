use std::collections::HashMap;

use simplicityhl::{
    ResolvedType, WitnessValues,
    elements::{TxOut, confidential::Asset},
    num::U256,
    parse::ParseFromStr,
    str::WitnessName,
    types::TypeConstructible,
    value::UIntValue,
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
    pub option_tx_out: TxOut,
    pub grantor_tx_out: TxOut,
}

#[must_use]
fn get_asset_point(asset: Asset) -> (u8, [u8; 32]) {
    let zero_bytes = [0u8; 33];
    let asset_bytes = match asset {
        Asset::Confidential(generator) => generator.serialize(),
        _ => zero_bytes,
    };

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&asset_bytes[1..]);
    (u8::from(asset_bytes[0] % 2 != 0), x_bytes)
}

#[must_use]
fn get_value_point(value: simplicityhl::elements::confidential::Value) -> (u8, [u8; 32]) {
    let zero_bytes = [0u8; 33];
    let asset_bytes = match value {
        simplicityhl::elements::confidential::Value::Confidential(generator) => {
            generator.serialize()
        }
        _ => zero_bytes,
    };

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&asset_bytes[1..]);
    (u8::from(asset_bytes[0] % 2 != 0), x_bytes)
}

/// Build additional witness values for options program execution.
///
/// # Panics
/// Panics if type parsing fails (should never happen with valid constants).
fn build_additional_option_witness(
    witness_map: &mut HashMap<WitnessName, simplicityhl::Value>,
    extra_inputs: Option<&ExtraInputs>,
) {
    let zero_point: (u8, [u8; 32]) = (0, [0u8; 32]);

    let (option_asset_point, option_value_point, grantor_asset_point, grantor_value_point) =
        if let Some(inputs) = extra_inputs {
            (
                get_asset_point(inputs.option_tx_out.asset),
                get_value_point(inputs.option_tx_out.value),
                get_asset_point(inputs.grantor_tx_out.asset),
                get_value_point(inputs.grantor_tx_out.value),
            )
        } else {
            (zero_point, zero_point, zero_point, zero_point)
        };

    // --- OPTION ---
    witness_map.insert(
        WitnessName::from_str_unchecked("OPTION_ASSET_PARITY"),
        simplicityhl::Value::from(UIntValue::U1(option_asset_point.0)),
    );

    witness_map.insert(
        WitnessName::from_str_unchecked("OPTION_ASSET_X"),
        simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(option_asset_point.1))),
    );

    witness_map.insert(
        WitnessName::from_str_unchecked("OPTION_VALUE_PARITY"),
        simplicityhl::Value::from(UIntValue::U1(option_value_point.0)),
    );

    witness_map.insert(
        WitnessName::from_str_unchecked("OPTION_VALUE_X"),
        simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(option_value_point.1))),
    );

    // --- GRANTOR ---
    witness_map.insert(
        WitnessName::from_str_unchecked("GRANTOR_ASSET_PARITY"),
        simplicityhl::Value::from(UIntValue::U1(grantor_asset_point.0)),
    );

    witness_map.insert(
        WitnessName::from_str_unchecked("GRANTOR_ASSET_X"),
        simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
            grantor_asset_point.1,
        ))),
    );

    witness_map.insert(
        WitnessName::from_str_unchecked("GRANTOR_VALUE_PARITY"),
        simplicityhl::Value::from(UIntValue::U1(grantor_value_point.0)),
    );

    witness_map.insert(
        WitnessName::from_str_unchecked("GRANTOR_VALUE_X"),
        simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
            grantor_value_point.1,
        ))),
    );
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
    build_additional_option_witness(&mut witness_map, extra_inputs);

    simplicityhl::WitnessValues::from(witness_map)
}
