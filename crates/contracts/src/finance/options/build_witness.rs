use std::collections::HashMap;

use simplicityhl::{
    ResolvedType, WitnessValues, elements::TxOutSecrets, num::U256, parse::ParseFromStr,
    str::WitnessName, types::TypeConstructible,
};

/// Extract (`asset_bf`, `value_bf`) as U256 from `TxOutSecrets`.
#[must_use]
pub fn blinding_factors_from_secrets(secrets: &TxOutSecrets) -> (U256, U256) {
    (
        U256::from_byte_array(*secrets.asset_bf.into_inner().as_ref()),
        U256::from_byte_array(*secrets.value_bf.into_inner().as_ref()),
    )
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum OptionBranch {
    Funding {
        expected_asset_amount: u64,
        input_option_abf: U256,
        input_option_vbf: U256,
        input_grantor_abf: U256,
        input_grantor_vbf: U256,
        output_option_abf: U256,
        output_option_vbf: U256,
        output_grantor_abf: U256,
        output_grantor_vbf: U256,
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

/// Build witness values for options program execution.
///
/// # Panics
///
/// Panics if internal static type descriptors or generated witness values fail
/// to parse.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_option_witness(branch: &OptionBranch) -> WitnessValues {
    let single =
        ResolvedType::parse_from_str("(u64, u256, u256, u256, u256, u256, u256, u256, u256)")
            .unwrap();
    let quadruple = ResolvedType::parse_from_str("(bool, u64, u64, u64)").unwrap();
    let triple = ResolvedType::parse_from_str("(bool, u64, u64)").unwrap();

    let exercise_or_settlement_type = ResolvedType::either(quadruple, triple.clone());
    let left_type = ResolvedType::either(single, exercise_or_settlement_type);
    let right_type = ResolvedType::either(triple.clone(), triple);
    let path_type = ResolvedType::either(left_type, right_type);

    let branch_str = match branch {
        OptionBranch::Funding {
            expected_asset_amount,
            input_option_abf,
            input_option_vbf,
            input_grantor_abf,
            input_grantor_vbf,
            output_option_abf,
            output_option_vbf,
            output_grantor_abf,
            output_grantor_vbf,
        } => format!(
            "Left(Left(({expected_asset_amount}, {input_option_abf}, {input_option_vbf}, {input_grantor_abf}, {input_grantor_vbf}, {output_option_abf}, {output_option_vbf}, {output_grantor_abf}, {output_grantor_vbf})))"
        ),
        OptionBranch::Exercise {
            is_change_needed,
            amount_to_burn,
            collateral_amount_to_get: collateral_amount,
            asset_amount,
        } => format!(
            "Left(Right(Left(({is_change_needed}, {amount_to_burn}, {collateral_amount}, {asset_amount}))))"
        ),
        OptionBranch::Settlement {
            is_change_needed,
            grantor_token_amount_to_burn,
            asset_amount,
        } => format!(
            "Left(Right(Right(({is_change_needed}, {grantor_token_amount_to_burn}, {asset_amount}))))"
        ),
        OptionBranch::Expiry {
            is_change_needed,
            grantor_token_amount_to_burn,
            collateral_amount_to_withdraw: collateral_amount,
        } => format!(
            "Right(Left(({is_change_needed}, {grantor_token_amount_to_burn}, {collateral_amount})))"
        ),
        OptionBranch::Cancellation {
            is_change_needed,
            amount_to_burn,
            collateral_amount_to_withdraw: collateral_amount,
        } => format!("Right(Right(({is_change_needed}, {amount_to_burn}, {collateral_amount})))"),
    };

    let mut witness_map = HashMap::new();

    witness_map.insert(
        WitnessName::from_str_unchecked("PATH"),
        simplicityhl::Value::parse_from_str(&branch_str, &path_type).unwrap(),
    );

    simplicityhl::WitnessValues::from(witness_map)
}
