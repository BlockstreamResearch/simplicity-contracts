use std::collections::HashMap;

use simplicityhl::{
    ResolvedType, Value, WitnessValues, elements::secp256k1_zkp::schnorr::Signature,
    parse::ParseFromStr, str::WitnessName, types::TypeConstructible, value::ValueConstructible,
};

/// Represents the different execution paths for the swap with change contract.
#[derive(Debug, Clone)]
pub enum SwapWithChangeBranch {
    /// Exercise path: counterparty swaps settlement asset for collateral
    Exercise {
        /// Amount of collateral the counterparty will receive
        collateral_amount: u64,
        /// Whether there's collateral change (partial swap)
        is_change_needed: bool,
    },
    /// Withdraw path: user withdraws settlement asset
    Withdraw { schnorr_signature: Signature },
    /// Expiry path: user reclaims collateral after expiry
    Expiry { schnorr_signature: Signature },
}

/// Build witness values for swap with change program execution.
///
/// # Panics
///
/// Panics if type parsing fails (should never happen with valid constants).
#[must_use]
pub fn build_swap_with_change_witness(branch: &SwapWithChangeBranch) -> WitnessValues {
    let exercise_type = ResolvedType::parse_from_str("(u64, bool)").unwrap();
    let signature_type = ResolvedType::parse_from_str("Signature").unwrap();
    let withdraw_or_expiry_type = ResolvedType::either(signature_type.clone(), signature_type);
    let path_type = ResolvedType::either(exercise_type, withdraw_or_expiry_type);

    let branch_str = match branch {
        SwapWithChangeBranch::Exercise {
            collateral_amount,
            is_change_needed,
        } => {
            format!("Left(({collateral_amount}, {is_change_needed}))")
        }
        SwapWithChangeBranch::Withdraw { schnorr_signature } => {
            format!(
                "Right(Left({}))",
                Value::byte_array(schnorr_signature.serialize())
            )
        }
        SwapWithChangeBranch::Expiry { schnorr_signature } => {
            format!(
                "Right(Right({}))",
                Value::byte_array(schnorr_signature.serialize())
            )
        }
    };

    simplicityhl::WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("PATH"),
        simplicityhl::Value::parse_from_str(&branch_str, &path_type).unwrap(),
    )]))
}
