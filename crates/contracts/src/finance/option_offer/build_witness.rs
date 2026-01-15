use std::collections::HashMap;

use simplicityhl::{
    ResolvedType, Value, WitnessValues, elements::secp256k1_zkp::schnorr::Signature,
    parse::ParseFromStr, str::WitnessName, types::TypeConstructible, value::ValueConstructible,
};

/// Represents the different execution paths for the option offer contract.
#[derive(Debug, Clone)]
pub enum OptionOfferBranch {
    /// Exercise path: counterparty swaps settlement asset for collateral + premium
    Exercise {
        /// Amount of collateral the counterparty will receive (premium derived from ratio)
        collateral_amount: u64,
        /// Whether there's change (partial swap)
        is_change_needed: bool,
    },
    /// Withdraw path: user withdraws settlement asset
    Withdraw { schnorr_signature: Signature },
    /// Expiry path: user reclaims collateral + premium after expiry
    Expiry { schnorr_signature: Signature },
}

/// Build witness values for option offer program execution.
///
/// # Panics
///
/// Panics if type parsing fails (should never happen with valid constants).
#[must_use]
pub fn build_option_offer_witness(branch: &OptionOfferBranch) -> WitnessValues {
    let exercise_type = ResolvedType::parse_from_str("(u64, bool)").unwrap();
    let signature_type = ResolvedType::parse_from_str("Signature").unwrap();
    let withdraw_or_expiry_type = ResolvedType::either(signature_type.clone(), signature_type);
    let path_type = ResolvedType::either(exercise_type, withdraw_or_expiry_type);

    let branch_str = match branch {
        OptionOfferBranch::Exercise {
            collateral_amount,
            is_change_needed,
        } => {
            format!("Left(({collateral_amount}, {is_change_needed}))")
        }
        OptionOfferBranch::Withdraw { schnorr_signature } => {
            format!(
                "Right(Left({}))",
                Value::byte_array(schnorr_signature.serialize())
            )
        }
        OptionOfferBranch::Expiry { schnorr_signature } => {
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
