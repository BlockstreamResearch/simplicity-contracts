use std::collections::HashMap;

use simplicityhl::elements::bitcoin::XOnlyPublicKey;
use simplicityhl::{
    ResolvedType, Value, WitnessValues, parse::ParseFromStr, str::WitnessName,
    types::TypeConstructible,
};
use wallet_abi::schema::values::{RuntimeSimfWitness, SimfWitness};

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
    Withdraw,
    /// Expiry path: user reclaims collateral + premium after expiry
    Expiry,
}

#[must_use]
/// Build runtime SIMF witness payload for option-offer branches.
///
/// # Panics
///
/// Panics if internal witness type/value parsing fails for static type descriptors.
pub fn build_option_offer_witness(
    branch: &OptionOfferBranch,
    to_sign_x_only: XOnlyPublicKey,
) -> SimfWitness {
    let exercise_type = ResolvedType::parse_from_str("(u64, bool)").unwrap();
    let signature_type = ResolvedType::parse_from_str("()").unwrap();
    let withdraw_or_expiry_type = ResolvedType::either(signature_type.clone(), signature_type);
    let path_type = ResolvedType::either(exercise_type, withdraw_or_expiry_type);

    let path = match branch {
        OptionOfferBranch::Exercise {
            collateral_amount,
            is_change_needed,
        } => {
            format!("Left(({collateral_amount}, {is_change_needed}))")
        }
        OptionOfferBranch::Withdraw => "Right(Left(()))".to_string(),
        OptionOfferBranch::Expiry => "Right(Right(()))".to_string(),
    };

    SimfWitness {
        resolved: WitnessValues::from(HashMap::from([(
            WitnessName::from_str_unchecked("PATH"),
            Value::parse_from_str(&path, &path_type).unwrap(),
        )])),
        runtime_arguments: vec![RuntimeSimfWitness::SigHashAll {
            name: "USER_SIGHASH_ALL".to_string(),
            public_key: to_sign_x_only,
        }],
    }
}
