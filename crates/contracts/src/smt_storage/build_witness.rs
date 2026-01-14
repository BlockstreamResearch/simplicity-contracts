use std::collections::HashMap;

use simplicityhl::num::U256;
use simplicityhl::types::{ResolvedType, TypeConstructible, UIntType};
use simplicityhl::value::{UIntValue, ValueConstructible};
use simplicityhl::{WitnessValues, str::WitnessName};

#[allow(non_camel_case_types)]
pub type u256 = [u8; 32];
pub const DEPTH: usize = 7;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct SMTWitness {
    leaf: u256,
    merkle_data: [(u256, bool); DEPTH],
}

impl SMTWitness {
    #[must_use]
    pub fn new(leaf: &u256, merkle_data: &[(u256, bool); DEPTH]) -> Self {
        Self {
            leaf: *leaf,
            merkle_data: *merkle_data,
        }
    }
}

impl Default for SMTWitness {
    fn default() -> Self {
        Self {
            leaf: [0u8; 32],
            merkle_data: [([0u8; 32], false); DEPTH],
        }
    }
}

#[must_use]
pub fn build_smt_storage_witness(witness: &SMTWitness) -> WitnessValues {
    let values: Vec<simplicityhl::Value> = witness
        .merkle_data
        .iter()
        .map(|(value, is_right)| {
            let hash_val =
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(*value)));
            let direction_val = simplicityhl::Value::from(*is_right);

            simplicityhl::Value::product(hash_val, direction_val)
        })
        .collect();

    let element_type = simplicityhl::types::TypeConstructible::product(
        UIntType::U256.into(),
        ResolvedType::boolean(),
    );

    simplicityhl::WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("LEAF"),
            simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(witness.leaf))),
        ),
        (
            WitnessName::from_str_unchecked("MERKLE_DATA"),
            simplicityhl::Value::array(values, element_type),
        ),
    ]))
}
