use std::collections::HashMap;

use simplicityhl::num::U256;
use simplicityhl::types::{ResolvedType, TypeConstructible, UIntType};
use simplicityhl::value::{UIntValue, ValueConstructible};
use simplicityhl::{WitnessValues, str::WitnessName};

#[allow(non_camel_case_types)]
pub type u256 = [u8; 32];

/// The fixed depth of the Sparse Merkle Tree (SMT).
///
/// This is set to 8 because Simplicity currently requires fixed-length arrays
/// and cannot dynamically resolve array lengths using `param::LEN`.
pub const DEPTH: usize = 8;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct SMTWitness {
    /// The internal public key used for Taproot tweaking.
    ///
    /// This corresponds to the `key` parameter in the Simplicity expression:
    /// `let tweaked_key: u256 = jet::build_taptweak(key, tap_node);`.
    key: u256,

    /// The leaf node (value) being stored or verified in the tree.
    leaf: u256,

    /// A bitwise representation of the tree traversal path.
    ///
    /// Since `DEPTH` is 8, the path fits into a single `u8`.
    /// * `1` (or `true`) represents a move to the **Right**.
    /// * `0` (or `false`) represents a move to the **Left**.
    ///
    /// **Note:** The bits are ordered from the **leaf up to the root**.
    /// This order is chosen to simplify bitwise processing within the Simplicity contract.
    path_bits: u8,

    /// The sibling nodes required to reconstruct the Merkle path.
    ///
    /// Each element is a tuple containing the sibling's hash and a boolean direction.
    /// Like `path_bits`, this array is ordered from the **leaf up to the root**
    /// to facilitate efficient processing in the Simplicity loop.
    merkle_data: [(u256, bool); DEPTH],
}

impl SMTWitness {
    #[must_use]
    pub fn new(
        key: &u256,
        leaf: &u256,
        path_bits: u8,
        merkle_data: &[(u256, bool); DEPTH],
    ) -> Self {
        Self {
            key: *key,
            leaf: *leaf,
            path_bits,
            merkle_data: *merkle_data,
        }
    }
}

impl Default for SMTWitness {
    fn default() -> Self {
        Self {
            key: [0u8; 32],
            leaf: [0u8; 32],
            path_bits: 0,
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
            WitnessName::from_str_unchecked("KEY"),
            simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(witness.key))),
        ),
        (
            WitnessName::from_str_unchecked("LEAF"),
            simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(witness.leaf))),
        ),
        (
            WitnessName::from_str_unchecked("PATH_BITS"),
            simplicityhl::Value::from(UIntValue::U8(witness.path_bits)),
        ),
        (
            WitnessName::from_str_unchecked("MERKLE_DATA"),
            simplicityhl::Value::array(values, element_type),
        ),
    ]))
}
