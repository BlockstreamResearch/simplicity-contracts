use std::collections::HashMap;

use simplicityhl::num::U256;
use simplicityhl::types::UIntType;
use simplicityhl::value::{UIntValue, ValueConstructible};
use simplicityhl::{WitnessValues, str::WitnessName};

// Storage is represented as 3 u256 slots.
// This is a constant because Simplicity cannot initialise an array using 'param'.
// The value 3 enables us to demonstrate the efficiency of storage with a small number of elements.
pub const MAX_VAL: usize = 3;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct State {
    pub limbs: [[u8; 32]; MAX_VAL],
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self {
            limbs: [[0u8; 32]; MAX_VAL],
        }
    }

    #[must_use]
    pub fn to_simplicity_values(&self) -> Vec<simplicityhl::Value> {
        self.limbs
            .iter()
            .map(|value| simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(*value))))
            .collect()
    }

    /// This function implements simple, arbitrary logic,
    /// namely changing a specific u256 element in the array by index.
    /// In this case, the last qword is changed to `num`, representing the final eight bytes written as `24..`.
    ///
    /// # Errors
    /// Returns an error if `index` is out of bounds.
    pub fn set_num_to_last_qword(&mut self, index: usize, num: u64) -> Result<(), &'static str> {
        let limb = self.limbs.get_mut(index).ok_or("Index out of bounds")?;
        limb[24..].copy_from_slice(&num.to_be_bytes());
        Ok(())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn build_array_tr_storage_witness(state: &State, changed_index: u16) -> WitnessValues {
    let values = state.to_simplicity_values();

    simplicityhl::WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("STATE"),
            simplicityhl::Value::array(values, UIntType::U256.into()),
        ),
        (
            WitnessName::from_str_unchecked("CHANGED_INDEX"),
            simplicityhl::Value::from(UIntValue::U16(changed_index)),
        ),
    ]))
}
