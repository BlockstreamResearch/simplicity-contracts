use std::collections::HashMap;

use simplicityhl::num::U256;
use simplicityhl::{WitnessValues, str::WitnessName, value::UIntValue};

#[must_use]
pub fn build_storage_inc_witness(
    state: [u8; 32],  // TODO think about endianness
) -> WitnessValues {
    simplicityhl::WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("STATE"),
            simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(state))),
        ),
    ]))
}
