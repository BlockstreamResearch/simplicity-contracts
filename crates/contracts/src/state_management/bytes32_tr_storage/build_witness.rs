use std::collections::HashMap;

use simplex::simplicityhl::num::U256;
use simplex::simplicityhl::{WitnessValues, str::WitnessName, value::UIntValue};

#[must_use]
pub fn build_bytes32_tr_witness(state: [u8; 32]) -> WitnessValues {
    simplex::simplicityhl::WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("STATE"),
        simplex::simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(state))),
    )]))
}
