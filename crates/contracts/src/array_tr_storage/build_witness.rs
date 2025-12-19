use std::collections::HashMap;

use simplicityhl::types::UIntType;
use simplicityhl::value::{UIntValue, ValueConstructible};
use simplicityhl::{WitnessValues, str::WitnessName};

pub const MAX_VAL: usize = 10000; // u16::MAX as usize;

#[must_use]
pub fn build_array_tr_storage_witness(storage: [u8; MAX_VAL]) -> WitnessValues {
    let values: Vec<simplicityhl::Value> = storage
        .into_iter()
        .map(|value| simplicityhl::Value::from(UIntValue::from(value)))
        .collect();

    simplicityhl::WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("STORAGE"),
        simplicityhl::Value::array(values, UIntType::U8.into()),
    )]))
}
