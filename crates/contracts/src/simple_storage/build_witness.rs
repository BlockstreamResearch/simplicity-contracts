use std::collections::HashMap;

use simplicityhl::simplicity::bitcoin;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{WitnessValues, str::WitnessName, value::UIntValue};

#[must_use]
pub fn build_storage_witness(
    new_value: u64,
    signature: &bitcoin::secp256k1::schnorr::Signature,
) -> WitnessValues {
    simplicityhl::WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("NEW_VALUE"),
            simplicityhl::Value::from(UIntValue::U64(new_value)),
        ),
        (
            WitnessName::from_str_unchecked("USER_SIGNATURE"),
            simplicityhl::Value::byte_array(signature.serialize()),
        ),
    ]))
}
