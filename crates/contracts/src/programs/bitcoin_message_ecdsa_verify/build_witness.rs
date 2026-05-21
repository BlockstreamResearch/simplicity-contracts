use std::collections::HashMap;

use simplex::simplicityhl::num::U256;
use simplex::simplicityhl::str::WitnessName;
use simplex::simplicityhl::value::{UIntValue, ValueConstructible};
use simplex::simplicityhl::{Arguments, Value, WitnessValues};

use super::{BitcoinMessageEcdsaVerifyWitness, Point};

#[must_use]
pub fn build_bitcoin_message_ecdsa_verify_arguments(public_key: Point) -> Arguments {
    Arguments::from(HashMap::from([(
        WitnessName::from_str_unchecked("PUBLIC_KEY"),
        point_value(public_key),
    )]))
}

#[must_use]
pub fn build_bitcoin_message_ecdsa_verify_witness(
    witness: &BitcoinMessageEcdsaVerifyWitness,
) -> WitnessValues {
    WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("NONCE_POINT"),
            point_value(witness.nonce_point),
        ),
        (
            WitnessName::from_str_unchecked("R"),
            Value::from(UIntValue::U256(U256::from_byte_array(witness.r))),
        ),
        (
            WitnessName::from_str_unchecked("S"),
            Value::from(UIntValue::U256(U256::from_byte_array(witness.s))),
        ),
    ]))
}

fn point_value(point: Point) -> Value {
    Value::tuple([
        Value::from(UIntValue::U1(u8::from(point.0))),
        Value::from(UIntValue::U256(U256::from_byte_array(point.1))),
    ])
}
