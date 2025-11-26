use std::collections::HashMap;

use hex::FromHex;

use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
pub struct StorageArguments {
    pub public_key: [u8; 32],
    pub slot_asset: String,
}

/// Build Simplicity arguments for storage program.
///
/// # Panics
/// Panics if the slot asset hex string is invalid.
#[must_use]
pub fn build_storage_arguments(args: &StorageArguments) -> Arguments {
    let mut slot_id = <[u8; 32]>::from_hex(&args.slot_asset).unwrap();
    slot_id.reverse();

    Arguments::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("SLOT_ID"),
            simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(slot_id))),
        ),
        (
            WitnessName::from_str_unchecked("USER"),
            simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(args.public_key))),
        ),
    ]))
}

impl simplicityhl_core::Encodable for StorageArguments {}
