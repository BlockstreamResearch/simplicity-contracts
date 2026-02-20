use std::collections::HashMap;

use hex::FromHex;

use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct StorageArguments {
    public_key: [u8; 32],
    slot_asset: String,
}

impl StorageArguments {
    /// Create new storage arguments.
    #[must_use]
    pub const fn new(public_key: [u8; 32], slot_asset: String) -> Self {
        Self {
            public_key,
            slot_asset,
        }
    }

    /// Returns the public key.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the slot asset.
    #[must_use]
    pub const fn slot_asset(&self) -> &String {
        &self.slot_asset
    }
}

/// Build Simplicity arguments for storage program.
///
/// # Panics
/// Panics if the slot asset hex string is invalid.
#[must_use]
pub fn build_storage_arguments(args: &StorageArguments) -> Arguments {
    let mut slot_id = <[u8; 32]>::from_hex(args.slot_asset()).unwrap();
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

impl wallet_abi::Encodable for StorageArguments {}
