use crate::error::FromArgumentsError;

use simplicityhl::Arguments;
use simplicityhl::str::WitnessName;
use simplicityhl::value::{UIntValue, ValueInner};

fn extract_uint<'a>(
    args: &'a Arguments,
    name: &WitnessName,
) -> Result<&'a UIntValue, FromArgumentsError> {
    let value = args
        .get(name)
        .ok_or_else(|| FromArgumentsError::MissingWitness {
            name: name.as_inner().to_owned(),
        })?;

    match value.inner() {
        ValueInner::UInt(uint_value) => Ok(uint_value),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.as_inner().to_owned(),
            expected: "UInt".to_owned(),
        }),
    }
}

/// Extract a U256 value as `[u8; 32]` from `Arguments` for a witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_u256_bytes(
    args: &Arguments,
    name: &WitnessName,
) -> Result<[u8; 32], FromArgumentsError> {
    match extract_uint(args, name)? {
        UIntValue::U256(u256) => Ok(u256.to_byte_array()),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.as_inner().to_owned(),
            expected: "U256".to_owned(),
        }),
    }
}

/// Extract a U64 value from `Arguments` for a witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_u64(args: &Arguments, name: &WitnessName) -> Result<u64, FromArgumentsError> {
    match extract_uint(args, name)? {
        UIntValue::U64(v) => Ok(*v),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.as_inner().to_owned(),
            expected: "U64".to_owned(),
        }),
    }
}

/// Extract a U32 value from `Arguments` for a witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_u32(args: &Arguments, name: &WitnessName) -> Result<u32, FromArgumentsError> {
    match extract_uint(args, name)? {
        UIntValue::U32(v) => Ok(*v),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.as_inner().to_owned(),
            expected: "U32".to_owned(),
        }),
    }
}
