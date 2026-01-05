use simplicityhl::Arguments;
use simplicityhl::str::WitnessName;
use simplicityhl::value::{UIntValue, ValueInner};

use crate::error::FromArgumentsError;

/// Extract a U256 value as `[u8; 32]` from Arguments by witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_u256_bytes(args: &Arguments, name: &str) -> Result<[u8; 32], FromArgumentsError> {
    let witness_name = WitnessName::from_str_unchecked(name);
    let value = args
        .get(&witness_name)
        .ok_or_else(|| FromArgumentsError::MissingWitness {
            name: name.to_string(),
        })?;

    match value.inner() {
        ValueInner::UInt(UIntValue::U256(u256)) => Ok(u256.to_byte_array()),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.to_string(),
            expected: "U256".to_string(),
        }),
    }
}

/// Extract a U64 value from Arguments by witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_u64(args: &Arguments, name: &str) -> Result<u64, FromArgumentsError> {
    let witness_name = WitnessName::from_str_unchecked(name);
    let value = args
        .get(&witness_name)
        .ok_or_else(|| FromArgumentsError::MissingWitness {
            name: name.to_string(),
        })?;

    match value.inner() {
        ValueInner::UInt(UIntValue::U64(v)) => Ok(*v),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.to_string(),
            expected: "U64".to_string(),
        }),
    }
}

/// Extract a U32 value from Arguments by witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_u32(args: &Arguments, name: &str) -> Result<u32, FromArgumentsError> {
    let witness_name = WitnessName::from_str_unchecked(name);
    let value = args
        .get(&witness_name)
        .ok_or_else(|| FromArgumentsError::MissingWitness {
            name: name.to_string(),
        })?;

    match value.inner() {
        ValueInner::UInt(UIntValue::U32(v)) => Ok(*v),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.to_string(),
            expected: "U32".to_string(),
        }),
    }
}

/// Extract a boolean value from Arguments by witness name.
///
/// # Errors
///
/// Returns error if the witness is missing or has wrong type.
pub fn extract_bool(args: &Arguments, name: &str) -> Result<bool, FromArgumentsError> {
    let witness_name = WitnessName::from_str_unchecked(name);
    let value = args
        .get(&witness_name)
        .ok_or_else(|| FromArgumentsError::MissingWitness {
            name: name.to_string(),
        })?;

    match value.inner() {
        ValueInner::Boolean(b) => Ok(*b),
        _ => Err(FromArgumentsError::WrongValueType {
            name: name.to_string(),
            expected: "bool".to_string(),
        }),
    }
}
