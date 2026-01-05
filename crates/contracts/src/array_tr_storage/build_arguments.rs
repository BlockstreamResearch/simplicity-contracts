use std::collections::HashMap;

use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct UnlimitedStorageArguments {
    len: u16,
}

impl UnlimitedStorageArguments {
    /// Create new unlimited storage arguments.
    #[must_use]
    pub const fn new(len: u16) -> Self {
        Self { len }
    }

    /// Returns the length parameter.
    #[must_use]
    pub const fn len(&self) -> u16 {
        self.len
    }

    /// Returns true if len is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Build Simplicity arguments for storage program.
#[must_use]
pub fn build_array_tr_storage_arguments(args: &UnlimitedStorageArguments) -> Arguments {
    Arguments::from(HashMap::from([(
        WitnessName::from_str_unchecked("LEN"),
        simplicityhl::Value::from(UIntValue::U16(args.len)),
    )]))
}

impl simplicityhl_core::Encodable for UnlimitedStorageArguments {}
