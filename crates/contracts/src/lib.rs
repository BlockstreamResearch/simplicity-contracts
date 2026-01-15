#![warn(clippy::all, clippy::pedantic)]
extern crate core;

pub mod arguments_helpers;
pub mod error;

pub mod sdk;

#[cfg(feature = "array-tr-storage")]
pub mod array_tr_storage;
#[cfg(feature = "bytes32-tr-storage")]
pub mod bytes32_tr_storage;
#[cfg(feature = "dcd")]
pub mod dual_currency_deposit;
#[cfg(feature = "option-offer")]
pub mod option_offer;
#[cfg(feature = "options")]
pub mod options;
#[cfg(feature = "simple-storage")]
pub mod simple_storage;
