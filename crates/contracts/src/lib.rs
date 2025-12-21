#![warn(clippy::all, clippy::pedantic)]
extern crate core;

pub mod error;

pub mod sdk;

#[cfg(feature = "array-tr-storage")]
pub mod array_tr_storage;
#[cfg(feature = "bytes32-tr-storage")]
pub mod bytes32_tr_storage;
#[cfg(feature = "dcd")]
pub mod dual_currency_deposit;
#[cfg(feature = "options")]
pub mod options;
#[cfg(feature = "simple-storage")]
pub mod simple_storage;
#[cfg(feature = "swap-with-change")]
pub mod swap_with_change;
