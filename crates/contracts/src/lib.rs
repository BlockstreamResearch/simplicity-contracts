#![warn(clippy::all, clippy::pedantic)]
extern crate core;

#[cfg(feature = "bytes32-tr-storage")]
mod bytes32_tr_storage;
#[cfg(feature = "dcd")]
mod dual_currency_deposit;
mod options;
#[cfg(feature = "simple-storage")]
mod simple_storage;

#[cfg(any(feature = "sdk-basic", feature = "sdk-options"))]
pub mod sdk;

#[cfg(feature = "bytes32-tr-storage")]
pub use bytes32_tr_storage::*;
#[cfg(feature = "dcd")]
pub use dual_currency_deposit::*;
pub use options::*;
#[cfg(feature = "simple-storage")]
pub use simple_storage::*;
