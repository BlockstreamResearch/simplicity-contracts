#![warn(clippy::all, clippy::pedantic)]
extern crate core;

#[cfg(feature = "cmr-storage")]
mod cmr_storage;
#[cfg(feature = "dcd")]
mod dual_currency_deposit;
mod options;
#[cfg(feature = "simple-storage")]
mod simple_storage;

#[cfg(any(feature = "sdk-basic", feature = "sdk-options"))]
pub mod sdk;

#[cfg(feature = "cmr-storage")]
pub use cmr_storage::*;
#[cfg(feature = "dcd")]
pub use dual_currency_deposit::*;
pub use options::*;
#[cfg(feature = "simple-storage")]
pub use simple_storage::*;
