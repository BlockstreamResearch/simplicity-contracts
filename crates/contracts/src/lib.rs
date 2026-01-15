#![warn(clippy::all, clippy::pedantic)]
extern crate core;

pub mod arguments_helpers;
pub mod error;

pub mod sdk;

#[cfg(feature = "array-tr-storage")]
pub mod array_tr_storage;
#[cfg(feature = "bytes32-tr-storage")]
pub mod bytes32_tr_storage;
#[cfg(any(
    feature = "finance-dcd",
    feature = "finance-option-offer",
    feature = "finance-options"
))]
pub mod finance;
#[cfg(feature = "simple-storage")]
pub mod simple_storage;

#[cfg(feature = "finance-dcd")]
pub use finance::dcd;
#[cfg(feature = "finance-option-offer")]
pub use finance::option_offer;
#[cfg(feature = "finance-options")]
pub use finance::options;
