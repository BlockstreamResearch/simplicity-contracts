#![warn(clippy::all, clippy::pedantic)]
extern crate core;

pub mod error;

#[cfg(any(feature = "finance-option-offer", feature = "finance-options"))]
pub mod finance;
pub mod state_management;

mod utils;

#[cfg(feature = "finance-option-offer")]
pub use finance::option_offer;
#[cfg(feature = "finance-options")]
pub use finance::options;

#[cfg(feature = "array-tr-storage")]
pub use state_management::array_tr_storage;
#[cfg(feature = "bytes32-tr-storage")]
pub use state_management::bytes32_tr_storage;
#[cfg(feature = "simple-storage")]
pub use state_management::simple_storage;
#[cfg(feature = "smt-storage")]
pub use state_management::smt_storage;
