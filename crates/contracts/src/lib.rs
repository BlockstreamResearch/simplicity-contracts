#![warn(clippy::all, clippy::pedantic)]
extern crate core;
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
pub mod artifacts;
pub mod programs;
pub mod simplicityhl_core;
pub mod state_management;

#[cfg(feature = "array-tr-storage")]
pub use state_management::array_tr_storage;
#[cfg(feature = "bytes32-tr-storage")]
pub use state_management::bytes32_tr_storage;
#[cfg(feature = "simple-storage")]
pub use state_management::simple_storage;
#[cfg(feature = "smt-storage")]
pub use state_management::smt_storage;

pub use simplicityhl_core::*;
