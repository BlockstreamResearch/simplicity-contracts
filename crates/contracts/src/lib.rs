//! Reference Simplicity contract templates and helpers for Elements/Liquid.
//!
//! - [`programs`]: finance contracts (options, option offer) built on the
//!   Simplex program API, with sources generated into [`artifacts`].
//! - [`state_management`]: standalone storage contract examples, each behind a
//!   feature flag.
//! - [`simplicityhl_core`]: shared compile/execute/taproot helpers.
#![warn(clippy::all, clippy::pedantic)]
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

pub use simplicityhl_core::*;
