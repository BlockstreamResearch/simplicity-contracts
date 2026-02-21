#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

mod error;
mod runtime;

pub use error::WalletAbiException;
pub use runtime::{WalletAbiRuntime, default_esplora_url, extract_request_network};

uniffi::setup_scaffolding!();
