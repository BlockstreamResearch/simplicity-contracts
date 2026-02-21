use std::sync::{MutexGuard, PoisonError};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum WalletAbiException {
    #[error("{msg}")]
    Generic { msg: String },

    #[error(
        "Invalid network '{network}'. Supported values: liquid, testnet-liquid, localtest-liquid"
    )]
    InvalidNetwork { network: String },

    #[error("Malformed JSON: {msg}")]
    MalformedJson { msg: String },

    #[error("Invalid request envelope: {msg}")]
    InvalidRequestEnvelope { msg: String },

    #[error("Runtime initialization failed: {msg}")]
    RuntimeInitialization { msg: String },

    #[error("Serialization failed: {msg}")]
    Serialization { msg: String },

    #[error("Runtime lock poisoned: {msg}")]
    PoisonError { msg: String },
}

impl From<wallet_abi::WalletAbiError> for WalletAbiException {
    fn from(value: wallet_abi::WalletAbiError) -> Self {
        Self::Generic {
            msg: value.to_string(),
        }
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for WalletAbiException {
    fn from(value: PoisonError<MutexGuard<'_, T>>) -> Self {
        Self::PoisonError {
            msg: value.to_string(),
        }
    }
}
