#[derive(Debug, thiserror::Error)]
pub enum WalletAbiError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Invalid finalization steps: {0}")]
    InvalidFinalizationSteps(String),

    #[error("Invalid signer configuration: {0}")]
    InvalidSignerConfig(String),

    #[error("Funding failed: {0}")]
    Funding(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("PSET error: {0}")]
    Pset(#[from] simplicityhl::elements::pset::Error),

    #[error("PSET blinding error: {0}")]
    PsetBlind(#[from] simplicityhl::elements::pset::PsetBlindError),

    #[error("Transaction decode error: {0}")]
    TxDecode(#[from] simplicityhl::elements::encode::Error),

    #[error("Transaction amount proof verification failed: {0}")]
    AmountProofVerification(#[from] simplicityhl::elements::VerificationError),

    #[error("Program error: {0}")]
    Program(#[from] lwk_simplicity::error::ProgramError),

    #[error("Program error: {0}")]
    ProgramTrace(String),

    #[error("esplora mutex poisoned: {0}")]
    EsploraPoisoned(String),

    #[error("LWK Signer error: {0}")]
    LWKSigner(#[from] lwk_signer::NewError),

    #[error("LWK sign error: {0}")]
    LWKSign(#[from] lwk_signer::SignError),

    #[error("LWK wollet error: {0}")]
    LWKWollet(#[from] lwk_wollet::Error),

    #[error("TXOut unblinding error: {0}")]
    Unblind(#[from] lwk_wollet::elements::UnblindError),

    #[error("Locktime error: {0}")]
    Locktime(#[from] lwk_wollet::elements::locktime::Error),
}

/// Errors that occur during binary or hex encoding/decoding operations.
#[derive(Debug, thiserror::Error)]
pub enum EncodingError {
    #[error("Failed to encode to binary: {0}")]
    BinaryEncode(#[from] bincode::error::EncodeError),

    #[error("Failed to decode from binary: {0}")]
    BinaryDecode(#[from] bincode::error::DecodeError),

    #[error("Unexpected trailing bytes after decode: consumed {consumed} of {total}")]
    TrailingBytes { consumed: usize, total: usize },

    #[error("Failed to decode hex string: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
