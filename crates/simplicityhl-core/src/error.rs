/// Errors that occur during binary or hex encoding/decoding operations.
///
/// These errors are returned by the [`Encodable`](crate::Encodable) trait methods
/// when serializing or deserializing data.
#[cfg(feature = "encoding")]
#[derive(Debug, thiserror::Error)]
pub enum EncodingError {
    #[error("Failed to encode to binary: {0}")]
    BinaryEncode(#[from] bincode::error::EncodeError),

    #[error("Failed to decode from binary: {0}")]
    BinaryDecode(#[from] bincode::error::DecodeError),

    /// Returned when a hex string cannot be parsed.
    #[error("Failed to decode hex string: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

/// Errors that occur during Simplicity program compilation, execution, or environment setup.
///
/// These errors cover the full lifecycle of working with Simplicity programs:
/// loading source, satisfying witnesses, running on the Bit Machine, and
/// validating transaction environments.
#[derive(Debug, thiserror::Error)]
pub enum ProgramError {
    #[error("Failed to compile Simplicity program: {0}")]
    Compilation(String),

    /// Returned when witness values cannot satisfy the program's requirements.
    #[error("Failed to satisfy witness: {0}")]
    WitnessSatisfaction(String),

    /// Returned when the program cannot be pruned against the transaction environment.
    #[error("Failed to prune program: {0}")]
    Pruning(#[from] simplicityhl::simplicity::bit_machine::ExecutionError),

    #[error("Failed to construct a Bit Machine with enough space: {0}")]
    BitMachineCreation(#[from] simplicityhl::simplicity::bit_machine::LimitError),

    #[error("Failed to execute program on the Bit Machine: {0}")]
    Execution(simplicityhl::simplicity::bit_machine::ExecutionError),

    #[error("UTXO index {input_index} out of bounds (have {utxo_count} UTXOs)")]
    UtxoIndexOutOfBounds {
        input_index: usize,
        utxo_count: usize,
    },

    /// Returned when the UTXO's script does not match the expected program address.
    #[error("Script pubkey mismatch: expected hash {expected_hash}, got {actual_hash}")]
    ScriptPubkeyMismatch {
        expected_hash: String,
        actual_hash: String,
    },

    #[error("Input index {0} exceeds u32 maximum")]
    InputIndexOverflow(usize),
}

/// Errors that occur when interacting with the Esplora API or local cache.
///
/// These errors are returned by [`EsploraClient`](crate::EsploraClient) methods
/// for broadcasting transactions and fetching UTXOs.
#[cfg(feature = "explorer")]
#[derive(Debug, thiserror::Error)]
pub enum ExplorerError {
    /// Returned when an HTTP request to the Esplora API fails.
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("Broadcast failed with HTTP {status} for {url}: {message}")]
    BroadcastRejected {
        status: u16,
        url: String,
        message: String,
    },

    /// Returned when a filesystem operation fails (cache read/write, directory creation).
    #[error("IO operation failed: {0}")]
    Io(#[from] std::io::Error),

    /// Returned when transaction data is not valid hexadecimal.
    #[error("Invalid transaction hex: {0}")]
    InvalidTransactionHex(#[from] hex::FromHexError),

    /// Returned when raw transaction bytes cannot be parsed.
    #[error("Failed to deserialize transaction: {0}")]
    TransactionDeserialize(#[from] simplicityhl::simplicity::elements::encode::Error),

    /// Returned when the requested output index does not exist in the transaction.
    #[error("Output index {index} out of bounds for transaction {txid}")]
    OutputIndexOutOfBounds { index: usize, txid: String },
}
