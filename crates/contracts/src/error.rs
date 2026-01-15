/// Errors from UTXO validation operations.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("UTXO {script_hash} has confidential value")]
    ConfidentialValue { script_hash: String },

    #[error("UTXO {script_hash} has confidential asset")]
    ConfidentialAsset { script_hash: String },

    #[error("UTXO {script_hash} has insufficient funds: have {available}, need {required}")]
    InsufficientFunds {
        script_hash: String,
        available: u64,
        required: u64,
    },

    #[error("Fee UTXO {script_hash} has wrong asset: expected {expected}, got {actual}")]
    FeeAssetMismatch {
        script_hash: String,
        expected: String,
        actual: String,
    },
}

/// Errors from taproot pubkey generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum TaprootPubkeyGenError {
    #[error("Invalid pubkey recovered: expected {expected}, got {actual}")]
    InvalidPubkey { expected: String, actual: String },

    #[error("Invalid address recovered: expected {expected}, got {actual}")]
    InvalidAddress { expected: String, actual: String },

    #[error(
        "Invalid taproot pubkey gen string: expected 3 parts separated by ':', got {parts_count}"
    )]
    InvalidFormat { parts_count: usize },

    #[error("Failed to decode seed hex: {0}")]
    SeedHexDecode(#[from] hex::FromHexError),

    #[error("Failed to parse public key: {0}")]
    PublicKeyParse(#[from] simplicityhl::simplicity::bitcoin::key::ParsePublicKeyError),

    #[error("Failed to parse address: {0}")]
    AddressParse(#[from] simplicityhl::elements::address::AddressError),

    #[error("Failed to create X-only public key from bytes: {0}")]
    XOnlyPublicKey(#[from] simplicityhl::simplicity::bitcoin::secp256k1::Error),

    #[error("Failed to generate address: {0}")]
    AddressGeneration(#[from] simplicityhl_core::ProgramError),
}

/// Errors from transaction building operations.
#[derive(Debug, thiserror::Error)]
pub enum TransactionBuildError {
    #[error("parts_to_split must be greater than 0")]
    InvalidSplitParts,

    #[error("Send amount {send_amount} exceeds asset UTXO value {available}")]
    SendAmountExceedsUtxo { send_amount: u64, available: u64 },

    #[error(
        "Fee UTXOs must have the same asset: first ({first_script_hash}) has {first_asset}, second ({second_script_hash}) has {second_asset}"
    )]
    FeeUtxoAssetMismatch {
        first_script_hash: String,
        first_asset: String,
        second_script_hash: String,
        second_asset: String,
    },

    #[error(
        "First issuance must produce option token: expected ({expected_token}, {expected_reissuance}), got ({actual_token}, {actual_reissuance})"
    )]
    OptionTokenMismatch {
        expected_token: String,
        expected_reissuance: String,
        actual_token: String,
        actual_reissuance: String,
    },

    #[error(
        "Second issuance must produce grantor token: expected ({expected_token}, {expected_reissuance}), got ({actual_token}, {actual_reissuance})"
    )]
    GrantorTokenMismatch {
        expected_token: String,
        expected_reissuance: String,
        actual_token: String,
        actual_reissuance: String,
    },

    #[error("Insufficient collateral: need {required}, have {available}")]
    InsufficientCollateral { required: u64, available: u64 },

    #[error("Insufficient settlement asset: need {required}, have {available}")]
    InsufficientSettlementAsset { required: u64, available: u64 },

    #[error("Grantor asset UTXO has wrong token: expected {expected}, got {actual}")]
    WrongGrantorToken { expected: String, actual: String },

    #[error("Settlement asset UTXO has wrong asset: expected {expected}, got {actual}")]
    WrongSettlementAsset { expected: String, actual: String },

    #[error("Failed to blind transaction: {0}")]
    Blinding(#[from] simplicityhl::elements::pset::Error),

    #[error("Failed to blind transaction outputs: {0}")]
    BlindingOutputs(#[from] simplicityhl::elements::pset::PsetBlindError),

    #[error("Transaction amount proof verification failed: {0}")]
    AmountProofVerification(#[from] simplicityhl::elements::VerificationError),

    #[error("Failed to unblind transaction output: {0}")]
    Unblinding(#[from] simplicityhl::elements::UnblindError),

    #[error("Invalid lock time: {0}")]
    InvalidLockTime(#[from] simplicityhl::elements::locktime::Error),

    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error(transparent)]
    TaprootPubkeyGen(#[from] TaprootPubkeyGenError),
}

/// Errors from extracting arguments from Arguments struct.
#[derive(Debug, thiserror::Error)]
pub enum FromArgumentsError {
    #[error("Missing witness name: {name}")]
    MissingWitness { name: String },

    #[error("Wrong value type for {name}: expected {expected}")]
    WrongValueType { name: String, expected: String },

    #[error("Invalid asset ID bytes for {name}")]
    InvalidAssetId { name: String },
}

/// Errors from DCD ratio calculations.
#[cfg(feature = "finance-dcd")]
#[derive(Debug, thiserror::Error)]
pub enum DCDRatioError {
    #[error("Arithmetic overflow: {operation}")]
    Overflow { operation: String },

    #[error("Value exceeds u64: {value_name}")]
    U64Overflow { value_name: String },

    #[error("{dividend} must be divisible by {divisor}, remainder {remainder}")]
    NotDivisible {
        dividend: String,
        divisor: String,
        remainder: u64,
    },

    #[error("{value_name} must be non-zero")]
    ZeroValue { value_name: String },
}
