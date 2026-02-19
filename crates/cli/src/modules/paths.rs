pub fn wallet_data_root() -> std::path::PathBuf {
    std::env::var_os("SIMPLICITY_CLI_WALLET_DATA_DIR").map_or_else(
        || std::path::PathBuf::from(".cache/wallet"),
        std::path::PathBuf::from,
    )
}
