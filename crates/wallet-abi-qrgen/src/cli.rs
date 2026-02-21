use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "wallet-abi-qrgen",
    version,
    about = "Generate wallet-abi transport request QR codes"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Build and encode a simple transfer request as `wa_v1` and generate QR artifacts.
    SimpleTransfer(SimpleTransferArgs),

    /// Build and encode a split transfer request with multiple equal outputs.
    SplitTransfer(SplitTransferArgs),

    /// Build and encode a new asset issuance request.
    IssueAsset(IssueAssetArgs),

    /// Build and encode an asset reissuance request.
    ReissueAsset(ReissueAssetArgs),

    /// Decode a `wa_v1` / `wa_resp_v1` payload (or full URL fragment) into JSON.
    ParsePayload(ParsePayloadArgs),

    /// Create a relay pairing QR (`wa_relay_v1`), wait for phone connect, send request, and print relay response.
    RelayConnect(RelayConnectArgs),

    /// Manage local option-offer reference state used by relay option-offer flows.
    OptionOfferState(OptionOfferStateArgs),
}

#[derive(Debug, Clone, Args)]
pub struct CommonRequestArgs {
    /// Network to target.
    #[arg(long = "network", default_value = "testnet-liquid")]
    pub network: wallet_abi::Network,

    /// HTTPS origin to include in the transport envelope.
    #[arg(long = "origin", default_value = "https://dapp.example")]
    pub origin: String,

    /// Callback mode for transport response.
    #[arg(long = "callback-mode", value_enum, default_value = "qr_roundtrip")]
    pub callback_mode: CallbackModeArg,

    /// HTTPS callback URL, required for `same_device_https` and `backend_push`.
    #[arg(long = "callback-url")]
    pub callback_url: Option<String>,

    /// Deep-link base URL for app handoff.
    #[arg(
        long = "base-link",
        default_value = "https://blockstream.com/walletabi/request"
    )]
    pub base_link: String,

    /// Request id override, defaults to generated `UUIDv4`.
    #[arg(long = "request-id")]
    pub request_id: Option<String>,

    /// Transport envelope TTL in milliseconds (max 120000).
    #[arg(long = "ttl-ms", default_value_t = 120_000_u64)]
    pub ttl_ms: u64,

    /// Whether runtime should broadcast the transaction.
    #[arg(long = "broadcast", default_value_t = false)]
    pub broadcast: bool,

    /// Fee rate in sat/vbyte.
    #[arg(long = "fee-rate-sat-vb", default_value_t = 0.1_f32)]
    pub fee_rate_sat_vb: f32,

    /// Directory for generated artifacts.
    #[arg(long = "out-dir", default_value = ".cache/wallet-abi-qrgen")]
    pub out_dir: PathBuf,

    /// Pixel scaling factor per QR module.
    #[arg(long = "pixel-per-module", default_value_t = 8_u8)]
    pub pixel_per_module: u8,
}

#[derive(Debug, Clone, Args)]
pub struct SimpleTransferArgs {
    /// Recipient Liquid address.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Amount to send in satoshis.
    #[arg(long = "amount-sat")]
    pub amount_sat: u64,

    /// Asset id to send, defaults to network policy asset.
    #[arg(long = "asset-id")]
    pub asset_id: Option<String>,

    #[command(flatten)]
    pub common: CommonRequestArgs,
}

#[derive(Debug, Clone, Args)]
pub struct SplitTransferArgs {
    /// Recipient Liquid address.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Number of equal outputs to create.
    #[arg(long = "split-parts")]
    pub split_parts: u16,

    /// Amount for each output in satoshis.
    #[arg(long = "part-amount-sat")]
    pub part_amount_sat: u64,

    /// Asset id to send, defaults to network policy asset.
    #[arg(long = "asset-id")]
    pub asset_id: Option<String>,

    #[command(flatten)]
    pub common: CommonRequestArgs,
}

#[derive(Debug, Clone, Args)]
pub struct IssueAssetArgs {
    /// Recipient Liquid address for both issued asset and reissuance token.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// New asset amount to issue in satoshis.
    #[arg(long = "issue-amount-sat")]
    pub issue_amount_sat: u64,

    /// Reissuance token amount to mint.
    #[arg(long = "token-amount-sat", default_value_t = 1_u64)]
    pub token_amount_sat: u64,

    /// 32-byte issuance entropy as hex.
    #[arg(long = "issuance-entropy-hex")]
    pub issuance_entropy_hex: String,

    /// Asset id used to fund issuance input, defaults to network policy asset.
    #[arg(long = "funding-asset-id")]
    pub funding_asset_id: Option<String>,

    #[command(flatten)]
    pub common: CommonRequestArgs,
}

#[derive(Debug, Clone, Args)]
pub struct ReissueAssetArgs {
    /// Recipient Liquid address for reissued asset and token change.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Reissuance token asset id to spend.
    #[arg(long = "reissue-token-asset-id")]
    pub reissue_token_asset_id: String,

    /// Reissued asset amount in satoshis.
    #[arg(long = "reissue-amount-sat")]
    pub reissue_amount_sat: u64,

    /// 32-byte reissued asset entropy as hex.
    #[arg(long = "asset-entropy-hex")]
    pub asset_entropy_hex: String,

    /// Reissuance token change amount in satoshis.
    #[arg(long = "token-change-sat", default_value_t = 1_u64)]
    pub token_change_sat: u64,

    #[command(flatten)]
    pub common: CommonRequestArgs,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum CallbackModeArg {
    #[value(name = "same_device_https")]
    SameDeviceHttps,
    #[value(name = "backend_push")]
    BackendPush,
    #[value(name = "qr_roundtrip")]
    QrRoundtrip,
}

#[derive(Debug, Clone, Args)]
pub struct ParsePayloadArgs {
    /// Input payload (raw `wa_v1/wa_resp_v1` string, fragment, or full URL)
    #[arg(value_name = "INPUT", required_unless_present = "input_file")]
    pub input: Option<String>,

    /// Read payload input from file instead of positional INPUT
    #[arg(long = "input-file", value_name = "PATH", conflicts_with = "input")]
    pub input_file: Option<PathBuf>,

    /// Force payload type; auto tries response first, then request
    #[arg(long = "kind", value_enum, default_value = "auto")]
    pub kind: ParseKindArg,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum ParseKindArg {
    #[value(name = "auto")]
    Auto,
    #[value(name = "request")]
    Request,
    #[value(name = "response")]
    Response,
}

#[derive(Debug, Clone, Args)]
pub struct RelayConnectArgs {
    /// Relay HTTP base URL (used for pairing create/delete).
    #[arg(long = "relay-http-url", default_value = "http://127.0.0.1:8787")]
    pub relay_http_url: String,

    /// Deep-link base URL for app handoff.
    #[arg(
        long = "base-link",
        default_value = "https://blockstream.com/walletabi/request"
    )]
    pub base_link: String,

    /// Directory for generated artifacts.
    #[arg(long = "out-dir", default_value = ".cache/wallet-abi-qrgen")]
    pub out_dir: PathBuf,

    /// Pixel scaling factor per QR module.
    #[arg(long = "pixel-per-module", default_value_t = 8_u8)]
    pub pixel_per_module: u8,

    /// Max time to wait for end-to-end relay roundtrip.
    #[arg(long = "wait-timeout-ms", default_value_t = 180_000_u64)]
    pub wait_timeout_ms: u64,

    #[command(subcommand)]
    pub request: RelayRequestCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum RelayRequestCommand {
    /// Build a simple transfer request and send via relay.
    SimpleTransfer(RelaySimpleTransferArgs),
    /// Build a split transfer request and send via relay.
    SplitTransfer(RelaySplitTransferArgs),
    /// Build an issue-asset request and send via relay.
    IssueAsset(RelayIssueAssetArgs),
    /// Build a reissue-asset request and send via relay.
    ReissueAsset(RelayReissueAssetArgs),
    /// Build an option-offer request and send via relay.
    #[command(subcommand)]
    OptionOffer(RelayOptionOfferCommand),
}

#[derive(Debug, Clone, Args)]
pub struct RelayRequestCommonArgs {
    /// Network to target.
    #[arg(long = "network", default_value = "testnet-liquid")]
    pub network: wallet_abi::Network,

    /// HTTPS origin to include in relay request envelope.
    #[arg(long = "origin", default_value = "https://dapp.example")]
    pub origin: String,

    /// Request id override, defaults to generated `UUIDv4`.
    #[arg(long = "request-id")]
    pub request_id: Option<String>,

    /// Relay pairing/request TTL in milliseconds (max 120000).
    #[arg(long = "ttl-ms", default_value_t = 120_000_u64)]
    pub ttl_ms: u64,

    /// Whether runtime should broadcast the transaction.
    #[arg(long = "broadcast", default_value_t = false)]
    pub broadcast: bool,

    /// Fee rate in sat/vbyte.
    #[arg(long = "fee-rate-sat-vb", default_value_t = 0.1_f32)]
    pub fee_rate_sat_vb: f32,
}

#[derive(Debug, Clone, Args)]
pub struct RelaySimpleTransferArgs {
    /// Recipient Liquid address.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Amount to send in satoshis.
    #[arg(long = "amount-sat")]
    pub amount_sat: u64,

    /// Asset id to send, defaults to network policy asset.
    #[arg(long = "asset-id")]
    pub asset_id: Option<String>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct RelaySplitTransferArgs {
    /// Recipient Liquid address.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Number of equal outputs to create.
    #[arg(long = "split-parts")]
    pub split_parts: u16,

    /// Amount for each output in satoshis.
    #[arg(long = "part-amount-sat")]
    pub part_amount_sat: u64,

    /// Asset id to send, defaults to network policy asset.
    #[arg(long = "asset-id")]
    pub asset_id: Option<String>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct RelayIssueAssetArgs {
    /// Recipient Liquid address for both issued asset and reissuance token.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// New asset amount to issue in satoshis.
    #[arg(long = "issue-amount-sat")]
    pub issue_amount_sat: u64,

    /// Reissuance token amount to mint.
    #[arg(long = "token-amount-sat", default_value_t = 1_u64)]
    pub token_amount_sat: u64,

    /// 32-byte issuance entropy as hex.
    #[arg(long = "issuance-entropy-hex")]
    pub issuance_entropy_hex: String,

    /// Asset id used to fund issuance input, defaults to network policy asset.
    #[arg(long = "funding-asset-id")]
    pub funding_asset_id: Option<String>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct RelayReissueAssetArgs {
    /// Recipient Liquid address for reissued asset and token change.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Reissuance token asset id to spend.
    #[arg(long = "reissue-token-asset-id")]
    pub reissue_token_asset_id: String,

    /// Reissued asset amount in satoshis.
    #[arg(long = "reissue-amount-sat")]
    pub reissue_amount_sat: u64,

    /// 32-byte reissued asset entropy as hex.
    #[arg(long = "asset-entropy-hex")]
    pub asset_entropy_hex: String,

    /// Reissuance token change amount in satoshis.
    #[arg(long = "token-change-sat", default_value_t = 1_u64)]
    pub token_change_sat: u64,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum RelayOptionOfferCommand {
    /// Build an option-offer create request and send via relay.
    Create(RelayOptionOfferCreateArgs),
    /// Build an option-offer exercise request and send via relay.
    Exercise(RelayOptionOfferExerciseArgs),
    /// Build an option-offer withdraw request and send via relay.
    Withdraw(RelayOptionOfferWithdrawArgs),
    /// Build an option-offer expiry request and send via relay.
    Expiry(RelayOptionOfferExpiryArgs),
}

#[derive(Debug, Clone, Args)]
pub struct RelayOptionOfferCreateArgs {
    /// Collateral asset id.
    #[arg(long = "collateral-asset-id")]
    pub collateral_asset_id: simplicityhl::elements::AssetId,

    /// Premium asset id.
    #[arg(long = "premium-asset-id")]
    pub premium_asset_id: simplicityhl::elements::AssetId,

    /// Settlement asset id.
    #[arg(long = "settlement-asset-id")]
    pub settlement_asset_id: simplicityhl::elements::AssetId,

    /// Expected collateral amount user will deposit.
    #[arg(long = "expected-to-deposit-collateral")]
    pub expected_to_deposit_collateral: u64,

    /// Expected premium amount user will deposit.
    #[arg(long = "expected-to-deposit-premium")]
    pub expected_to_deposit_premium: u64,

    /// Expected settlement amount user will receive on exercise.
    #[arg(long = "expected-to-get-settlement")]
    pub expected_to_get_settlement: u64,

    /// Unix timestamp after which expiry branch is valid.
    #[arg(long = "expiry-time")]
    pub expiry_time: u32,

    /// User x-only pubkey (32 bytes hex) used in covenant arguments.
    #[arg(long = "user-xonly-pubkey-hex")]
    pub user_xonly_pubkey_hex: String,

    /// Optional store path for local option-offer state.
    #[arg(long = "store-path")]
    pub store_path: Option<PathBuf>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct RelayOptionOfferExerciseArgs {
    /// Option-offer taproot pubkey-gen handle.
    #[arg(long = "option-offer-taproot-pubkey-gen")]
    pub option_offer_taproot_pubkey_gen: String,

    /// Encoded option-offer arguments (hex). If omitted, loaded from local store.
    #[arg(long = "encoded-option-offer-arguments")]
    pub encoded_option_offer_arguments: Option<String>,

    /// Optional store path for local option-offer state lookup.
    #[arg(long = "store-path")]
    pub store_path: Option<PathBuf>,

    /// Creation txid containing covenant outputs.
    #[arg(long = "creation-txid")]
    pub creation_tx_id: simplicityhl::elements::Txid,

    /// Collateral amount to request.
    #[arg(long = "collateral-amount")]
    pub collateral_amount: u64,

    /// Recipient address for released assets.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Explicit covenant collateral amount override.
    #[arg(long = "available-collateral-amount")]
    pub available_collateral_amount: Option<u64>,

    /// Explicit covenant premium amount override.
    #[arg(long = "available-premium-amount")]
    pub available_premium_amount: Option<u64>,

    /// Optional Esplora base URL for tx lookups.
    #[arg(long = "esplora-url")]
    pub esplora_url: Option<String>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct RelayOptionOfferWithdrawArgs {
    /// Option-offer taproot pubkey-gen handle.
    #[arg(long = "option-offer-taproot-pubkey-gen")]
    pub option_offer_taproot_pubkey_gen: String,

    /// Encoded option-offer arguments (hex). If omitted, loaded from local store.
    #[arg(long = "encoded-option-offer-arguments")]
    pub encoded_option_offer_arguments: Option<String>,

    /// Optional store path for local option-offer state lookup.
    #[arg(long = "store-path")]
    pub store_path: Option<PathBuf>,

    /// Exercise txid containing covenant settlement output.
    #[arg(long = "exercise-txid")]
    pub exercise_tx_id: simplicityhl::elements::Txid,

    /// Recipient address for settlement withdrawal.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Explicit covenant settlement output index override.
    #[arg(long = "settlement-vout")]
    pub settlement_vout: Option<u32>,

    /// Explicit covenant settlement amount override.
    #[arg(long = "settlement-amount-sat")]
    pub settlement_amount_sat: Option<u64>,

    /// Optional Esplora base URL for tx lookups.
    #[arg(long = "esplora-url")]
    pub esplora_url: Option<String>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct RelayOptionOfferExpiryArgs {
    /// Option-offer taproot pubkey-gen handle.
    #[arg(long = "option-offer-taproot-pubkey-gen")]
    pub option_offer_taproot_pubkey_gen: String,

    /// Encoded option-offer arguments (hex). If omitted, loaded from local store.
    #[arg(long = "encoded-option-offer-arguments")]
    pub encoded_option_offer_arguments: Option<String>,

    /// Optional store path for local option-offer state lookup.
    #[arg(long = "store-path")]
    pub store_path: Option<PathBuf>,

    /// Creation txid containing covenant collateral/premium outputs.
    #[arg(long = "creation-txid")]
    pub creation_tx_id: simplicityhl::elements::Txid,

    /// Recipient address for reclaimed assets.
    #[arg(long = "to-address")]
    pub to_address: String,

    /// Explicit covenant collateral amount override.
    #[arg(long = "collateral-amount")]
    pub collateral_amount: Option<u64>,

    /// Explicit covenant premium amount override.
    #[arg(long = "premium-amount")]
    pub premium_amount: Option<u64>,

    /// Optional Esplora base URL for tx lookups.
    #[arg(long = "esplora-url")]
    pub esplora_url: Option<String>,

    #[command(flatten)]
    pub common: RelayRequestCommonArgs,
}

#[derive(Debug, Clone, Args)]
pub struct OptionOfferStateArgs {
    #[command(subcommand)]
    pub command: OptionOfferStateCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum OptionOfferStateCommand {
    /// Import option-offer arguments into local state store.
    Import(OptionOfferStateImportArgs),
    /// Export option-offer arguments from local state store.
    Export(OptionOfferStateExportArgs),
}

#[derive(Debug, Clone, Args)]
pub struct OptionOfferStateImportArgs {
    /// Network used to validate taproot-handle to arguments binding.
    #[arg(long = "network")]
    pub network: wallet_abi::Network,

    /// Option-offer taproot pubkey-gen handle.
    #[arg(long = "option-offer-taproot-pubkey-gen")]
    pub option_offer_taproot_pubkey_gen: String,

    /// Encoded option-offer arguments (hex).
    #[arg(long = "encoded-option-offer-arguments")]
    pub encoded_option_offer_arguments: String,

    /// Optional store path for local option-offer state.
    #[arg(long = "store-path")]
    pub store_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct OptionOfferStateExportArgs {
    /// Option-offer taproot pubkey-gen handle.
    #[arg(long = "option-offer-taproot-pubkey-gen")]
    pub option_offer_taproot_pubkey_gen: String,

    /// Optional store path for local option-offer state.
    #[arg(long = "store-path")]
    pub store_path: Option<PathBuf>,
}
