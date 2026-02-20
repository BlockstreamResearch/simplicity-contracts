#![warn(clippy::all, clippy::pedantic)]

use cli::commands::basic::Basic;
use cli::commands::option_offer::OptionOffer;
use cli::modules::utils::{esplora_url_from_network, wallet_data_root};

use anyhow::Result;

use clap::{Parser, Subcommand};

use wallet_abi::runtime::WalletRuntimeConfig;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Command-line entrypoint for the Simplicity helper CLI.
#[derive(Parser, Debug)]
#[command(
    name = "simplicity-cli",
    version,
    about = "Simplicity helper CLI for Liquid testnet"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Network on which to send a transaction
    #[arg(long = "network")]
    network: lwk_common::Network,
    #[arg(short, long, env = "MNEMONIC")]
    mnemonic: Option<String>,
}

/// Top-level subcommand groups.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Simple transaction utilities
    Basic {
        #[command(subcommand)]
        basic: Box<Basic>,
    },
    /// Option-offer contract utilities
    OptionOffer {
        #[command(subcommand)]
        option_offer: Box<OptionOffer>,
    },
    // /// Options contract utilities
    // Options {
    //     #[command(subcommand)]
    //     options: Box<Options>,
    // },
    // /// Storage utilities
    // Storage {
    //     #[command(subcommand)]
    //     storage: Box<SMTStorage>,
    // },
}

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    logging_init();

    let parsed = Cli::parse();

    let mnemonic = parsed.mnemonic.unwrap_or_else(|| TEST_MNEMONIC.to_string());

    let runtime = WalletRuntimeConfig::from_mnemonic(
        &mnemonic,
        parsed.network,
        &esplora_url_from_network(parsed.network),
        wallet_data_root(),
    )?;

    match parsed.command {
        Commands::Basic { basic } => basic.handle(runtime).await,
        Commands::OptionOffer { option_offer } => Box::pin(option_offer.handle(runtime)).await,
        // TODO: Commands::Options { options } => options.handle().await,
        // TODO: Commands::Storage { storage } => storage.handle().await,
    }
}

fn logging_init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(filter)
        .init();
}
