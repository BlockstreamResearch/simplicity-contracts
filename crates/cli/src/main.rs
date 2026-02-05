#![warn(clippy::all, clippy::pedantic)]

//! Simplicity helper CLI for Liquid testnet.
//!
//! This binary exposes multiple subcommand groups to work with Liquid testnet:
//! - `basic`: P2PK utilities such as deriving addresses and building simple transfers.
//! - `options`: Utilities for the options contract.

mod commands;
mod explorer;
mod modules;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands::basic::Basic;
use crate::commands::options::Options;
use crate::commands::smt_storage::SMTStorage;

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
}

/// Top-level subcommand groups.
#[derive(Subcommand, Debug)]
enum Commands {
    /// P2PK and simple transaction utilities
    Basic {
        #[command(subcommand)]
        basic: Box<Basic>,
    },
    /// Options contract utilities
    Options {
        #[command(subcommand)]
        options: Box<Options>,
    },
    /// Storage utilities
    Storage {
        #[command(subcommand)]
        storage: Box<SMTStorage>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Basic { basic } => basic.handle().await,
        Commands::Options { options } => options.handle().await,
        Commands::Storage { storage } => storage.handle().await,
    }
}
