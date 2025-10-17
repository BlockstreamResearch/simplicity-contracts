//! Simplicity helper CLI for Liquid testnet.
//!
//! This binary exposes multiple subcommand groups to work with Liquid testnet:
//! - `basic`: P2PK utilities such as deriving addresses and building simple transfers.
//! - `options`: Utilities for the options contract (address derivation and funding paths).
//!
//! Run `simplicity-cli --help` or any subcommand with `--help` for usage.

mod commands;
mod modules;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands::basic::Basic;
use crate::commands::options::Options;

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
    /// P2PK and simple transaction utilities (addresses, transfers, splits, assets)
    Basic {
        #[command(subcommand)]
        basic: Box<Basic>,
    },
    /// Options contract utilities (creation and funding paths)
    Options {
        #[command(subcommand)]
        options: Box<Options>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Basic { basic } => basic.handle(),
        Commands::Options { options } => options.handle(),
    }
}
