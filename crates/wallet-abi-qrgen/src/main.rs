#![warn(clippy::all, clippy::pedantic)]

use clap::Parser;
use wallet_abi_qrgen::cli::Cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    wallet_abi_qrgen::run(cli)
}
