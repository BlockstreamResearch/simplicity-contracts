//! Dual Currency Deposit (DCD) – price-attested Simplicity covenant for Liquid testnet.
//!
//! This module exposes helpers to compile, execute, and finalize the DCD program:
//! - `get_dcd_template_program`, `get_dcd_program`, `get_compiled_dcd_program`
//! - `get_dcd_address` to derive the covenant P2TR address bound to a Taproot pubkey
//! - `execute_dcd_program` to run a specific branch with witness values
//! - `finalize_dcd_transaction_on_liquid_testnet` to attach the Simplicity witness to a tx input
//!
//! DCD flows supported by the Simplicity program and CLI:
//! - Maker funding: deposit settlement asset and collateral, issue grantor tokens
//! - Taker funding: deposit collateral within the funding window and receive filler tokens
//! - Settlement at `settlement_height`: oracle Schnorr-signature selects LBTC vs ALT branch
//! - Early/post-expiry termination: taker returns filler; maker burns grantor tokens
//! - Token merge utilities: merge 2/3/4 token UTXOs
//!
//! See `crates/cli/README.md` for canonical CLI usage and parameters.
//! All transactions are explicit and target Liquid testnet.

use std::sync::Arc;

use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::elements::{Address, Transaction, TxOut};
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::{CompiledProgram, TemplateProgram};
use wallet_abi::{
    Network, ProgramError, create_p2tr_address, finalize_transaction, load_program, run_program,
};

mod build_arguments;
mod build_witness;

pub use build_arguments::{DCDArguments, DCDRatioArguments};
pub use build_witness::{DcdBranch, MergeBranch, TokenBranch, build_dcd_witness};

pub const PRICE_ATTESTED_SDK_SOURCE: &str = include_str!("source_simf/dual_currency_deposit.simf");

/// Get the DCD template program for instantiation with arguments.
///
/// # Panics
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_dcd_template_program() -> TemplateProgram {
    TemplateProgram::new(PRICE_ATTESTED_SDK_SOURCE)
        .expect("INTERNAL: expected DCD Price Attested Program to compile successfully.")
}

/// Derive P2TR address for a DCD contract with given arguments.
///
/// # Errors
/// Returns error if program compilation fails.
pub fn get_dcd_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &DCDArguments,
    network: Network,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_dcd_program(arguments)?.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

/// Compile DCD program with the given arguments.
///
/// # Errors
/// Returns error if compilation fails.
pub fn get_dcd_program(arguments: &DCDArguments) -> Result<CompiledProgram, ProgramError> {
    load_program(PRICE_ATTESTED_SDK_SOURCE, arguments.build_arguments())
}

/// Get compiled DCD program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_compiled_dcd_program(arguments: &DCDArguments) -> CompiledProgram {
    let program = get_dcd_template_program();

    program
        .instantiate(arguments.build_arguments(), true)
        .unwrap()
}

/// Execute DCD program with witness values for the specified branches.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_dcd_program(
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    token_branch: TokenBranch,
    branch: &DcdBranch,
    merge_branch: MergeBranch,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_dcd_witness(token_branch, branch, merge_branch);
    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

/// Finalize DCD transaction by attaching Simplicity witness on Liquid testnet.
///
/// # Errors
/// Returns error if program execution or environment verification fails.
#[allow(clippy::too_many_arguments)]
pub fn finalize_dcd_transaction_on_liquid_testnet(
    tx: Transaction,
    dcd_program: &CompiledProgram,
    dcd_public_key: &XOnlyPublicKey,
    utxos: &[TxOut],
    input_index: u32,
    token_branch: TokenBranch,
    branch: &DcdBranch,
    merge_branch: MergeBranch,
    log_level: TrackerLogLevel,
) -> Result<Transaction, ProgramError> {
    let network = Network::TestnetLiquid;
    let input_index = input_index as usize;
    let witness_values = build_dcd_witness(token_branch, branch, merge_branch);
    finalize_transaction(
        tx,
        dcd_program,
        dcd_public_key,
        utxos,
        input_index,
        witness_values,
        network,
        log_level,
    )
}

#[must_use]
pub fn oracle_msg(expiry_height: u32, price_at_current_block_height: u64) -> [u8; 32] {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&expiry_height.to_be_bytes());
    b[4..].copy_from_slice(&price_at_current_block_height.to_be_bytes());
    sha256::Hash::hash(&b).to_byte_array()
}
