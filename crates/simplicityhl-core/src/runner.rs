//! Program execution helpers and logging levels for Simplicity programs.
//!
//! Provides `run_program` which satisfies and executes a compiled program
//! against an `ElementsEnv`, with optional debug and jet-trace logging.

use std::sync::Arc;

use simplicityhl::simplicity::elements::Transaction;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::{BitMachine, RedeemNode, Value};
use simplicityhl::tracker::{DefaultTracker, TrackerLogLevel};
use simplicityhl::{CompiledProgram, WitnessValues};

/// Satisfy and execute a compiled program in the provided environment.
/// Returns the pruned program and the resulting value.
///
/// # Errors
/// Returns error if witness satisfaction or program execution fails.
pub fn run_program(
    program: &CompiledProgram,
    witness_values: WitnessValues,
    env: &ElementsEnv<Arc<Transaction>>,
    log_level: TrackerLogLevel,
) -> anyhow::Result<(Arc<RedeemNode<Elements>>, Value)> {
    let satisfied = program
        .satisfy(witness_values)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut tracker = DefaultTracker::new(satisfied.debug_symbols()).with_log_level(log_level);

    let pruned = satisfied.redeem().prune_with_tracker(env, &mut tracker)?;
    let mut mac = BitMachine::for_program(&pruned)?;

    match mac.exec(&pruned, env) {
        Ok(res) => Ok((pruned, res)),
        Err(e) => Err(e.into()),
    }
}
