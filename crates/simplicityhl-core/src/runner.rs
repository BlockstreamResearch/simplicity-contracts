//! Program execution helpers and logging levels for Simplicity programs.
//!
//! Provides `run_program` which satisfies and executes a compiled program
//! against an `ElementsEnv`, with optional debug and jet-trace logging.

use crate::DefaultTracker;

use std::sync::Arc;

use simplicityhl::simplicity::elements::Transaction;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::{BitMachine, RedeemNode, Value};
use simplicityhl::{CompiledProgram, WitnessValues};

/// Controls verbosity of program execution.
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Copy, Clone, Debug)]
pub enum RunnerLogLevel {
    #[default]
    None,
    Debug,
    Trace,
}

/// Satisfy and execute a compiled program in the provided environment.
/// Returns the pruned program and the resulting value.
pub fn run_program(
    program: &CompiledProgram,
    witness_values: WitnessValues,
    env: ElementsEnv<Arc<Transaction>>,
    log_level: RunnerLogLevel,
) -> anyhow::Result<(Arc<RedeemNode<Elements>>, Value)> {
    let satisfied = program
        .satisfy(witness_values)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let pruned = match satisfied.redeem().prune(&env) {
        Ok(pruned) => pruned,
        Err(e) => return Err(e.into()),
    };
    let mut mac = match BitMachine::for_program(&pruned) {
        Ok(mac) => mac,
        Err(e) => return Err(e.into()),
    };

    let mut tracker = {
        let mut t = DefaultTracker::new(satisfied.debug_symbols());
        if log_level >= RunnerLogLevel::Debug {
            t = t.with_default_debug_sink();
        }
        if log_level >= RunnerLogLevel::Trace {
            t = t.with_default_jet_trace_sink();
        }
        t
    };

    match mac.exec_with_tracker(&pruned, &env, &mut tracker) {
        Ok(res) => Ok((pruned, res)),
        Err(e) => Err(e.into()),
    }
}
