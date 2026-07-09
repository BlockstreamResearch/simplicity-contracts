use std::sync::Arc;

use simplex::simplicityhl::ast::ElementsJetHinter;
use simplex::simplicityhl::simplicity::RedeemNode;
use simplex::simplicityhl::simplicity::elements::Transaction;
use simplex::simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplex::simplicityhl::simplicity::{BitMachine, Value};
use simplex::simplicityhl::tracker::{DefaultTracker, TrackerLogLevel};
use simplex::simplicityhl::{CompiledProgram, WitnessValues};

use super::error::ProgramError;

/// Satisfy and execute a compiled program in the provided environment.
/// Returns the pruned program and the resulting value.
///
/// # Errors
/// Returns an error if witness satisfaction, pruning, or execution fails.
pub fn run_program(
    program: &CompiledProgram,
    witness_values: WitnessValues,
    env: &ElementsEnv<Arc<Transaction>>,
    log_level: TrackerLogLevel,
) -> Result<(Arc<RedeemNode>, Value), ProgramError> {
    let satisfied = program
        .satisfy(witness_values)
        .map_err(ProgramError::WitnessSatisfaction)?;

    let mut tracker = DefaultTracker::build(satisfied.debug_symbols(), Box::new(ElementsJetHinter))
        .with_log_level(log_level);

    let pruned = satisfied
        .redeem()
        .prune_with_tracker(env, &mut tracker)
        .map_err(ProgramError::Pruning)?;
    let mut mac = BitMachine::for_program(&pruned)?;

    let result = mac.exec(&pruned, env).map_err(ProgramError::Execution)?;

    Ok((pruned, result))
}
