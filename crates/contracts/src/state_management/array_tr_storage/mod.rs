//! Stores an array of `u256` limbs hashed into a hidden taproot leaf;
//! spending proves the old array and the changed index.

use crate::error::ProgramError;
use crate::runner::run_program;
use crate::scripts::{state_taproot_spend_info, tap_data_hash};

use std::sync::Arc;

use simplex::simplicityhl::ast::ElementsJetHinter;
use simplex::simplicityhl::simplicity::bitcoin::secp256k1;
use simplex::simplicityhl::simplicity::elements::Transaction;
use simplex::simplicityhl::simplicity::elements::taproot::TaprootSpendInfo;
use simplex::simplicityhl::simplicity::hashes::sha256;
use simplex::simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplex::simplicityhl::simplicity::{Cmr, RedeemNode};
use simplex::simplicityhl::tracker::TrackerLogLevel;
use simplex::simplicityhl::{Arguments, CompiledProgram, TemplateProgram};

mod build_witness;

pub use build_witness::{State, build_array_tr_storage_witness};

pub const ARRAY_TR_STORAGE_SOURCE: &str = include_str!("source_simf/array_tr_storage.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_array_tr_storage_template_program() -> TemplateProgram {
    TemplateProgram::new(ARRAY_TR_STORAGE_SOURCE, Box::new(ElementsJetHinter))
        .expect("embedded source should compile")
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_array_tr_storage_compiled_program() -> CompiledProgram {
    get_array_tr_storage_template_program()
        .instantiate(Arguments::default(), true)
        .unwrap()
}

/// Execute storage program with new state.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_array_tr_storage_program(
    state: &State,
    changed_index: u16,
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode>, ProgramError> {
    let witness_values = build_array_tr_storage_witness(state, changed_index);
    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

/// Compute the `TapData`-tagged hash of the concatenated state limbs.
#[must_use]
pub fn compute_tapdata_tagged_hash_of_the_state(state: &State) -> sha256::Hash {
    let mut state_bytes = Vec::with_capacity(state.limbs.len() * 32);
    for item in &state.limbs {
        state_bytes.extend_from_slice(item);
    }
    tap_data_hash(&state_bytes)
}

/// Compute the [`TaprootSpendInfo`] for a tap tree committing to the program
/// CMR and the `TapData`-tagged hash of the state array.
///
/// # Panics
/// Panics if the tap tree cannot be built (never happens for a valid CMR).
#[must_use]
pub fn array_tr_storage_taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    state: &State,
    cmr: Cmr,
) -> TaprootSpendInfo {
    state_taproot_spend_info(
        internal_key,
        compute_tapdata_tagged_hash_of_the_state(state),
        cmr,
    )
}

#[cfg(test)]
mod array_tr_storage_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use crate::scripts::{script_ver, unspendable_internal_key};

    use simplex::simplicityhl::elements::confidential::{Asset, Value};
    use simplex::simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplex::simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplex::simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplex::simplicityhl::simplicity::hashes::Hash as _;
    use simplex::simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};

    #[test]
    fn test_array_tr_storage_mint_path() -> Result<()> {
        let old_state = State::new();

        let mut new_state = old_state.clone();
        let changed_index = 2;
        new_state
            .set_num_to_last_qword(changed_index, 20)
            .expect("Failed to set number");

        let program = get_array_tr_storage_compiled_program();
        let cmr = program.commit().cmr();

        let old_spend_info =
            array_tr_storage_taproot_spend_info(unspendable_internal_key(), &old_state, cmr);
        let old_script_pubkey = Script::new_v1_p2tr_tweaked(old_spend_info.output_key());

        let new_spend_info =
            array_tr_storage_taproot_spend_info(unspendable_internal_key(), &new_state, cmr);
        let new_script_pubkey = Script::new_v1_p2tr_tweaked(new_spend_info.output_key());

        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint0 = OutPoint::new(Txid::from_slice(&[0; 32])?, 0);
        pst.add_input(Input::from_prevout(outpoint0));
        pst.add_output(Output::new_explicit(
            new_script_pubkey,
            0,
            AssetId::default(),
            None,
        ));

        let control_block = old_spend_info
            .control_block(&script_ver(cmr))
            .expect("must get control block");

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: old_script_pubkey,
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?,
            None,
            BlockHash::all_zeros(),
        );

        assert!(
            execute_array_tr_storage_program(
                &old_state,
                u16::try_from(changed_index)?,
                &program,
                &env,
                TrackerLogLevel::Trace,
            )
            .is_ok(),
            "expected success mint path"
        );

        Ok(())
    }
}
