//! Stores 32 bytes of state as a hidden taproot leaf next to the program
//! leaf; spending reveals the old state and commits to the new one.
use std::sync::Arc;

use crate::error::ProgramError;
use crate::runner::run_program;
use crate::scripts::{state_taproot_spend_info, tap_data_hash};

use simplex::simplicityhl::ast::ElementsJetHinter;
use simplex::simplicityhl::simplicity::bitcoin::secp256k1;
use simplex::simplicityhl::simplicity::elements::Transaction;
use simplex::simplicityhl::simplicity::elements::taproot::TaprootSpendInfo;
use simplex::simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplex::simplicityhl::simplicity::{Cmr, RedeemNode};
use simplex::simplicityhl::tracker::TrackerLogLevel;
use simplex::simplicityhl::{CompiledProgram, TemplateProgram};

mod build_witness;

pub use build_witness::build_bytes32_tr_witness;

pub const BYTES32_TR_STORAGE_SOURCE: &str = include_str!("source_simf/bytes32_tr_storage.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_bytes32_tr_template_program() -> TemplateProgram {
    TemplateProgram::new(BYTES32_TR_STORAGE_SOURCE, Box::new(ElementsJetHinter))
        .expect("embedded source should compile")
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_bytes32_tr_compiled_program() -> CompiledProgram {
    get_bytes32_tr_template_program()
        .instantiate(simplex::simplicityhl::Arguments::default(), true)
        .unwrap()
}

/// Execute storage program with new state.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_bytes32_tr_program(
    state: [u8; 32],
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode>, ProgramError> {
    let witness_values = build_bytes32_tr_witness(state);
    Ok(run_program(compiled_program, witness_values, env, log_level)?.0)
}

/// Compute the [`TaprootSpendInfo`] for a tap tree committing to the program
/// CMR and the `TapData`-tagged hash of the 32-byte state.
///
/// # Panics
/// Panics if the tap tree cannot be built (never happens for a valid CMR).
#[must_use]
pub fn taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    state: [u8; 32],
    cmr: Cmr,
) -> TaprootSpendInfo {
    state_taproot_spend_info(internal_key, tap_data_hash(&state), cmr)
}

#[cfg(test)]
mod bytes32_tr_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use crate::scripts::{script_ver, unspendable_internal_key};

    use simplex::simplicityhl::elements::confidential::{Asset, Value};
    use simplex::simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplex::simplicityhl::elements::{self, AssetId, OutPoint, Script, Txid};
    use simplex::simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplex::simplicityhl::simplicity::hashes::Hash as _;
    use simplex::simplicityhl::simplicity::jet::elements::ElementsEnv;

    #[test]
    fn test_bytes32_tr_mint_path() -> Result<()> {
        let old_state: [u8; 32] = [0u8; 32];

        // Increment the last qword of the state by one.
        let mut new_state = old_state;
        let mut val = u64::from_be_bytes(new_state[24..].try_into().unwrap());
        val += 1;
        new_state[24..].copy_from_slice(&val.to_be_bytes());

        let program = get_bytes32_tr_compiled_program();
        let cmr = program.commit().cmr();

        let old_spend_info = taproot_spend_info(unspendable_internal_key(), old_state, cmr);
        let old_script_pubkey = Script::new_v1_p2tr_tweaked(old_spend_info.output_key());

        let new_spend_info = taproot_spend_info(unspendable_internal_key(), new_state, cmr);
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
            .expect("Must retrieve control block for the script path");

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                simplex::simplicityhl::simplicity::jet::elements::ElementsUtxo {
                    script_pubkey: old_script_pubkey,
                    asset: Asset::default(),
                    value: Value::default(),
                },
            ],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?,
            None,
            elements::BlockHash::all_zeros(),
        );

        assert!(
            execute_bytes32_tr_program(old_state, &program, &env, TrackerLogLevel::None).is_ok(),
            "expected success mint path"
        );

        Ok(())
    }
}
