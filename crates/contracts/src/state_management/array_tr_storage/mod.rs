use std::sync::Arc;

use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use simplicityhl::simplicity::elements::{Script, Transaction};
use simplicityhl::simplicity::hashes::sha256;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::{Cmr, RedeemNode};
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::{Arguments, CompiledProgram, TemplateProgram};
use wallet_abi::{ProgramError, run_program, simplicity_leaf_version, tap_data_hash};

mod build_witness;

pub use build_witness::{State, build_array_tr_storage_witness};

pub const ARRAY_TR_STORAGE_SOURCE: &str = include_str!("source_simf/array_tr_storage.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_array_tr_storage_template_program() -> TemplateProgram {
    TemplateProgram::new(ARRAY_TR_STORAGE_SOURCE)
        .expect("INTERNAL: expected to compile successfully.")
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
///
/// Panics if program instantiation fails.
#[must_use]
pub fn get_array_tr_storage_compiled_program() -> CompiledProgram {
    let program = get_array_tr_storage_template_program();

    program.instantiate(Arguments::default(), true).unwrap()
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
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_array_tr_storage_witness(state, changed_index);
    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

fn array_tr_storage_script_ver(cmr: Cmr) -> (Script, LeafVersion) {
    (
        Script::from(cmr.as_ref().to_vec()),
        simplicity_leaf_version(),
    )
}

#[must_use]
pub fn compute_tapdata_tagged_hash_of_the_state(state: &State) -> sha256::Hash {
    let mut state_bytes = Vec::with_capacity(state.limbs.len() * 32);
    for item in &state.limbs {
        state_bytes.extend_from_slice(item);
    }
    tap_data_hash(&state_bytes)
}

/// Given a Simplicity CMR and an internal key, computes the [`TaprootSpendInfo`]
/// for a Taptree with this CMR as its single leaf.
///
/// # Panics
///
/// This function **panics** if building the taproot tree fails (the calls to
/// `TaprootBuilder::add_leaf_with_ver` or `.add_hidden` return `Err`) or if
/// finalizing the builder fails. Those panics come from the `.expect(...)`
/// calls on the builder methods.
#[must_use]
pub fn array_tr_storage_taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    state: &State,
    cmr: Cmr,
) -> TaprootSpendInfo {
    let (script, version) = array_tr_storage_script_ver(cmr);
    let state_hash = compute_tapdata_tagged_hash_of_the_state(state);

    // Build taproot tree with hidden leaf.
    // Here, 'depth refers to the level at which the script and hash are transferred.
    // At depth 0, this will take the place of the root, meaning it will be impossible to place both
    // the `script` and the `state_hash`. At depth 2 or higher, additional nods are required,
    // which complicates the structure. Therefore, a value of 1 was chosen, where the `script` and
    // the `state_hash` values are leaves of the root.
    // `add_hidden`` in this context allows you to insert the hash as is, unlike add_leaf_with_ver, which hashes under the hood `script`.
    let builder = TaprootBuilder::new()
        .add_leaf_with_ver(1, script, version)
        .expect("tap tree should be valid")
        .add_hidden(1, state_hash)
        .expect("tap tree should be valid");

    builder
        .finalize(secp256k1::SECP256K1, internal_key)
        .expect("tap tree should be valid")
}

#[cfg(test)]
mod array_tr_storage_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::hashes::Hash as _;
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};

    #[rustfmt::skip] // mangles byte vectors
    fn array_tr_storage_unspendable_internal_key() -> secp256k1::XOnlyPublicKey {
    	secp256k1::XOnlyPublicKey::from_slice(&[
    		0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    		0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0, 
    	])
    	.expect("key should be valid")
    }

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

        let old_spend_info = array_tr_storage_taproot_spend_info(
            array_tr_storage_unspendable_internal_key(),
            &old_state,
            cmr,
        );
        let old_script_pubkey = Script::new_v1_p2tr_tweaked(old_spend_info.output_key());

        let new_spend_info = array_tr_storage_taproot_spend_info(
            array_tr_storage_unspendable_internal_key(),
            &new_state,
            cmr,
        );
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
            .control_block(&array_tr_storage_script_ver(cmr))
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
