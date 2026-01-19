use std::sync::Arc;

use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::hashes::HashEngine as _;
use simplicityhl::simplicity::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use simplicityhl::simplicity::elements::{Script, Transaction};
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::{Cmr, RedeemNode, leaf_version};
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::{Arguments, CompiledProgram, TemplateProgram};
use simplicityhl_core::{ProgramError, run_program};

mod build_witness;
mod smt;

pub use build_witness::{DEPTH, SMTWitness, build_smt_storage_witness, u256};
pub use smt::SparseMerkleTree;

pub const SMT_STORAGE_SOURCE: &str = include_str!("source_simf/smt_storage.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_smt_storage_template_program() -> TemplateProgram {
    TemplateProgram::new(SMT_STORAGE_SOURCE).expect("INTERNAL: expected to compile successfully.")
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
///
/// Panics if program instantiation fails.
#[must_use]
pub fn get_smt_storage_compiled_program() -> CompiledProgram {
    let program = get_smt_storage_template_program();

    program.instantiate(Arguments::default(), true).unwrap()
}

/// Execute storage program with new state.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_smt_storage_program(
    witness: &SMTWitness,
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_smt_storage_witness(witness);
    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

fn smt_storage_script_ver(cmr: Cmr) -> (Script, LeafVersion) {
    (Script::from(cmr.as_ref().to_vec()), leaf_version())
}

/// Computes the TapData-tagged hash of the Simplicity state.
///
/// This involves hashing the tag "`TapData`" twice, followed by the
/// limbs of the state.
///
/// # Panics
///
/// This function **does not panic**.
/// All hashing operations (`sha256::Hash::engine`, `input`, `from_engine`) are
/// infallible, and iterating over the state limbs is safe.
#[must_use]
pub fn compute_tapdata_tagged_hash_of_the_state(
    leaf: &u256,
    path: &[(u256, bool); DEPTH],
) -> sha256::Hash {
    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(leaf);

    let mut current_hash = sha256::Hash::from_engine(eng);

    for (hash, is_right_direction) in path {
        let mut eng = sha256::Hash::engine();

        if *is_right_direction {
            eng.input(hash);
            eng.input(&current_hash.to_byte_array());
        } else {
            eng.input(&current_hash.to_byte_array());
            eng.input(hash);
        }

        current_hash = sha256::Hash::from_engine(eng);
    }
    current_hash
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
pub fn smt_storage_taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    leaf: &u256,
    path: &[(u256, bool); DEPTH],
    cmr: Cmr,
) -> TaprootSpendInfo {
    let (script, version) = smt_storage_script_ver(cmr);
    let state_hash = compute_tapdata_tagged_hash_of_the_state(leaf, path);

    // Build taproot tree with hidden leaf
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
mod smt_storage_tests {
    use super::*;
    use anyhow::Result;
    use rand::Rng as _;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};

    #[rustfmt::skip] // mangles byte vectors
    fn smt_storage_unspendable_internal_key() -> secp256k1::XOnlyPublicKey {
    	secp256k1::XOnlyPublicKey::from_slice(&[
    		0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    		0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0, 
    	])
    	.expect("key should be valid")
    }

    fn add_elements(smt: &mut SparseMerkleTree, num: u64) -> (u256, [u256; DEPTH], [bool; DEPTH]) {
        let mut rng = rand::rng();

        let mut leaf = [0u8; 32];
        let mut merkle_hashes = [[0u8; 32]; DEPTH];
        let mut path = [false; DEPTH];

        for _ in 0..num {
            leaf = rng.random();
            path = std::array::from_fn(|_| rng.random());
            merkle_hashes = smt.update(&leaf, path);
        }

        (leaf, merkle_hashes, path)
    }

    #[test]
    fn test_smt_storage_mint_path() -> Result<()> {
        let mut smt = SparseMerkleTree::new();
        let (old_leaf, merkle_hashes, path) = add_elements(&mut smt, 30);

        let merkle_data =
            std::array::from_fn(|i| (merkle_hashes[DEPTH - i - 1], path[DEPTH - i - 1]));

        let witness = SMTWitness::new(&old_leaf, &merkle_data);

        // Set last leaf qword to 1
        let mut new_leaf = old_leaf;
        for byte in new_leaf.iter_mut().skip(24) {
            *byte = 0;
        }
        new_leaf[31] = 1;
        smt.update(&new_leaf, path);

        let program = get_smt_storage_compiled_program();
        let cmr = program.commit().cmr();

        let old_spend_info: TaprootSpendInfo = smt_storage_taproot_spend_info(
            smt_storage_unspendable_internal_key(),
            &old_leaf,
            &merkle_data,
            cmr,
        );
        let old_script_pubkey = Script::new_v1_p2tr_tweaked(old_spend_info.output_key());

        let new_spend_info = smt_storage_taproot_spend_info(
            smt_storage_unspendable_internal_key(),
            &new_leaf,
            &merkle_data,
            cmr,
        );
        let new_script_pubkey = Script::new_v1_p2tr_tweaked(new_spend_info.output_key());

        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint0 = OutPoint::new(Txid::from_slice(&[0; 32])?, 0);
        pst.add_input(Input::from_prevout(outpoint0));
        pst.add_output(Output::new_explicit(
            new_script_pubkey.clone(),
            0,
            AssetId::default(),
            None,
        ));

        let control_block = old_spend_info
            .control_block(&smt_storage_script_ver(cmr))
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
            execute_smt_storage_program(&witness, &program, &env, TrackerLogLevel::Trace,).is_ok(),
            "expected success mint path"
        );

        Ok(())
    }
}
