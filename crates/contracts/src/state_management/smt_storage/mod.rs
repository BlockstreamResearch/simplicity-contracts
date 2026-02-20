use std::sync::Arc;

use simplicityhl::elements::TxInWitness;
use simplicityhl::elements::TxOut;
use simplicityhl::elements::taproot::ControlBlock;
use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::hashes::HashEngine as _;
use simplicityhl::simplicity::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use simplicityhl::simplicity::elements::{Script, Transaction};
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::simplicity::{Cmr, RedeemNode};
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::{Arguments, CompiledProgram, TemplateProgram};
use wallet_abi::{Network, ProgramError, run_program};
use wallet_abi::{simplicity_leaf_version, tap_data_hash};

mod build_witness;
mod smt;

pub use build_witness::{DEPTH, SMTWitness, build_smt_storage_witness, u256};
pub use smt::SparseMerkleTree;

#[must_use]
pub fn get_path_bits(path: &[bool], reverse: bool) -> u8 {
    let mut path_bits = 0u8;
    for (i, direction) in path.iter().enumerate().take(DEPTH) {
        let shift = if reverse { DEPTH - i - 1 } else { i };
        path_bits |= u8::from(*direction) << shift;
    }
    path_bits
}

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

#[must_use]
pub fn smt_storage_script_ver(cmr: Cmr) -> (Script, LeafVersion) {
    (
        Script::from(cmr.as_ref().to_vec()),
        simplicity_leaf_version(),
    )
}

/// Computes the control block for the given CMR and spend info.
///
/// # Panics
///
/// Panics if the control block cannot be retrieved. This typically happens if the
/// provided `cmr` corresponds to a script that is not present in the `spend_info` tree.
#[must_use]
pub fn control_block(cmr: Cmr, spend_info: &TaprootSpendInfo) -> ControlBlock {
    spend_info
        .control_block(&smt_storage_script_ver(cmr))
        .expect("must get control block")
}

/// Computes the TapData-tagged hash of the Simplicity state (SMT Root).
///
/// This involves hashing the tag "`TapData`" twice, followed by the leaf value
/// and the path bits, and finally performing the Merkle proof hashing up to the root.
///
/// # Security Note: Second Preimage Resistance
///
/// The `raw_path` (bit representation of the path) is included in the initial hash of the leaf
/// alongside the `leaf` data.
///
/// This is a defense mechanism against **second preimage attacks** (specifically, Merkle substitution attacks).
/// In Merkle trees (especially those with variable depth), an attacker might try to present
/// an internal node as a leaf, or vice versa. By including the path in the leaf's hash,
/// we strictly bind the data to its specific position in the tree hierarchy.
///
/// Although `DEPTH` is currently fixed (which mitigates some of these risks naturally),
/// this explicit domain separation ensures that a valid proof for a leaf at one position
/// cannot be reused or confused with a node at another level or branch, ensuring future
/// safety even if depth constraints change.
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
    let raw_path: [bool; DEPTH] = std::array::from_fn(|i| path[i].1);
    let mut tapdata_input = Vec::with_capacity(leaf.len() + 1);
    tapdata_input.extend_from_slice(leaf);
    tapdata_input.push(get_path_bits(&raw_path, false));
    let mut current_hash = tap_data_hash(&tapdata_input);

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

/// Constructs and verifies the Simplicity environment for the SMT storage execution.
///
/// # Errors
///
/// Returns an error if:
/// - The `input_index` is out of bounds for the provided `utxos`.
/// - The script pubkey of the UTXO at `input_index` does not match the expected SMT storage address.
pub fn get_and_verify_env(
    tx: &Transaction,
    program: &CompiledProgram,
    spend_info: &TaprootSpendInfo,
    utxos: &[TxOut],
    network: Network,
    input_index: usize,
) -> Result<ElementsEnv<Arc<Transaction>>, ProgramError> {
    let genesis_hash = network.genesis_hash();
    let cmr = program.commit().cmr();

    if utxos.len() <= input_index {
        return Err(ProgramError::UtxoIndexOutOfBounds {
            input_index,
            utxo_count: utxos.len(),
        });
    }

    let target_utxo = &utxos[input_index];
    let script_pubkey = Script::new_v1_p2tr_tweaked(spend_info.output_key());

    if target_utxo.script_pubkey != script_pubkey {
        return Err(ProgramError::ScriptPubkeyMismatch {
            expected_hash: script_pubkey.script_hash().to_string(),
            actual_hash: target_utxo.script_pubkey.script_hash().to_string(),
        });
    }

    Ok(ElementsEnv::new(
        Arc::new(tx.clone()),
        utxos
            .iter()
            .map(|utxo| ElementsUtxo {
                script_pubkey: utxo.script_pubkey.clone(),
                asset: utxo.asset,
                value: utxo.value,
            })
            .collect(),
        u32::try_from(input_index)?,
        cmr,
        control_block(cmr, spend_info),
        None,
        genesis_hash,
    ))
}

/// Finalizes the SMT storage transaction by executing the program and attaching the witness.
///
/// # Errors
///
/// Returns an error if:
/// - The environment verification fails (e.g., mismatched UTXOs or script pubkeys).
/// - The SMT storage program execution fails during the simulation.
#[allow(clippy::too_many_arguments)]
pub fn finalize_get_storage_transaction(
    mut tx: Transaction,
    spend_info: &TaprootSpendInfo,
    witness: &SMTWitness,
    storage_program: &CompiledProgram,
    utxos: &[TxOut],
    input_index: usize,
    network: Network,
    log_level: TrackerLogLevel,
) -> Result<Transaction, ProgramError> {
    let env = get_and_verify_env(
        &tx,
        storage_program,
        spend_info,
        utxos,
        network,
        input_index,
    )?;

    let pruned = execute_smt_storage_program(witness, storage_program, &env, log_level)?;

    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, spend_info).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}

#[cfg(test)]
mod smt_storage_tests {
    use super::*;
    use anyhow::Result;
    use simplicityhl::elements::secp256k1_zkp::rand::{Rng, thread_rng};
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};

    fn add_elements(smt: &mut SparseMerkleTree, num: u64) -> (u256, [u256; DEPTH], [bool; DEPTH]) {
        let mut rng = thread_rng();

        let mut leaf = [0u8; 32];
        let mut merkle_hashes = [[0u8; 32]; DEPTH];
        let mut path = [false; DEPTH];

        for _ in 0..num {
            leaf = rng.r#gen();
            path = std::array::from_fn(|_| rng.r#gen());
            merkle_hashes = smt.update(&leaf, path);
        }

        (leaf, merkle_hashes, path)
    }

    #[rustfmt::skip] // mangles byte vectors
    fn unspendable_internal_key() -> secp256k1::XOnlyPublicKey {
        secp256k1::XOnlyPublicKey::from_slice(&[
		    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
		    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0, 
	    ])
        .expect("key should be valid")
    }

    #[test]
    fn test_smt_storage_mint_path() -> Result<()> {
        let mut smt = SparseMerkleTree::new();
        let (old_leaf, merkle_hashes, path) = add_elements(&mut smt, 1);

        let merkle_data =
            std::array::from_fn(|i| (merkle_hashes[DEPTH - i - 1], path[DEPTH - i - 1]));

        let internal_key = unspendable_internal_key();
        let witness = SMTWitness::new(
            &internal_key.serialize(),
            &old_leaf,
            get_path_bits(&path, true),
            &merkle_data,
        );

        // Set last leaf qword to 1
        let mut new_leaf = old_leaf;
        for byte in new_leaf.iter_mut().skip(24) {
            *byte = 0;
        }
        new_leaf[31] = 1;
        smt.update(&new_leaf, path);

        let program = get_smt_storage_compiled_program();
        let cmr = program.commit().cmr();

        let old_spend_info: TaprootSpendInfo =
            smt_storage_taproot_spend_info(internal_key, &old_leaf, &merkle_data, cmr);
        let old_script_pubkey = Script::new_v1_p2tr_tweaked(old_spend_info.output_key());

        let new_spend_info =
            smt_storage_taproot_spend_info(internal_key, &new_leaf, &merkle_data, cmr);
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

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: old_script_pubkey,
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            control_block(cmr, &old_spend_info),
            None,
            BlockHash::all_zeros(),
        );

        assert!(
            execute_smt_storage_program(&witness, &program, &env, TrackerLogLevel::Trace).is_ok(),
            "expected success mint path"
        );

        Ok(())
    }
}
