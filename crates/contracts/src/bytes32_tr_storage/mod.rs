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
use simplicityhl::{CompiledProgram, TemplateProgram};
use simplicityhl_core::{ProgramError, run_program};

mod build_witness;

pub use build_witness::build_bytes32_tr_witness;

pub const BYTES32_TR_STORAGE_SOURCE: &str = include_str!("source_simf/bytes32_tr_storage.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_bytes32_tr_template_program() -> TemplateProgram {
    TemplateProgram::new(BYTES32_TR_STORAGE_SOURCE)
        .expect("INTERNAL: expected to compile successfully.")
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_bytes32_tr_compiled_program() -> CompiledProgram {
    let program = get_bytes32_tr_template_program();

    program
        .instantiate(simplicityhl::Arguments::default(), true)
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
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_bytes32_tr_witness(state);
    Ok(run_program(compiled_program, witness_values, env, log_level)?.0)
}

/// The unspendable internal key specified in BIP-0341.
///
/// # Panics
///
/// This function **panics** if the hard-coded 32-byte slice is not a valid
/// x-only public key. The panic originates from
/// `secp256k1::XOnlyPublicKey::from_slice(...).expect(...)`.
/// The unspendable internal key specified in BIP-0341.
#[rustfmt::skip] // mangles byte vectors
#[must_use] 
pub fn unspendable_internal_key() -> secp256k1::XOnlyPublicKey {
	secp256k1::XOnlyPublicKey::from_slice(&[
		0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
		0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0, 
	])
	.expect("key should be valid")
}

fn script_ver(cmr: Cmr) -> (Script, LeafVersion) {
    (Script::from(cmr.as_ref().to_vec()), leaf_version())
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
pub fn taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    state: [u8; 32],
    cmr: Cmr,
) -> TaprootSpendInfo {
    let (script, version) = script_ver(cmr);

    // Compute TapData-tagged hash of the state
    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(&state);
    let state_hash = sha256::Hash::from_engine(eng);

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
mod bytes32_tr_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{self, AssetId, OutPoint, Script, Txid};
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::jet::elements::ElementsEnv;

    #[test]
    fn test_bytes32_tr_mint_path() -> Result<()> {
        let old_state: [u8; 32] = [0u8; 32];

        // Calculate new_state
        // NOTE: Our example can be done with the line new_state[31] = 1
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

        // Build transaction
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

        // Set up environment
        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![simplicityhl::simplicity::jet::elements::ElementsUtxo {
                script_pubkey: old_script_pubkey,
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?, // Real control block
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
