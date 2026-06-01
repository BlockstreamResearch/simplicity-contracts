use std::fmt::Debug;
use std::sync::Arc;

use crate::error::ProgramError;
use crate::runner::run_program;
use crate::scripts::{simplicity_leaf_version, tap_data_hash};

use rand::{random, Rng};
use simplex::simplicityhl::simplicity::bitcoin::secp256k1;
use simplex::simplicityhl::simplicity::elements::taproot::{
    LeafVersion, TaprootBuilder, TaprootSpendInfo,
};
use simplex::simplicityhl::simplicity::elements::{Script, Transaction};
use simplex::simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplex::simplicityhl::simplicity::jet::Elements;
use simplex::simplicityhl::simplicity::{Cmr, RedeemNode};
use simplex::simplicityhl::tracker::TrackerLogLevel;
use simplex::simplicityhl::{elements, CompiledProgram, TemplateProgram};

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
    (
        Script::from(cmr.as_ref().to_vec()),
        simplicity_leaf_version(),
    )
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
    let state_hash = tap_data_hash(&state);

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
    use rand::random;
    use simplex::simplicityhl::elements::confidential::{Asset, Value};
    use simplex::simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplex::simplicityhl::elements::{self, AssetId, OutPoint, Script, Txid};
    use simplex::simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplex::simplicityhl::simplicity::hashes::Hash as _;
    use simplex::simplicityhl::simplicity::jet::elements::ElementsEnv;
    use std::sync::Arc;

    #[test]
    fn test_bytes32_tr_mint_path() -> Result<()> {
        let old_state: [u8; 32] = random();

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
            vec![
                simplex::simplicityhl::simplicity::jet::elements::ElementsUtxo {
                    script_pubkey: old_script_pubkey,
                    asset: Asset::default(),
                    value: Value::default(),
                },
            ],
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

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::proptest;
use simplex::simplicityhl::elements::{AssetId, OutPoint, TxOut, TxOutWitness, Txid};

use crate::artifacts::bytes32_tr_storage::derived_bytes32_tr_storage::{
    Bytes32TrStorageArguments, Bytes32TrStorageWitness,
};
use crate::artifacts::bytes32_tr_storage::Bytes32TrStorageProgram;
use simplex::constants::DUMMY_SIGNATURE;
use simplex::either::Either;
use simplex::simplicityhl::elements::confidential::{Asset, Value};
use simplex::simplicityhl::elements::hashes::Hash;
use simplex::simplicityhl::elements::hex::ToHex;
use simplex::simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplex::simplicityhl::elements::taproot::ControlBlock;
use simplex::transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature};

fn arb_either<L: 'static + Debug, R: 'static + Debug>(
    left: impl Strategy<Value = L> + 'static,
    right: impl Strategy<Value = R> + 'static,
) -> impl Strategy<Value = Either<L, R>> {
    prop_oneof![left.prop_map(Either::Left), right.prop_map(Either::Right),]
}

fn arb_u8() -> impl Strategy<Value = u8> {
    any::<u8>()
}

fn arb_2_bytes() -> impl Strategy<Value = [u8; 2]> {
    any::<[u8; 2]>()
}

fn arb_4_bytes() -> impl Strategy<Value = [u8; 4]> {
    any::<[u8; 4]>()
}

fn arb_8_bytes() -> impl Strategy<Value = [u8; 8]> {
    any::<[u8; 8]>()
}

fn arb_16_bytes() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

fn arb_32_bytes() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_pubkey() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_64_bytes() -> impl Strategy<Value = [u8; 64]> {
    any::<[u8; 64]>()
}

fn arb_witness() -> impl Strategy<Value = Bytes32TrStorageWitness> {
    arb_32_bytes().prop_map(|state| Bytes32TrStorageWitness { state })
}

fn arb_arguments() -> impl Strategy<Value = Bytes32TrStorageArguments> {
    Just(Bytes32TrStorageArguments {})
}

fn arb_program_params()
-> impl Strategy<Value = (Bytes32TrStorageArguments, Bytes32TrStorageWitness)> {
    (arb_arguments(), arb_witness())
}

fn arb_asset_id() -> impl Strategy<Value = (AssetId)> {
    arb_32_bytes().prop_map(|x| AssetId::from_slice(&x).unwrap())
}

fn modify_state(mut state: [u8; 32]) -> [u8; 32] {
    let mut val = u64::from_be_bytes(state[24..].try_into().unwrap());
    val += 1;
    state[24..].copy_from_slice(&val.to_be_bytes());
    state
}

proptest! {
    #[test]
    fn proptesting_example((_arguments, witness1) in arb_program_params()) {
        let old_state: [u8; 32] = witness1.state;

        let new_state = modify_state(old_state);
        dbg!(old_state.to_hex(), new_state.to_hex());

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
            vec![
                simplex::simplicityhl::simplicity::jet::elements::ElementsUtxo {
                    script_pubkey: old_script_pubkey,
                    asset: Asset::default(),
                    value: Value::default(),
                },
            ],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?, // Real control block
            None,
            elements::BlockHash::all_zeros(),
        );

        execute_bytes32_tr_program(old_state, &program, &env, TrackerLogLevel::None).unwrap();
        assert!(
            execute_bytes32_tr_program(old_state, &program, &env, TrackerLogLevel::None).is_ok(),
            "expected success mint path"
        );
    }
}

use simplex::program::core::ProgramTrait;
use simplex::program::WitnessTrait;
use simplex::provider::SimplicityNetwork;

#[test]
fn proptesting_example_sim2() {
    let witness1 = Bytes32TrStorageWitness {
        state: { random() },
    };
    let old_state: [u8; 32] = witness1.state;

    let new_state = modify_state(old_state);
    dbg!(old_state.to_hex(), new_state.to_hex());

    let mut program = Bytes32TrStorageProgram::new(Bytes32TrStorageArguments {})
        .with_taproot_pubkey(unspendable_internal_key())
        .with_storage_capacity(1);
    program.set_storage_at(0, old_state);
    let compiled = program.as_ref().load().unwrap();
    let cmr = compiled.commit().cmr();
    let network = SimplicityNetwork::default_regtest();

    // Fix: taproot_spend_info needs to take the *new* state for generating the spending environment
    // The previous state script pubkey bounds the executing program. Wait, taproot node needs to reflect `old_state` to be the current contract UTXO.
    let old_spend_info = taproot_spend_info(unspendable_internal_key(), old_state, cmr);
    let old_script_pubkey = program.get_script_pubkey(&network);

    let new_spend_info = taproot_spend_info(unspendable_internal_key(), new_state, cmr);
    let new_script_pubkey = Script::new_v1_p2tr_tweaked(new_spend_info.output_key());

    // Build transaction
    let mut pst = PartiallySignedTransaction::new_v2();
    let outpoint0 = OutPoint::new(Txid::from_slice(&[0; 32]).unwrap(), 0);
    {
        let mut input = Input::from_prevout(outpoint0);
        input.witness_utxo = Some(TxOut {
            asset: Asset::Explicit(network.policy_asset()),
            value: Value::Explicit(0),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: old_script_pubkey,
            witness: TxOutWitness::default(),
        });

        let control_block = old_spend_info
            .control_block(&script_ver(cmr))
            .expect("Must retrieve control block for the script path");

        let mut tap_scripts = std::collections::BTreeMap::new();
        tap_scripts.insert(
            ControlBlock::from_slice(&control_block.serialize()).unwrap(),
            (
                Script::from(cmr.as_ref().to_vec()),
                simplicity_leaf_version(),
            ),
        );
        input.tap_scripts = tap_scripts;

        pst.add_input(input);
    }
    pst.add_output(Output::new_explicit(
        new_script_pubkey,
        0,
        AssetId::default(),
        None,
    ));

    program
        .as_ref()
        .execute(
            &pst,
            &witness1.build_witness(),
            0,
            &SimplicityNetwork::default_regtest(),
        )
        .unwrap();
    assert!(
        program
            .as_ref()
            .execute(
                &pst,
                &witness1.build_witness(),
                0,
                &SimplicityNetwork::default_regtest()
            )
            .is_ok(),
        "expected success mint path"
    );
}

proptest! {
    #[test]
    fn proptesting_example_simplex((_arguments, witness1) in arb_program_params()) {
        let old_state: [u8; 32] = witness1.state;

        let new_state = modify_state(old_state);
        dbg!(old_state.to_hex(), new_state.to_hex());

        let mut program = Bytes32TrStorageProgram::new(Bytes32TrStorageArguments {})
            .with_taproot_pubkey(unspendable_internal_key())
            .with_storage_capacity(1);
        program.set_storage_at(0, old_state);
        let compiled = program.as_ref().load().unwrap();
        let cmr = compiled.commit().cmr();
        let network = SimplicityNetwork::default_regtest();

        // Fix: taproot_spend_info needs to take the *new* state for generating the spending environment
        // The previous state script pubkey bounds the executing program. Wait, taproot node needs to reflect `old_state` to be the current contract UTXO.
        let old_spend_info = taproot_spend_info(unspendable_internal_key(), old_state, cmr);
        let old_script_pubkey = program.get_script_pubkey(&network);

        let new_spend_info = taproot_spend_info(unspendable_internal_key(), new_state, cmr);
        let new_script_pubkey = Script::new_v1_p2tr_tweaked(new_spend_info.output_key());

        // Build transaction
        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint0 = OutPoint::new(Txid::from_slice(&[0; 32]).unwrap(), 0);
        {
            let mut input = Input::from_prevout(outpoint0);
            input.witness_utxo = Some(TxOut {
                asset: Asset::Explicit(network.policy_asset()),
                value: Value::Explicit(0),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: old_script_pubkey,
                witness: TxOutWitness::default(),
            });

            let control_block = old_spend_info
                .control_block(&script_ver(cmr))
                .expect("Must retrieve control block for the script path");

            let mut tap_scripts = std::collections::BTreeMap::new();
            tap_scripts.insert(
                ControlBlock::from_slice(&control_block.serialize()).unwrap(),
                (Script::from(cmr.as_ref().to_vec()), simplicity_leaf_version()),
            );
            input.tap_scripts = tap_scripts;

            pst.add_input(input);
        }
        pst.add_output(Output::new_explicit(
            new_script_pubkey,
            0,
            AssetId::default(),
            None,
        ));

        program
            .as_ref()
            .execute(
                &pst,
                &witness1.build_witness(),
                0,
                &SimplicityNetwork::default_regtest(),
            )
            .unwrap();
        assert!(
            program
                .as_ref()
                .execute(
                    &pst,
                    &witness1.build_witness(),
                    0,
                    &SimplicityNetwork::default_regtest()
                )
                .is_ok(),
            "expected success mint path"
        );
    }
}
