//! High-level helpers for building and executing Simplicity programs on Liquid.
//!
//! This crate provides:
//! - Address derivation for P2TR Simplicity programs
//! - Utilities to compile and run programs with optional logging
//! - Helpers to finalize transactions with Simplicity script witnesses
//! - Esplora integration and small conveniences around Elements types

mod constants;
mod explorer;
mod runner;
mod scripts;
mod taproot_pubkey_gen;
mod trackers;

#[cfg(feature = "encoding")]
pub mod encoding {
    pub use bincode::{Decode, Encode};

    pub trait Encodable {
        fn encode(&self) -> anyhow::Result<Vec<u8>>
        where
            Self: Encode,
        {
            bincode::encode_to_vec(self, bincode::config::standard()).map_err(anyhow::Error::msg)
        }

        fn decode(buf: &[u8]) -> anyhow::Result<Self>
        where
            Self: Sized,
            Self: Decode<()>,
        {
            Ok(bincode::decode_from_slice(buf, bincode::config::standard())?.0)
        }

        fn to_hex(&self) -> anyhow::Result<String>
        where
            Self: Encode,
        {
            Ok(hex::encode(Encodable::encode(self)?))
        }

        fn from_hex(hex: &str) -> anyhow::Result<Self>
        where
            Self: bincode::Decode<()>,
        {
            Encodable::decode(&hex::decode(hex).map_err(anyhow::Error::msg)?)
        }
    }
}

pub use constants::*;
pub use explorer::*;
pub use runner::*;
pub use scripts::*;
pub use taproot_pubkey_gen::*;
pub use trackers::*;

#[cfg(feature = "encoding")]
pub use encoding::Encodable;

use std::collections::HashMap;
use std::sync::Arc;

use simplicityhl::num::U256;
use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::bitcoin::key::Keypair;
use simplicityhl::simplicity::bitcoin::{XOnlyPublicKey, secp256k1};
use simplicityhl::simplicity::elements::{Address, AddressParams, Transaction, TxInWitness, TxOut};
use simplicityhl::simplicity::hashes::Hash;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::str::WitnessName;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{CompiledProgram, Value, WitnessValues, elements};

/// Embedded Simplicity source for a basic P2PK program used to sign a single input.
pub const P2PK_SOURCE: &str = include_str!("source_simf/p2pk.simf");

/// Construct a P2TR address for the embedded P2PK program and the provided public key.
pub fn get_p2pk_address(
    x_only_public_key: &XOnlyPublicKey,
    params: &'static AddressParams,
) -> anyhow::Result<Address> {
    Ok(create_p2tr_address(
        get_p2pk_program(x_only_public_key)?.commit().cmr(),
        x_only_public_key,
        params,
    ))
}

/// Compile the embedded P2PK program with the given X-only public key as argument.
pub fn get_p2pk_program(account_public_key: &XOnlyPublicKey) -> anyhow::Result<CompiledProgram> {
    let arguments = simplicityhl::Arguments::from(HashMap::from([(
        WitnessName::from_str_unchecked("PUBLIC_KEY"),
        Value::u256(U256::from_byte_array(account_public_key.serialize())),
    )]));

    load_program(P2PK_SOURCE, arguments)
}

/// Execute the compiled P2PK program against the provided env, producing a pruned redeem node.
pub fn execute_p2pk_program(
    compiled_program: &CompiledProgram,
    keypair: &Keypair,
    env: ElementsEnv<Arc<Transaction>>,
    runner_log_level: RunnerLogLevel,
) -> anyhow::Result<Arc<RedeemNode<Elements>>> {
    let sighash_all = secp256k1::Message::from_digest(env.c_tx_env().sighash_all().to_byte_array());

    let witness_values = simplicityhl::WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("SIGNATURE"),
        Value::byte_array(keypair.sign_schnorr(sighash_all).serialize()),
    )]));

    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

/// Finalize the given transaction by attaching a Simplicity witness for the specified P2PK input.
///
/// Preconditions:
/// - `utxos[input_index]` must match the P2PK address derived from `keypair` and program CMR.
pub fn finalize_p2pk_transaction(
    mut tx: Transaction,
    utxos: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
    params: &'static AddressParams,
    genesis_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let p2pk_program = get_p2pk_program(&keypair.x_only_public_key().0)?;

    let env = get_and_verify_env(
        &tx,
        &p2pk_program,
        &keypair.x_only_public_key().0,
        utxos,
        params,
        genesis_hash,
        input_index,
    )?;

    let pruned = execute_p2pk_program(&p2pk_program, keypair, env, RunnerLogLevel::None)?;

    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, keypair.x_only_public_key().0).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_transaction(
    mut tx: Transaction,
    program: &CompiledProgram,
    program_public_key: &XOnlyPublicKey,
    utxos: &[TxOut],
    input_index: usize,
    witness_values: WitnessValues,
    params: &'static AddressParams,
    genesis_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let env = get_and_verify_env(
        &tx,
        program,
        program_public_key,
        utxos,
        params,
        genesis_hash,
        input_index,
    )?;

    let pruned = run_program(program, witness_values, env, RunnerLogLevel::None)?.0;

    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, *program_public_key).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}

pub fn get_and_verify_env(
    tx: &Transaction,
    program: &CompiledProgram,
    program_public_key: &XOnlyPublicKey,
    utxos: &[TxOut],
    params: &'static AddressParams,
    genesis_hash: elements::BlockHash,
    input_index: usize,
) -> anyhow::Result<ElementsEnv<Arc<Transaction>>> {
    let cmr = program.commit().cmr();

    anyhow::ensure!(
        utxos.len() > input_index,
        "UTXOs must be greater than input index"
    );

    let target_utxo = &utxos[input_index];
    let script_pubkey = create_p2tr_address(cmr, program_public_key, params).script_pubkey();

    anyhow::ensure!(
        target_utxo.script_pubkey == script_pubkey,
        "Expected the UTXO to be spent to have the same script"
    );

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
        input_index as u32,
        cmr,
        control_block(cmr, *program_public_key),
        None,
        genesis_hash,
    ))
}
