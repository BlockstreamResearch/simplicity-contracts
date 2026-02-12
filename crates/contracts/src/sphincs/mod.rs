use std::collections::HashMap;
use std::sync::Arc;

use simplicityhl::elements::Address;
use simplicityhl::elements::{Transaction, TxInWitness, TxOut};
use simplicityhl::num::U256;
use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::str::WitnessName;
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{Arguments, CompiledProgram, TemplateProgram, Value, WitnessValues};
use simplicityhl_core::{
    ProgramError, SimplicityNetwork, control_block, create_p2tr_address, get_and_verify_env,
    load_program, run_program,
};

pub const SPHINCS_MAIN_SOURCE: &str = include_str!("source_simf/sphincs_main.simf");

/// Get the SPHINCS main template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_sphincs_main_template_program() -> TemplateProgram {
    TemplateProgram::new(SPHINCS_MAIN_SOURCE)
        .expect("INTERNAL: expected SPHINCS main program to compile successfully.")
}

/// Derive P2TR address for the SPHINCS main contract.
///
/// # Errors
///
/// Returns error if program compilation fails.
pub fn get_sphincs_main_address(
    x_only_public_key: &XOnlyPublicKey,
    network: SimplicityNetwork,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_sphincs_main_program()?.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

/// Compile the SPHINCS main program.
///
/// # Errors
///
/// Returns error if compilation fails.
pub fn get_sphincs_main_program() -> Result<CompiledProgram, ProgramError> {
    load_program(SPHINCS_MAIN_SOURCE, Arguments::default())
}

/// Execute SPHINCS main program with the provided witness values.
///
/// # Errors
///
/// Returns error if program execution fails.
pub fn execute_sphincs_main_program(
    compiled_program: &CompiledProgram,
    witness_values: WitnessValues,
    env: &ElementsEnv<Arc<Transaction>>,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

/// Finalize SPHINCS main transaction with Simplicity witness.
///
/// # Errors
///
/// Returns error if program execution fails or script pubkey doesn't match.
#[allow(clippy::too_many_arguments)]
pub fn finalize_sphincs_main_transaction(
    mut tx: Transaction,
    contract_public_key: &XOnlyPublicKey,
    utxos: &[TxOut],
    input_index: usize,
    network: SimplicityNetwork,
    log_level: TrackerLogLevel,
) -> Result<Transaction, ProgramError> {
    let contract_program = get_sphincs_main_program()?;

    let env = get_and_verify_env(
        &tx,
        &contract_program,
        contract_public_key,
        utxos,
        network,
        input_index,
    )?;

    let wt = simplicityhl::WitnessValues::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("PARAM"),
            Value::u256(U256::from_byte_array(
                hex::decode("d5fbd7a8ee5f95496e39ef74f3724ecc567046931ad02019997e261117797955")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )),
        ),
        (
            WitnessName::from_str_unchecked("SIG_2"),
            Value::u128(0x00000000000000000000000000000000ac78f16e2dc46e1738db9dd971915eac),
        ),
    ]));

    let pruned = execute_sphincs_main_program(&contract_program, wt, &env, log_level)?;
    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, *contract_public_key).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}

/// Get compiled SPHINCS main program, panicking on failure.
///
/// # Panics
///
/// Panics if program instantiation fails.
#[must_use]
pub fn get_compiled_sphincs_main_program() -> CompiledProgram {
    let program = get_sphincs_main_template_program();
    program.instantiate(Arguments::default(), true).unwrap()
}
