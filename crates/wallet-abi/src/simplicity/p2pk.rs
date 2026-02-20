use std::collections::HashMap;
use std::sync::Arc;

use lwk_common::Network;
use lwk_simplicity::runner::run_program;
use lwk_simplicity::scripts::{create_p2tr_address, load_program};

use simplicityhl::elements::secp256k1_zkp::schnorr::Signature;
use simplicityhl::num::U256;
use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::str::WitnessName;
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{CompiledProgram, Value, WitnessValues, elements};

use crate::ProgramError;

/// Embedded Simplicity source for a basic P2PK program.
pub const P2PK_SOURCE: &str = include_str!("../source_simf/p2pk.simf");

/// Construct a P2TR address for the embedded P2PK program and the provided public key.
pub fn get_p2pk_address(
    x_only_public_key: &XOnlyPublicKey,
    network: Network,
) -> Result<elements::Address, ProgramError> {
    Ok(create_p2tr_address(
        get_p2pk_program(x_only_public_key)?.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

/// Compile the embedded P2PK program with the given X-only public key as argument.
pub fn get_p2pk_program(
    account_public_key: &XOnlyPublicKey,
) -> Result<CompiledProgram, ProgramError> {
    let arguments = simplicityhl::Arguments::from(HashMap::from([(
        WitnessName::from_str_unchecked("PUBLIC_KEY"),
        Value::u256(U256::from_byte_array(account_public_key.serialize())),
    )]));

    load_program(P2PK_SOURCE, arguments)
}

/// Execute the compiled P2PK program against the provided env, producing a pruned redeem node.
pub fn execute_p2pk_program(
    compiled_program: &CompiledProgram,
    schnorr_signature: &Signature,
    env: &ElementsEnv<Arc<elements::Transaction>>,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("SIGNATURE"),
        Value::byte_array(schnorr_signature.serialize()),
    )]));

    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}
