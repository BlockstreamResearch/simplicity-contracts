#![allow(clippy::similar_names)]

use wallet_abi::{Network, ProgramError, create_p2tr_address, load_program};

use simplicityhl::elements::Address;

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;

use simplicityhl::{CompiledProgram, TemplateProgram};

pub mod build_arguments;
pub mod build_witness;

pub use build_arguments::OptionsArguments;

pub const OPTION_SOURCE: &str = include_str!("source_simf/options.simf");

/// Get the options template program for instantiation.
///
/// # Panics
/// - if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_options_template_program() -> TemplateProgram {
    TemplateProgram::new(OPTION_SOURCE)
        .expect("INTERNAL: expected Options Program to compile successfully.")
}

/// Derive P2TR address for an options contract.
///
/// # Errors
/// Returns error if program compilation fails.
pub fn get_options_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &OptionsArguments,
    network: Network,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_options_program(arguments)?.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

/// Compile options program with the given arguments.
///
/// # Errors
/// Returns error if compilation fails.
pub fn get_options_program(arguments: &OptionsArguments) -> Result<CompiledProgram, ProgramError> {
    load_program(OPTION_SOURCE, arguments.build_option_arguments())
}

/// Get compiled options program, panicking on failure.
///
/// # Panics
/// - if program instantiation fails.
#[must_use]
pub fn get_compiled_options_program(arguments: &OptionsArguments) -> CompiledProgram {
    let program = get_options_template_program();

    program
        .instantiate(arguments.build_option_arguments(), true)
        .unwrap()
}
