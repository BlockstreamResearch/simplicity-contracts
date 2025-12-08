use simplicityhl_core::{RunnerLogLevel, create_p2tr_address, load_program, run_program};
use std::sync::Arc;

use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::bitcoin::key::Keypair;
use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::{Address, AddressParams, Transaction};
use simplicityhl::simplicity::hashes::Hash;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::{CompiledProgram, TemplateProgram};

// For taproot
use simplicityhl::simplicity::{
    elements::hashes::{sha256, Hash as _, HashEngine as _},
    
};


mod build_witness;

pub use build_witness::build_storage_inc_witness;

pub const SIMPLE_STORAGE_SOURCE: &str = include_str!("source_simf/storage_inc.simf");

/// Get the storage template program for instantiation.
///
/// # Panics
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_storage_template_program() -> TemplateProgram {
    TemplateProgram::new(SIMPLE_STORAGE_SOURCE)
        .expect("INTERNAL: expected to compile successfully.")
}

/// Derive P2TR address for a storage contract.
///
/// # Errors
/// Returns error if program compilation fails.
pub fn get_storage_inc_address(
    public_key: &XOnlyPublicKey,
    params: &'static AddressParams,
) -> anyhow::Result<Address> {
    Ok(create_p2tr_address(
        get_storage_program()?.commit().cmr(),
        public_key,
        params,
    ))
}

fn get_storage_program() -> anyhow::Result<CompiledProgram> {
    load_program(SIMPLE_STORAGE_SOURCE, simplicityhl::Arguments::default())
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_storage_inc_compiled_program() -> CompiledProgram {
    let program = get_storage_template_program();

    program
        .instantiate(simplicityhl::Arguments::default(), true)
        .unwrap()
}

/// Execute storage program with new state.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_storage_inc_program(
    state: [u8; 32],  // TODO think about endianness
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
) -> anyhow::Result<Arc<RedeemNode<Elements>>> {

    let witness_values = build_storage_inc_witness(state);
    Ok(run_program(compiled_program, witness_values, env, RunnerLogLevel::None)?.0)
}


pub fn script_hash_for_input_script(state_data: [u8; 32]) -> [u8; 32] {

    [0u8; 32]
}


#[cfg(test)]
mod simple_storage_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{self, AssetId, OutPoint, Script, Txid};
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1;
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::jet::elements::ElementsEnv;

    #[test]
    fn test_simple_storage_mint_path() -> Result<()> {
        let old_state: [u8; 32] = [0u8; 32];
        let new_state: [u8; 32] = script_hash_for_input_script(old_state.clone());

        let keypair = Keypair::from_secret_key(
            secp256k1::SECP256K1,
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let storage_address = get_storage_inc_address(
            &keypair.x_only_public_key().0,
            &elements::AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint0 = OutPoint::new(Txid::from_slice(&[2; 32])?, 0);
        pst.add_input(Input::from_prevout(outpoint0));
        pst.add_output(Output::new_explicit(
            storage_address.script_pubkey(),
            0,
            AssetId::default(),
            None,
        ));

        let program = get_storage_inc_compiled_program();

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                simplicityhl::simplicity::jet::elements::ElementsUtxo {
                    script_pubkey: storage_address.script_pubkey(),
                    asset: Asset::default(),
                    value: Value::default(),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        assert!(
            execute_storage_inc_program(new_state, &program, &env).is_ok(),
            "expected success mint path"
        );

        Ok(())
    }
}
