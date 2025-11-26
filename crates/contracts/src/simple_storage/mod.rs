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

mod build_arguments;
mod build_witness;

pub use build_arguments::{StorageArguments, build_storage_arguments};
pub use build_witness::build_storage_witness;

pub const SIMPLE_STORAGE_SOURCE: &str = include_str!("source_simf/simple_storage.simf");

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
pub fn get_storage_address(
    public_key: &XOnlyPublicKey,
    args: &StorageArguments,
    params: &'static AddressParams,
) -> anyhow::Result<Address> {
    Ok(create_p2tr_address(
        get_storage_program(args)?.commit().cmr(),
        public_key,
        params,
    ))
}

fn get_storage_program(args: &StorageArguments) -> anyhow::Result<CompiledProgram> {
    load_program(SIMPLE_STORAGE_SOURCE, build_storage_arguments(args))
}

/// Get compiled storage program, panicking on failure.
///
/// # Panics
/// Panics if program instantiation fails.
#[must_use]
pub fn get_storage_compiled_program(args: &StorageArguments) -> CompiledProgram {
    let program = get_storage_template_program();

    program
        .instantiate(build_storage_arguments(args), true)
        .unwrap()
}

/// Execute storage program with signature and new value.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_storage_program(
    new_value: u64,
    keypair: &Keypair,
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
) -> anyhow::Result<Arc<RedeemNode<Elements>>> {
    let sighash_all = secp256k1::Message::from_digest(env.c_tx_env().sighash_all().to_byte_array());

    let signature = keypair.sign_schnorr(sighash_all);
    let witness_values = build_storage_witness(new_value, &signature);
    Ok(run_program(compiled_program, witness_values, env, RunnerLogLevel::None)?.0)
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

    use simplicityhl_core::LIQUID_TESTNET_BITCOIN_ASSET;

    #[test]
    fn test_simple_storage_mint_path() -> Result<()> {
        // old_value < new_value triggers the mint branch requiring output at index 1
        let old_value: u64 = 100;
        let new_value: u64 = 150;

        let keypair = Keypair::from_secret_key(
            secp256k1::SECP256K1,
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let storage_arguments = StorageArguments {
            public_key: keypair.x_only_public_key().0.serialize(),
            slot_asset: LIQUID_TESTNET_BITCOIN_ASSET.to_string(),
        };

        let storage_address = get_storage_address(
            &keypair.x_only_public_key().0,
            &storage_arguments,
            &elements::AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint0 = OutPoint::new(Txid::from_slice(&[2; 32])?, 0);
        let outpoint1 = OutPoint::new(Txid::from_slice(&[3; 32])?, 1);

        pst.add_input(Input::from_prevout(outpoint0));
        pst.add_input(Input::from_prevout(outpoint1));

        pst.add_output(Output::new_explicit(
            storage_address.script_pubkey(),
            new_value,
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));

        pst.add_output(Output::new_explicit(
            storage_address.script_pubkey(),
            1,
            AssetId::default(),
            None,
        ));

        let program = get_storage_compiled_program(&storage_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                simplicityhl::simplicity::jet::elements::ElementsUtxo {
                    script_pubkey: storage_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(old_value),
                },
                simplicityhl::simplicity::jet::elements::ElementsUtxo {
                    script_pubkey: storage_address.script_pubkey(),
                    asset: Asset::Explicit(AssetId::default()),
                    value: Value::Explicit(1),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        assert!(
            execute_storage_program(new_value, &keypair, &program, &env).is_ok(),
            "expected success mint path"
        );

        Ok(())
    }

    #[test]
    fn test_simple_storage_burn_path() -> Result<()> {
        // old_value > new_value triggers the burn branch requiring OP_RETURN at index 1
        let old_value: u64 = 150;
        let new_value: u64 = 100; // burn 50

        let keypair = Keypair::from_secret_key(
            secp256k1::SECP256K1,
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let storage_arguments = StorageArguments {
            public_key: keypair.x_only_public_key().0.serialize(),
            slot_asset: LIQUID_TESTNET_BITCOIN_ASSET.to_string(),
        };

        let storage_address = get_storage_address(
            &keypair.x_only_public_key().0,
            &storage_arguments,
            &elements::AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint0 = OutPoint::new(Txid::from_slice(&[4; 32])?, 0);

        pst.add_input(Input::from_prevout(outpoint0));

        // Output 0: updated storage state with new value
        pst.add_output(Output::new_explicit(
            storage_address.script_pubkey(),
            new_value,
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));

        // Output 1: burn OP_RETURN of the storage asset with the difference
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            old_value - new_value,
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));

        let program = get_storage_compiled_program(&storage_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![simplicityhl::simplicity::jet::elements::ElementsUtxo {
                script_pubkey: storage_address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(old_value),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        assert!(
            execute_storage_program(new_value, &keypair, &program, &env).is_ok(),
            "expected success burn path"
        );

        Ok(())
    }
}
