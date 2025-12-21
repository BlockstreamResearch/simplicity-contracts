use crate::options::build_witness::{OptionBranch, build_option_witness};

use std::sync::Arc;

use simplicityhl_core::{
    ProgramError, control_block, create_p2tr_address, get_and_verify_env, load_program, run_program,
};

use simplicityhl::elements::{self, Address, AddressParams, Transaction, TxInWitness, TxOut};

use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::{bitcoin::XOnlyPublicKey, jet::elements::ElementsEnv};

use simplicityhl::tracker::TrackerLogLevel;
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
    params: &'static AddressParams,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_options_program(arguments)?.commit().cmr(),
        x_only_public_key,
        params,
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

/// Execute options program for funding path.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_options_program(
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    option_branch: OptionBranch,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_option_witness(option_branch);

    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

/// Finalize options funding path transaction with Simplicity witness.
///
/// # Errors
///
/// Returns error if program execution fails or script pubkey doesn't match.
#[allow(clippy::too_many_arguments)]
pub fn finalize_options_transaction(
    mut tx: Transaction,
    options_public_key: &XOnlyPublicKey,
    options_program: &CompiledProgram,
    utxos: &[TxOut],
    input_index: usize,
    option_branch: OptionBranch,
    params: &'static AddressParams,
    genesis_hash: elements::BlockHash,
) -> Result<Transaction, ProgramError> {
    let env = get_and_verify_env(
        &tx,
        options_program,
        options_public_key,
        utxos,
        params,
        genesis_hash,
        input_index,
    )?;

    let pruned =
        execute_options_program(options_program, &env, option_branch, TrackerLogLevel::None)?;

    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, *options_public_key).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}

#[cfg(test)]
mod options_tests {
    use super::*;

    use anyhow::Result;
    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1;
    use simplicityhl::simplicity::bitcoin::secp256k1::Secp256k1;
    use simplicityhl::simplicity::elements::{self, AssetId, OutPoint, Txid};
    use simplicityhl::simplicity::hashes::Hash;
    use std::str::FromStr;

    use crate::sdk::taproot_pubkey_gen::{TaprootPubkeyGen, get_random_seed};
    use crate::sdk::{
        build_option_cancellation, build_option_creation, build_option_exercise,
        build_option_expiry, build_option_funding, build_option_settlement,
    };
    use simplicityhl::elements::pset::PartiallySignedTransaction;
    use simplicityhl::elements::secp256k1_zkp::SECP256K1;
    use simplicityhl::elements::taproot::ControlBlock;
    use simplicityhl::elements::{ContractHash, Script};
    use simplicityhl::simplicity::jet::elements::ElementsUtxo;
    use simplicityhl_core::{LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_TEST_ASSET_ID_STR};

    fn get_creation_pst(
        keypair: &Keypair,
        start_time: u32,
        expiry_time: u32,
        collateral_per_contract: u64,
        settlement_per_contract: u64,
    ) -> Result<(
        (PartiallySignedTransaction, TaprootPubkeyGen),
        OptionsArguments,
    )> {
        let option_outpoint = OutPoint::new(Txid::from_slice(&[1; 32])?, 0);
        let grantor_outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 0);

        let issuance_asset_entropy = get_random_seed();

        let option_arguments = OptionsArguments {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id: LIQUID_TESTNET_BITCOIN_ASSET.into_inner().0,
            settlement_asset_id: AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?
                .into_inner()
                .0,
            option_token_entropy: AssetId::generate_asset_entropy(
                option_outpoint,
                ContractHash::from_byte_array(issuance_asset_entropy),
            )
            .0,
            grantor_token_entropy: AssetId::generate_asset_entropy(
                grantor_outpoint,
                ContractHash::from_byte_array(issuance_asset_entropy),
            )
            .0,
        };

        Ok((
            build_option_creation(
                &keypair.public_key(),
                (
                    option_outpoint,
                    TxOut {
                        asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                        value: Value::Explicit(500),
                        nonce: elements::confidential::Nonce::Null,
                        script_pubkey: Script::new(),
                        witness: elements::TxOutWitness::default(),
                    },
                ),
                (
                    grantor_outpoint,
                    TxOut {
                        asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                        value: Value::Explicit(1000),
                        nonce: elements::confidential::Nonce::Null,
                        script_pubkey: Script::new(),
                        witness: elements::TxOutWitness::default(),
                    },
                ),
                &option_arguments,
                issuance_asset_entropy,
                100,
                &AddressParams::LIQUID_TESTNET,
            )?,
            option_arguments,
        ))
    }

    #[test]
    fn test_options_creation() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let _ = get_creation_pst(&keypair, 0, 0, 20, 25)?;

        Ok(())
    }

    #[test]
    fn test_options_funding_path() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let collateral_per_contract = 20;
        let settlement_per_contract = 25;

        let ((pst, option_pubkey_gen), option_arguments) = get_creation_pst(
            &keypair,
            0,
            0,
            collateral_per_contract,
            settlement_per_contract,
        )?;
        let pst = pst.extract_tx()?;

        let collateral_amount = 1000;

        let option_tx_out = pst.output[0].clone();
        let option_tx_out_secrets = pst.output[0].unblind(SECP256K1, keypair.secret_key())?;

        let grantor_tx_out = pst.output[1].clone();
        let grantor_tx_out_secrets = pst.output[1].unblind(SECP256K1, keypair.secret_key())?;

        let (pst, option_branch) = build_option_funding(
            &keypair.public_key(),
            (OutPoint::default(), option_tx_out, option_tx_out_secrets),
            (OutPoint::default(), grantor_tx_out, grantor_tx_out_secrets),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(collateral_amount + 1000),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            None,
            &option_arguments,
            collateral_amount,
            50,
        )?;

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1000),
                },
                ElementsUtxo {
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1000),
                },
                ElementsUtxo {
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(collateral_amount),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(option_branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::Trace).is_ok(),
            "expected success funding path"
        );

        Ok(())
    }

    #[test]
    fn test_options_cancellation_path() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let collateral_per_contract = 20;
        let settlement_per_contract = 25;

        let ((_, option_pubkey_gen), option_arguments) = get_creation_pst(
            &keypair,
            0,
            0,
            collateral_per_contract,
            settlement_per_contract,
        )?;

        let collateral_amount = 1000;
        let option_token_amount = collateral_amount / collateral_per_contract;
        let amount_to_burn = option_token_amount / 2;

        let (option_asset_id, _) = option_arguments.get_option_token_ids();
        let (grantor_asset_id, _) = option_arguments.get_grantor_token_ids();

        let (pst, option_branch) = build_option_cancellation(
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(collateral_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(option_asset_id),
                    value: Value::Explicit(option_token_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(grantor_asset_id),
                    value: Value::Explicit(option_token_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(100),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            &option_arguments,
            amount_to_burn,
            50,
        )?;

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: option_pubkey_gen.address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(collateral_amount),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(option_branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::None).is_ok(),
            "expected success cancellation path"
        );

        Ok(())
    }

    #[test]
    fn test_options_exercise_path() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let collateral_per_contract = 20;
        let settlement_per_contract = 10;

        let ((_, option_pubkey_gen), option_arguments) = get_creation_pst(
            &keypair,
            500_000_000,
            500_000_000,
            collateral_per_contract,
            settlement_per_contract,
        )?;

        let collateral_amount_total = 1000;
        let option_token_amount_total = collateral_amount_total / collateral_per_contract; // 50
        let option_amount_to_burn = option_token_amount_total - 5; // 45
        let asset_amount_to_pay = option_amount_to_burn * settlement_per_contract; // 450

        let (option_asset_id, _) = option_arguments.get_option_token_ids();
        let settlement_asset_id = AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?;

        let (pst, option_branch) = build_option_exercise(
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(collateral_amount_total),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(option_asset_id),
                    value: Value::Explicit(option_token_amount_total),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(settlement_asset_id),
                    value: Value::Explicit(asset_amount_to_pay + 100), // extra for change
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(100),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            option_amount_to_burn,
            50,
            &option_arguments,
        )?;

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: option_pubkey_gen.address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(collateral_amount_total),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(option_branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::None).is_ok(),
            "expected success exercise path"
        );

        Ok(())
    }

    #[test]
    fn test_options_settlement_path() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let collateral_per_contract = 20;
        let settlement_per_contract = 40;

        let ((_, option_pubkey_gen), option_arguments) = get_creation_pst(
            &keypair,
            500_000_000,
            500_000_000,
            collateral_per_contract,
            settlement_per_contract,
        )?;

        let grantor_token_amount_to_burn = 10;
        let available_target_asset = 1000; // available in input utxo

        let (grantor_asset_id, _) = option_arguments.get_grantor_token_ids();
        let settlement_asset_id = AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?;

        let (pst, option_branch) = build_option_settlement(
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(settlement_asset_id),
                    value: Value::Explicit(available_target_asset),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(grantor_asset_id),
                    value: Value::Explicit(grantor_token_amount_to_burn + 5), // extra for change
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(100),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            grantor_token_amount_to_burn,
            50,
            &option_arguments,
        )?;

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: option_pubkey_gen.address.script_pubkey(),
                asset: Asset::Explicit(settlement_asset_id),
                value: Value::Explicit(available_target_asset),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(option_branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::None).is_ok(),
            "expected success settlement path"
        );

        Ok(())
    }

    #[test]
    fn test_options_expiry_path() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let collateral_per_contract = 20;
        let settlement_per_contract = 25;

        let ((_, option_pubkey_gen), option_arguments) = get_creation_pst(
            &keypair,
            500_000_000,
            500_000_000,
            collateral_per_contract,
            settlement_per_contract,
        )?;

        let collateral_amount_total = 1000;
        let option_token_amount_total = collateral_amount_total / collateral_per_contract; // 50

        // At expiry, burn grantor tokens to withdraw collateral
        let grantor_token_amount_to_burn = option_token_amount_total / 2; // 25

        let (grantor_asset_id, _) = option_arguments.get_grantor_token_ids();

        let (pst, option_branch) = build_option_expiry(
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(collateral_amount_total),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(grantor_asset_id),
                    value: Value::Explicit(grantor_token_amount_to_burn + 5), // extra for change
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::default(),
                TxOut {
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(100),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            grantor_token_amount_to_burn,
            50,
            &option_arguments,
        )?;

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: option_pubkey_gen.address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(collateral_amount_total),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(option_branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::None).is_ok(),
            "expected success expiry path"
        );

        Ok(())
    }
}
