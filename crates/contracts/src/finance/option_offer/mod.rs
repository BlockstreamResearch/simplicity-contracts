use crate::finance::option_offer::build_witness::{OptionOfferBranch, build_option_offer_witness};

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

pub use build_arguments::OptionOfferArguments;

pub const OPTION_OFFER_SOURCE: &str = include_str!("source_simf/option_offer.simf");

/// Get the option offer template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_option_offer_template_program() -> TemplateProgram {
    TemplateProgram::new(OPTION_OFFER_SOURCE)
        .expect("INTERNAL: expected Option Offer Program to compile successfully.")
}

/// Derive P2TR address for an option offer contract.
///
/// # Errors
///
/// Returns error if program compilation fails.
pub fn get_option_offer_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &OptionOfferArguments,
    params: &'static AddressParams,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_option_offer_program(arguments)?.commit().cmr(),
        x_only_public_key,
        params,
    ))
}

/// Compile option offer program with the given arguments.
///
/// # Errors
///
/// Returns error if compilation fails.
pub fn get_option_offer_program(
    arguments: &OptionOfferArguments,
) -> Result<CompiledProgram, ProgramError> {
    load_program(OPTION_OFFER_SOURCE, arguments.build_arguments())
}

/// Get compiled option offer program, panicking on failure.
///
/// # Panics
///
/// Panics if program instantiation fails.
#[must_use]
pub fn get_compiled_option_offer_program(arguments: &OptionOfferArguments) -> CompiledProgram {
    let program = get_option_offer_template_program();

    program
        .instantiate(arguments.build_arguments(), true)
        .unwrap()
}

/// Execute option offer program for a given branch.
///
/// # Errors
///
/// Returns error if program execution fails.
pub fn execute_option_offer_program(
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    branch: &OptionOfferBranch,
    runner_log_level: TrackerLogLevel,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_option_offer_witness(branch);

    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

/// Finalize option offer transaction with Simplicity witness.
///
/// # Errors
///
/// Returns error if program execution fails or script pubkey doesn't match.
#[allow(clippy::too_many_arguments)]
pub fn finalize_option_offer_transaction(
    mut tx: Transaction,
    contract_public_key: &XOnlyPublicKey,
    contract_program: &CompiledProgram,
    utxos: &[TxOut],
    input_index: usize,
    branch: &OptionOfferBranch,
    params: &'static AddressParams,
    genesis_hash: elements::BlockHash,
    log_level: TrackerLogLevel,
) -> Result<Transaction, ProgramError> {
    let env = get_and_verify_env(
        &tx,
        contract_program,
        contract_public_key,
        utxos,
        params,
        genesis_hash,
        input_index,
    )?;

    let pruned = execute_option_offer_program(contract_program, &env, branch, log_level)?;

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

#[cfg(test)]
mod option_offer_tests {
    use super::*;

    use anyhow::Result;
    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1;
    use simplicityhl::simplicity::bitcoin::secp256k1::Secp256k1;
    use simplicityhl::simplicity::elements::{self, OutPoint, Txid};
    use simplicityhl::simplicity::hashes::Hash;

    use simplicityhl::elements::taproot::ControlBlock;
    use simplicityhl::elements::{AssetId, Script};
    use simplicityhl::simplicity::jet::elements::ElementsUtxo;
    use simplicityhl_core::{
        LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, get_and_verify_env, get_p2pk_address,
    };

    use crate::sdk::{
        build_option_offer_deposit, build_option_offer_exercise, build_option_offer_expiry,
        build_option_offer_withdraw,
    };

    fn get_test_arguments(
        x_only_public_key: &XOnlyPublicKey,
        expiry_time: u32,
    ) -> OptionOfferArguments {
        OptionOfferArguments::new(
            AssetId::from_slice(&[1u8; 32]).unwrap(),
            AssetId::from_slice(&[2u8; 32]).unwrap(),
            *LIQUID_TESTNET_BITCOIN_ASSET,
            100,
            10,
            expiry_time,
            x_only_public_key.serialize(),
        )
    }

    #[test]
    fn test_sdk_deposit() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let args = get_test_arguments(&keypair.x_only_public_key().0, 1_700_000_000);

        let collateral_deposit_amount = 1000u64;
        let premium_deposit_amount = collateral_deposit_amount * args.premium_per_collateral();
        let fee_amount = 500u64;

        let (pst, _) = build_option_offer_deposit(
            (
                OutPoint::new(Txid::from_slice(&[1; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_collateral_asset_id()),
                    value: Value::Explicit(collateral_deposit_amount + 500),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[2; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_premium_asset_id()),
                    value: Value::Explicit(premium_deposit_amount + 500),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[3; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(fee_amount + 100),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            collateral_deposit_amount,
            fee_amount,
            &args,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let tx = pst.extract_tx()?;

        assert_eq!(
            tx.output[0].asset,
            Asset::Explicit(args.get_collateral_asset_id())
        );
        assert_eq!(
            tx.output[0].value,
            Value::Explicit(collateral_deposit_amount)
        );

        assert_eq!(
            tx.output[1].asset,
            Asset::Explicit(args.get_premium_asset_id())
        );
        assert_eq!(tx.output[1].value, Value::Explicit(premium_deposit_amount));

        Ok(())
    }

    #[test]
    fn test_sdk_exercise_with_change() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let args = get_test_arguments(&keypair.x_only_public_key().0, 1_700_000_000);

        let program = get_compiled_option_offer_program(&args);

        let covenant_address = get_option_offer_address(
            &keypair.x_only_public_key().0,
            &args,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let change_recipient = get_p2pk_address(
            &keypair.x_only_public_key().0,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let input_collateral_amount = 1000u64;
        let input_premium_amount = input_collateral_amount * args.premium_per_collateral();
        let collateral_to_receive = 400u64;
        let settlement_required = collateral_to_receive * args.collateral_per_contract();
        let fee_amount = 500u64;

        let (pst, branch) = build_option_offer_exercise(
            (
                OutPoint::new(Txid::from_slice(&[1; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_collateral_asset_id()),
                    value: Value::Explicit(input_collateral_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[2; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_premium_asset_id()),
                    value: Value::Explicit(input_premium_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[3; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_settlement_asset_id()),
                    value: Value::Explicit(settlement_required + 1000),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[4; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_settlement_asset_id()),
                    value: Value::Explicit(fee_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            collateral_to_receive,
            fee_amount,
            &args,
            change_recipient.script_pubkey(),
        )?;

        let tx = pst.extract_tx()?;

        let env = ElementsEnv::new(
            Arc::new(tx),
            vec![
                ElementsUtxo {
                    script_pubkey: covenant_address.script_pubkey(),
                    asset: Asset::Explicit(args.get_collateral_asset_id()),
                    value: Value::Explicit(input_collateral_amount),
                },
                ElementsUtxo {
                    script_pubkey: covenant_address.script_pubkey(),
                    asset: Asset::Explicit(args.get_premium_asset_id()),
                    value: Value::Explicit(input_premium_amount),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_offer_witness(&branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::Trace).is_ok(),
            "expected success exercise path with change"
        );

        Ok(())
    }

    #[test]
    fn test_sdk_exercise_without_change() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let args = get_test_arguments(&keypair.x_only_public_key().0, 1_700_000_000);
        let program = get_compiled_option_offer_program(&args);

        let change_recipient = get_p2pk_address(
            &keypair.x_only_public_key().0,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let covenant_address = get_option_offer_address(
            &keypair.x_only_public_key().0,
            &args,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let input_collateral_amount = 1000u64;
        let input_premium_amount = input_collateral_amount * args.premium_per_collateral();
        let collateral_to_receive = 1000u64;
        let settlement_required = collateral_to_receive * args.collateral_per_contract();
        let fee_amount = 500u64;

        let (pst, branch) = build_option_offer_exercise(
            (
                OutPoint::new(Txid::from_slice(&[1; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_collateral_asset_id()),
                    value: Value::Explicit(input_collateral_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[2; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_premium_asset_id()),
                    value: Value::Explicit(input_premium_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[3; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_settlement_asset_id()),
                    value: Value::Explicit(settlement_required),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[4; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_settlement_asset_id()),
                    value: Value::Explicit(fee_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            collateral_to_receive,
            fee_amount,
            &args,
            change_recipient.script_pubkey(),
        )?;

        let tx = pst.extract_tx()?;

        let env = ElementsEnv::new(
            Arc::new(tx),
            vec![
                ElementsUtxo {
                    script_pubkey: covenant_address.script_pubkey(),
                    asset: Asset::Explicit(args.get_collateral_asset_id()),
                    value: Value::Explicit(input_collateral_amount),
                },
                ElementsUtxo {
                    script_pubkey: covenant_address.script_pubkey(),
                    asset: Asset::Explicit(args.get_premium_asset_id()),
                    value: Value::Explicit(input_premium_amount),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_offer_witness(&branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::Trace).is_ok(),
            "expected success exercise path without change"
        );

        Ok(())
    }

    #[test]
    fn test_sdk_withdraw() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let args = get_test_arguments(&keypair.x_only_public_key().0, 1_700_000_000);
        let program = get_compiled_option_offer_program(&args);

        let change_recipient = get_p2pk_address(
            &keypair.x_only_public_key().0,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let covenant_address = get_option_offer_address(
            &keypair.x_only_public_key().0,
            &args,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let settlement_amount = 50000u64;
        let fee_amount = 500u64;

        let pst = build_option_offer_withdraw(
            (
                OutPoint::new(Txid::from_slice(&[1; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_settlement_asset_id()),
                    value: Value::Explicit(settlement_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[2; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(fee_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            fee_amount,
            &args,
            change_recipient.script_pubkey(),
        )?;

        let tx = pst.extract_tx()?;

        let utxos = vec![
            TxOut {
                asset: Asset::Explicit(args.get_settlement_asset_id()),
                value: Value::Explicit(settlement_amount),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: covenant_address.script_pubkey(),
                witness: elements::TxOutWitness::default(),
            },
            TxOut {
                asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(fee_amount),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: Script::new(),
                witness: elements::TxOutWitness::default(),
            },
        ];

        let env = get_and_verify_env(
            &tx,
            &program,
            &keypair.x_only_public_key().0,
            &utxos,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
            0,
        )?;

        let sighash_all = env.c_tx_env().sighash_all();
        let signature =
            keypair.sign_schnorr(secp256k1::Message::from_digest(sighash_all.to_byte_array()));

        let branch = OptionOfferBranch::Withdraw {
            schnorr_signature: signature,
        };

        let witness_values = build_option_offer_witness(&branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::Trace).is_ok(),
            "expected success withdraw path"
        );

        Ok(())
    }

    #[test]
    fn test_sdk_expiry() -> Result<()> {
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );

        let args = get_test_arguments(&keypair.x_only_public_key().0, 1_700_000_000);
        let program = get_compiled_option_offer_program(&args);

        let change_recipient = get_p2pk_address(
            &keypair.x_only_public_key().0,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let covenant_address = get_option_offer_address(
            &keypair.x_only_public_key().0,
            &args,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let collateral_amount = 1000u64;
        let premium_amount = collateral_amount * args.premium_per_collateral();
        let fee_amount = 500u64;

        let pst = build_option_offer_expiry(
            (
                OutPoint::new(Txid::from_slice(&[1; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_collateral_asset_id()),
                    value: Value::Explicit(collateral_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[2; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(args.get_premium_asset_id()),
                    value: Value::Explicit(premium_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: covenant_address.script_pubkey(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            (
                OutPoint::new(Txid::from_slice(&[3; 32])?, 0),
                TxOut {
                    asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(fee_amount),
                    nonce: elements::confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: elements::TxOutWitness::default(),
                },
            ),
            fee_amount,
            &args,
            change_recipient.script_pubkey(),
        )?;

        let tx = pst.extract_tx()?;

        let utxos = vec![
            TxOut {
                asset: Asset::Explicit(args.get_collateral_asset_id()),
                value: Value::Explicit(collateral_amount),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: covenant_address.script_pubkey(),
                witness: elements::TxOutWitness::default(),
            },
            TxOut {
                asset: Asset::Explicit(args.get_premium_asset_id()),
                value: Value::Explicit(premium_amount),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: covenant_address.script_pubkey(),
                witness: elements::TxOutWitness::default(),
            },
        ];

        let env = get_and_verify_env(
            &tx,
            &program,
            &keypair.x_only_public_key().0,
            &utxos,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
            0,
        )?;

        let sighash_all = env.c_tx_env().sighash_all();
        let signature =
            keypair.sign_schnorr(secp256k1::Message::from_digest(sighash_all.to_byte_array()));

        let branch = OptionOfferBranch::Expiry {
            schnorr_signature: signature,
        };

        let witness_values = build_option_offer_witness(&branch);

        assert!(
            run_program(&program, witness_values, &env, TrackerLogLevel::Trace).is_ok(),
            "expected success expiry path"
        );

        Ok(())
    }
}
