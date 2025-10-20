use std::sync::Arc;

use crate::build_witness::{TokenBranch, build_option_witness};
use simplicityhl_core::{
    LIQUID_TESTNET_GENESIS, RunnerLogLevel, control_block, create_p2tr_address, load_program,
    run_program,
};

use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::elements::{Address, AddressParams, Transaction, TxInWitness, TxOut};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsUtxo;
use simplicityhl::simplicity::{bitcoin::XOnlyPublicKey, jet::elements::ElementsEnv};
use simplicityhl::{CompiledProgram, TemplateProgram};

pub mod build_arguments;
pub mod build_witness;

pub use build_arguments::OptionsArguments;

pub const OPTION_SOURCE: &str = include_str!("source_simf/options.simf");

pub fn get_options_template_program() -> TemplateProgram {
    TemplateProgram::new(OPTION_SOURCE)
        .expect("INTERNAL: expected Options Program to compile successfully.")
}

pub fn get_options_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &OptionsArguments,
    params: &'static AddressParams,
) -> anyhow::Result<Address> {
    Ok(create_p2tr_address(
        get_options_program(arguments)?.commit().cmr(),
        x_only_public_key,
        params,
    ))
}

pub fn get_options_program(arguments: &OptionsArguments) -> anyhow::Result<CompiledProgram> {
    load_program(OPTION_SOURCE, arguments.build_option_arguments())
}

pub fn get_compiled_options_program(arguments: &OptionsArguments) -> CompiledProgram {
    let program = get_options_template_program();

    program
        .instantiate(arguments.build_option_arguments(), true)
        .unwrap()
}

pub fn execute_options_program(
    compiled_program: &CompiledProgram,
    env: ElementsEnv<Arc<Transaction>>,
    expected_asset_amount: u64,
    token_branch: TokenBranch,
    runner_log_level: RunnerLogLevel,
) -> anyhow::Result<Arc<RedeemNode<Elements>>> {
    let witness_values = build_option_witness(
        token_branch,
        build_witness::OptionBranch::Funding {
            expected_asset_amount,
        },
    );

    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

pub fn finalize_options_funding_path_transaction(
    mut tx: Transaction,
    options_public_key: &XOnlyPublicKey,
    options_program: &CompiledProgram,
    utxos: &[TxOut],
    input_index: usize,
    expected_asset_amount: u64,
    token_branch: TokenBranch,
) -> anyhow::Result<Transaction> {
    let cmr = options_program.commit().cmr();

    let target_utxo = &utxos[input_index];
    let script_pubkey =
        create_p2tr_address(cmr, options_public_key, &AddressParams::LIQUID_TESTNET)
            .script_pubkey();

    assert_eq!(
        target_utxo.script_pubkey, script_pubkey,
        "Expected for the UTXO to be spent by Options to have the same script."
    );

    let env: ElementsEnv<Arc<Transaction>> = ElementsEnv::new(
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
        control_block(cmr, *options_public_key),
        None,
        *LIQUID_TESTNET_GENESIS,
    );

    let pruned = execute_options_program(
        options_program,
        env,
        expected_asset_amount,
        token_branch,
        RunnerLogLevel::None,
    )?;

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
    use std::vec;

    use anyhow::Result;
    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output};
    use simplicityhl::elements::{LockTime, Script};
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1;
    use simplicityhl::simplicity::bitcoin::secp256k1::Secp256k1;
    use simplicityhl::simplicity::elements::pset::PartiallySignedTransaction;
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::elements::{self, AssetId, OutPoint, Txid};
    use simplicityhl::simplicity::hashes::Hash;
    use simplicityhl::simplicity::jet::elements::ElementsEnv;
    use std::str::FromStr;
    use std::sync::Arc;

    use simplicityhl_core::{
        LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_TEST_ASSET_ID_STR, get_new_asset_entropy,
    };

    #[test]
    fn test_options_funding_path() -> Result<()> {
        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);

        let second_asset_id = AssetId::from_entropy(second_asset_entropy);

        let contract_size = 20;
        let collateral_amount = 1000;
        let asset_strike_price = 2;
        let option_token_amount = collateral_amount / contract_size;
        let expected_asset_amount = collateral_amount / asset_strike_price;
        let grantor_token_strike_price = expected_asset_amount / option_token_amount;

        let option_arguments = OptionsArguments {
            start_time: 0,
            expiry_time: 0,
            contract_size,
            asset_strike_price,
            grantor_token_strike_price,
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_token_asset_id_hex_le: second_asset_id.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let options_address = get_options_address(
            &keypair.x_only_public_key().0,
            &option_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();

        let mut first_reissuance_tx = Input::from_prevout(outpoint);
        first_reissuance_tx.issuance_value_amount = Some(option_token_amount);
        first_reissuance_tx.issuance_inflation_keys = None;
        first_reissuance_tx.issuance_asset_entropy = Some(first_asset_entropy.to_byte_array());

        let mut second_reissuance_tx = Input::from_prevout(outpoint);
        second_reissuance_tx.issuance_value_amount = Some(option_token_amount);
        second_reissuance_tx.issuance_inflation_keys = None;
        second_reissuance_tx.issuance_asset_entropy = Some(second_asset_entropy.to_byte_array());

        pst.add_input(first_reissuance_tx);
        pst.add_input(second_reissuance_tx);
        pst.add_input(Input::from_prevout(outpoint));

        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            1,
            AssetId::default(),
            None,
        ));

        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            1,
            AssetId::default(),
            None,
        ));

        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            collateral_amount,
            elements::AssetId::LIQUID_BTC,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new(),
            option_token_amount,
            first_asset_id,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new(),
            option_token_amount,
            second_asset_id,
            None,
        ));

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: options_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1000),
                },
                ElementsUtxo {
                    script_pubkey: options_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1000),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(
            TokenBranch::OptionToken,
            build_witness::OptionBranch::Funding {
                expected_asset_amount,
            },
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::None).is_err() {
            panic!("expected success funding path -- option token");
        }

        Ok(())
    }

    #[test]
    fn test_options_cancellation_path() -> Result<()> {
        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);

        let second_asset_id = AssetId::from_entropy(second_asset_entropy);

        let contract_size = 20;
        let collateral_amount = 1000;
        let asset_strike_price = 2;
        let option_token_amount = collateral_amount / contract_size;
        let expected_asset_amount = collateral_amount * asset_strike_price;
        let grantor_token_strike_price = expected_asset_amount / option_token_amount;

        let amount_to_burn = option_token_amount / 2;
        let collateral_amount_to_withdraw = collateral_amount / 2;

        let option_arguments = OptionsArguments {
            start_time: 0,
            expiry_time: 0,
            contract_size,
            asset_strike_price,
            grantor_token_strike_price,
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_token_asset_id_hex_le: second_asset_id.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let options_address = get_options_address(
            &keypair.x_only_public_key().0,
            &option_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();

        pst.add_input(Input::from_prevout(outpoint));

        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            collateral_amount - collateral_amount_to_withdraw,
            elements::AssetId::LIQUID_BTC,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            amount_to_burn,
            first_asset_id,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            amount_to_burn,
            second_asset_id,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new(),
            collateral_amount_to_withdraw,
            elements::AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: options_address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(collateral_amount),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(
            TokenBranch::OptionToken,
            build_witness::OptionBranch::Cancellation {
                is_change_needed: true,
                index_to_spend: 0,
                amount_to_burn,
                collateral_amount_to_withdraw,
            },
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::None).is_err() {
            panic!("expected success funding path -- option token");
        }

        Ok(())
    }

    #[test]
    fn test_options_exercise_path() -> Result<()> {
        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);

        let second_asset_id = AssetId::from_entropy(second_asset_entropy);

        let contract_size = 20;
        let collateral_amount_total = 1000;
        let asset_strike_price = 2;
        let option_token_amount_total = collateral_amount_total / contract_size; // 50

        let option_amount_to_burn = option_token_amount_total - 5; // 45
        let collateral_amount_to_get = option_amount_to_burn * contract_size; // 900
        let asset_amount_to_pay = collateral_amount_to_get / asset_strike_price; // 450
        let grantor_token_strike_price =
            (collateral_amount_total * asset_strike_price) / option_token_amount_total; // 40

        let option_arguments = OptionsArguments {
            start_time: 1760358546,
            expiry_time: 0,
            contract_size,
            asset_strike_price,
            grantor_token_strike_price,
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_token_asset_id_hex_le: second_asset_id.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let options_address = get_options_address(
            &keypair.x_only_public_key().0,
            &option_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();

        // Spend collateral from the covenant
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Output 0: change (collateral asset) back to covenant
        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            collateral_amount_total - collateral_amount_to_get,
            elements::AssetId::LIQUID_BTC,
            None,
        ));

        // Output 1: burn option tokens
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            option_amount_to_burn,
            first_asset_id,
            None,
        ));

        // Output 2: settlement payment in target asset to covenant script (same script hash as output 0)
        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            asset_amount_to_pay,
            elements::AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        pst.global.tx_data.fallback_locktime =
            Some(LockTime::from_time(option_arguments.start_time)?);

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: options_address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(collateral_amount_total),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(
            TokenBranch::OptionToken,
            build_witness::OptionBranch::Exercise {
                is_change_needed: true,
                index_to_spend: 0,
                amount_to_burn: option_amount_to_burn,
                collateral_amount_to_get,
                asset_amount: asset_amount_to_pay,
            },
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::None).is_err() {
            panic!("expected success exercise path -- option token");
        }

        Ok(())
    }

    #[test]
    fn test_options_settlement_path() -> Result<()> {
        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);

        let second_asset_id = AssetId::from_entropy(second_asset_entropy);

        let contract_size = 20;
        let asset_strike_price = 2;
        let option_token_amount_total = 50; // arbitrary, only used to derive strike price below
        let grantor_token_strike_price = (1000 * asset_strike_price) / option_token_amount_total; // 40

        // Settlement burns grantor tokens against target asset held by covenant
        let grantor_token_amount_to_burn = 10;
        let asset_amount = grantor_token_amount_to_burn * grantor_token_strike_price; // 400
        let available_target_asset = 1000; // available in input utxo

        let option_arguments = OptionsArguments {
            start_time: 1760358546,
            expiry_time: 0,
            contract_size,
            asset_strike_price,
            grantor_token_strike_price,
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_token_asset_id_hex_le: second_asset_id.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let options_address = get_options_address(
            &keypair.x_only_public_key().0,
            &option_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime =
            Some(LockTime::from_time(option_arguments.start_time)?);

        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Output 0: change (target asset) back to covenant
        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            available_target_asset - asset_amount,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        // Output 1: burn grantor tokens
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_token_amount_to_burn,
            second_asset_id,
            None,
        ));

        // Output 2: settlement asset (target asset) forwarded
        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            asset_amount,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: options_address.script_pubkey(),
                asset: Asset::Explicit(AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?),
                value: Value::Explicit(available_target_asset),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(
            TokenBranch::GrantorToken,
            build_witness::OptionBranch::Exercise {
                is_change_needed: true,
                index_to_spend: 0,
                amount_to_burn: grantor_token_amount_to_burn,
                collateral_amount_to_get: 0,
                asset_amount,
            },
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::None).is_err() {
            panic!("expected success settlement path -- grantor token");
        }

        Ok(())
    }

    #[test]
    fn test_options_expiry_path() -> Result<()> {
        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);

        let second_asset_id = AssetId::from_entropy(second_asset_entropy);

        let contract_size = 20;
        let collateral_amount_total = 1000;
        let asset_strike_price = 2;
        let option_token_amount_total = collateral_amount_total / contract_size; // 50
        let grantor_token_strike_price =
            (collateral_amount_total * asset_strike_price) / option_token_amount_total; // 40

        // At expiry, burn grantor tokens to withdraw collateral
        let grantor_token_amount_to_burn = option_token_amount_total / 2; // 25
        let collateral_amount = grantor_token_amount_to_burn * contract_size; // 500

        let option_arguments = OptionsArguments {
            start_time: 1760358546,
            expiry_time: 1760358546,
            contract_size,
            asset_strike_price,
            grantor_token_strike_price,
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_token_asset_id_hex_le: second_asset_id.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let options_address = get_options_address(
            &keypair.x_only_public_key().0,
            &option_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime =
            Some(LockTime::from_time(option_arguments.start_time)?);

        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Output 0: change (collateral) back to covenant
        pst.add_output(Output::new_explicit(
            options_address.script_pubkey(),
            collateral_amount_total - collateral_amount,
            elements::AssetId::LIQUID_BTC,
            None,
        ));

        // Output 1: burn grantor tokens
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_token_amount_to_burn,
            second_asset_id,
            None,
        ));

        // Output 2: withdraw collateral
        pst.add_output(Output::new_explicit(
            Script::new(),
            collateral_amount,
            elements::AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_options_program(&option_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: options_address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(collateral_amount_total),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_option_witness(
            TokenBranch::GrantorToken,
            build_witness::OptionBranch::Expiry {
                is_change_needed: true,
                index_to_spend: 0,
                grantor_token_amount_to_burn,
                collateral_amount_to_withdraw: collateral_amount,
            },
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::None).is_err() {
            panic!("expected success expiry path -- grantor token");
        }

        Ok(())
    }
}
