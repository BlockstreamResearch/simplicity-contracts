use std::sync::Arc;

use simplicityhl::simplicity::RedeemNode;
use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplicityhl::simplicity::elements::{Address, AddressParams, Transaction, TxInWitness, TxOut};
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::{CompiledProgram, TemplateProgram};

use simplicityhl_core::{
    LIQUID_TESTNET_GENESIS, RunnerLogLevel, control_block, create_p2tr_address, load_program,
    run_program,
};

mod build_arguments;
mod build_witness;

pub use build_arguments::{DCDArguments, DCDRatioArguments};
pub use build_witness::{DcdBranch, MergeBranch, TokenBranch, build_dcd_witness};

pub const PRICE_ATTESTED_SDK_SOURCE: &str = include_str!("source_simf/dual_currency_deposit.simf");

pub fn get_dcd_template_program() -> TemplateProgram {
    TemplateProgram::new(PRICE_ATTESTED_SDK_SOURCE)
        .expect("INTERNAL: expected DCD Price Attested Program to compile successfully.")
}

pub fn get_dcd_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &DCDArguments,
    params: &'static AddressParams,
) -> anyhow::Result<Address> {
    Ok(create_p2tr_address(
        get_dcd_program(arguments)?.commit().cmr(),
        x_only_public_key,
        params,
    ))
}

pub fn get_dcd_program(arguments: &DCDArguments) -> anyhow::Result<CompiledProgram> {
    load_program(PRICE_ATTESTED_SDK_SOURCE, arguments.build_arguments())
}

pub fn get_compiled_dcd_program(arguments: &DCDArguments) -> CompiledProgram {
    let program = get_dcd_template_program();

    program
        .instantiate(arguments.build_arguments(), true)
        .unwrap()
}

pub fn execute_dcd_program(
    compiled_program: &CompiledProgram,
    env: ElementsEnv<Arc<Transaction>>,
    token_branch: TokenBranch,
    branch: DcdBranch,
    merge_branch: MergeBranch,
    runner_log_level: RunnerLogLevel,
) -> anyhow::Result<Arc<RedeemNode<Elements>>> {
    let witness_values = build_dcd_witness(token_branch, branch, merge_branch);
    Ok(run_program(compiled_program, witness_values, env, runner_log_level)?.0)
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_dcd_transaction_on_liquid_testnet(
    mut tx: Transaction,
    dcd_program: &CompiledProgram,
    dcd_public_key: &XOnlyPublicKey,
    utxos: &[TxOut],
    input_index: u32,
    token_branch: TokenBranch,
    branch: DcdBranch,
    merge_branch: MergeBranch,
) -> anyhow::Result<Transaction> {
    let cmr = dcd_program.commit().cmr();

    assert!(
        utxos.len() > input_index as usize,
        "UTXOs must be greater than input index"
    );

    let target_utxo = &utxos[input_index as usize];
    let script_pubkey =
        create_p2tr_address(cmr, dcd_public_key, &AddressParams::LIQUID_TESTNET).script_pubkey();

    assert_eq!(
        target_utxo.script_pubkey, script_pubkey,
        "Expected for the UTXO to be spent by DCD to have the same script."
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
        input_index,
        cmr,
        control_block(cmr, *dcd_public_key),
        None,
        *LIQUID_TESTNET_GENESIS,
    );

    let pruned = execute_dcd_program(
        dcd_program,
        env,
        token_branch,
        branch,
        merge_branch,
        RunnerLogLevel::None,
    )?;

    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index as usize].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, *dcd_public_key).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}

pub fn oracle_msg(expiry_height: u32, price_at_current_block_height: u64) -> [u8; 32] {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&expiry_height.to_be_bytes());
    b[4..].copy_from_slice(&price_at_current_block_height.to_be_bytes());
    sha256::Hash::hash(&b).to_byte_array()
}

#[cfg(test)]
mod dcd_merge_tests {
    use super::*;

    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::dual_currency_deposit::build_arguments::DCDRatioArguments;
    use crate::dual_currency_deposit::build_witness::build_dcd_witness;
    use anyhow::Result;
    use simplicityhl::elements::secp256k1_zkp::Secp256k1;
    use simplicityhl::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1;
    use simplicityhl::simplicity::elements::confidential::{Asset, Value};
    use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::simplicity::elements::{
        self, AddressParams, AssetId, OutPoint, Script, Txid,
    };
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
    use simplicityhl_core::{
        LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_TEST_ASSET_ID_STR, get_new_asset_entropy,
    };

    #[test]
    fn test_dcd_maker_funding_path() -> Result<()> {
        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);
        let second_asset_id = AssetId::from_entropy(second_asset_entropy);
        let third_asset_id = AssetId::from_entropy(third_asset_entropy);

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: 10,
            taker_funding_end_time: 0,
            contract_expiry_time: 0,
            early_termination_end_time: 0,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();

        let mut first_reissuance_tx = Input::from_prevout(outpoint);
        first_reissuance_tx.issuance_value_amount = Some(ratio_args.filler_token_amount);
        first_reissuance_tx.issuance_inflation_keys = None;
        first_reissuance_tx.issuance_asset_entropy = Some(first_asset_entropy.to_byte_array());

        let mut second_reissuance_tx = Input::from_prevout(outpoint);
        second_reissuance_tx.issuance_value_amount = Some(ratio_args.filler_token_amount);
        second_reissuance_tx.issuance_inflation_keys = None;
        second_reissuance_tx.issuance_asset_entropy = Some(second_asset_entropy.to_byte_array());

        let mut third_reissuance_tx = Input::from_prevout(outpoint);
        third_reissuance_tx.issuance_value_amount = Some(ratio_args.filler_token_amount);
        third_reissuance_tx.issuance_inflation_keys = None;
        third_reissuance_tx.issuance_asset_entropy = Some(third_asset_entropy.to_byte_array());

        pst.add_input(first_reissuance_tx);
        pst.add_input(second_reissuance_tx);
        pst.add_input(third_reissuance_tx);
        pst.add_input(Input::from_prevout(outpoint));

        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::default(),
            None,
        ));

        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::default(),
            None,
        ));

        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::default(),
            None,
        ));

        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            ratio_args.interest_collateral_amount,
            AssetId::LIQUID_BTC,
            None,
        ));

        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            ratio_args.total_asset_amount,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            ratio_args.filler_token_amount,
            first_asset_id,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new(),
            ratio_args.filler_token_amount,
            second_asset_id,
            None,
        ));

        pst.add_output(Output::new_explicit(
            Script::new(),
            ratio_args.filler_token_amount,
            third_asset_id,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1000),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1000),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
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

        let witness_values = build_dcd_witness(
            TokenBranch::default(),
            DcdBranch::MakerFunding {
                principal_collateral_amount: ratio_args.principal_collateral_amount,
                principal_asset_amount: ratio_args.principal_asset_amount,
                interest_collateral_amount: ratio_args.interest_collateral_amount,
                interest_asset_amount: ratio_args.interest_asset_amount,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success funding path -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_taker_funding_path_with_change_and_locktime() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now + 10,
            taker_funding_end_time: now + 20,
            contract_expiry_time: now + 30,
            early_termination_end_time: now,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // Locktime window: start <= t < end and t < expiry
        pst.global.tx_data.fallback_locktime = Some(elements::LockTime::from_time(
            dcd_arguments.taker_funding_start_time + 5,
        )?);

        // Input[0]: FILLER token input that will provide change
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Outputs:
        // 0: FILLER change (available - to_get)
        let available_filler = ratio_args.filler_token_amount * 2; // 200
        let filler_to_get = ratio_args.filler_token_amount; // 100
        let filler_change = available_filler - filler_to_get; // 100
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            filler_change,
            first_asset_id,
            None,
        ));

        // 1: Collateral to covenant (deposit)
        let collateral_deposit = ratio_args.filler_per_principal_collateral * filler_to_get; // 1000
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            collateral_deposit,
            AssetId::LIQUID_BTC,
            None,
        ));

        // 2: FILLER to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            filler_to_get,
            first_asset_id,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: dcd_address.script_pubkey(),
                asset: Asset::Explicit(first_asset_id),
                value: Value::Explicit(available_filler),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::default(),
            DcdBranch::TakerFunding {
                collateral_amount_to_deposit: collateral_deposit,
                filler_token_amount_to_get: filler_to_get,
                is_change_needed: true,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success taker funding path -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_taker_early_termination_path_with_change_and_locktime() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now + 30,
            early_termination_end_time: now + 20,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // Locktime t <= early_term_end
        pst.global.tx_data.fallback_locktime = Some(elements::LockTime::from_time(
            dcd_arguments.early_termination_end_time - 5,
        )?);

        // Inputs: 0 -> collateral, 1 -> filler token
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);
        pst.add_input(Input::from_prevout(outpoint));

        let collateral_get = ratio_args.principal_collateral_amount; // 1000
        let filler_return = ratio_args.filler_token_amount; // 100
        let available_collateral = collateral_get + 500; // to force change
        let collateral_change = available_collateral - collateral_get; // 500

        // 0: collateral change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            collateral_change,
            AssetId::LIQUID_BTC,
            None,
        ));
        // 1: return filler to covenant (same script)
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            filler_return,
            first_asset_id,
            None,
        ));
        // 2: return collateral to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            collateral_get,
            AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(available_collateral),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(first_asset_id),
                    value: Value::Explicit(filler_return),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::default(),
            DcdBranch::TakerEarlyTermination {
                is_change_needed: true,
                index_to_spend: 0,
                filler_token_amount_to_return: filler_return,
                collateral_amount_to_get: collateral_get,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success taker early termination path -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_maker_collateral_termination_path_with_change_and_locktime() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now + 30,
            early_termination_end_time: now + 20,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime = Some(elements::LockTime::from_time(
            dcd_arguments.early_termination_end_time - 1,
        )?);

        // Inputs: 0 -> collateral, 1 -> grantor collateral token
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);
        pst.add_input(Input::from_prevout(outpoint));

        let grantor_burn = ratio_args.filler_token_amount / 2; // 50
        let collateral_get = ratio_args.interest_collateral_amount / 2; // 1000
        let collateral_change = ratio_args.interest_collateral_amount - collateral_get;

        // 0: collateral change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            collateral_change,
            AssetId::LIQUID_BTC,
            None,
        ));
        // 1: burn grantor collateral token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_burn,
            second_asset_id,
            None,
        ));
        // 2: return collateral to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            collateral_get,
            AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(ratio_args.interest_collateral_amount),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(second_asset_id),
                    value: Value::Explicit(grantor_burn),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::Maker,
            DcdBranch::MakerTermination {
                is_change_needed: true,
                index_to_spend: 0,
                grantor_token_amount_to_burn: grantor_burn,
                amount_to_get: collateral_get,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::None).is_err() {
            panic!("expected success maker collateral termination path -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_maker_settlement_termination_path_with_change_and_locktime() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now + 30,
            early_termination_end_time: now + 20,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime = Some(elements::LockTime::from_time(
            dcd_arguments.early_termination_end_time - 1,
        )?);

        // Inputs: 0 -> settlement asset, 1 -> grantor settlement token
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);
        pst.add_input(Input::from_prevout(outpoint));

        let grantor_burn = ratio_args.filler_token_amount / 2; // 100
        let settlement_get = ratio_args.total_asset_amount / 2; // 11000
        let settlement_change = ratio_args.total_asset_amount - settlement_get;

        // 0: settlement change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            settlement_change,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));
        // 1: burn grantor settlement token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_burn,
            third_asset_id,
            None,
        ));
        // 2: return settlement to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            settlement_get,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?),
                    value: Value::Explicit(ratio_args.total_asset_amount),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(third_asset_id),
                    value: Value::Explicit(grantor_burn),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            DcdBranch::MakerTermination {
                is_change_needed: true,
                index_to_spend: 0,
                grantor_token_amount_to_burn: grantor_burn,
                amount_to_get: settlement_get,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success maker settlement termination path -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_maker_settlement_path_price_le_strike() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let secp = Secp256k1::new();
        let oracle_sk = secp256k1::SecretKey::from_slice(&[3u8; 32])?;
        let oracle_kp = Keypair::from_secret_key(&secp, &oracle_sk);
        let oracle_schnorr_kp = Keypair::from_secret_key(&secp, &oracle_sk);

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let settlement_height = 100u32;
        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // Height lock for settlement
        pst.global.tx_data.fallback_locktime =
            Some(elements::LockTime::from_height(settlement_height)?);
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Maker gets ALT branch (price <= strike): input is SETTLEMENT asset
        let amount_to_get = ratio_args.total_asset_amount / 2; // 11000
        let grantor_burn = ratio_args.filler_token_amount / 2; // 100
        let available_settlement = ratio_args.total_asset_amount;

        // 0: settlement change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            available_settlement - amount_to_get,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));
        // 1: burn grantor settlement token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_burn,
            third_asset_id,
            None,
        ));
        // 2: burn grantor collateral token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_burn,
            second_asset_id,
            None,
        ));
        // 3: settlement to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            amount_to_get,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        // Oracle signature for price <= strike
        let price = strike_price - 2; // <= strike
        let msg = oracle_msg(settlement_height, price);
        let sig = secp.sign_schnorr(
            &secp256k1::Message::from_digest_slice(&msg)?,
            &oracle_schnorr_kp,
        );

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: dcd_address.script_pubkey(),
                asset: Asset::Explicit(AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?),
                value: Value::Explicit(available_settlement),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::Maker,
            DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &sig,
                index_to_spend: 0,
                amount_to_burn: grantor_burn,
                amount_to_get,
                is_change_needed: true,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success maker settlement (price <= strike) -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_maker_settlement_path_price_gt_strike() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let secp = Secp256k1::new();
        let oracle_sk = secp256k1::SecretKey::from_slice(&[3u8; 32])?;
        let oracle_kp = Keypair::from_secret_key(&secp, &oracle_sk);
        let oracle_schnorr_kp = Keypair::from_secret_key(&secp, &oracle_sk);

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let settlement_height = 100u32;
        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // Height lock for settlement
        pst.global.tx_data.fallback_locktime =
            Some(elements::LockTime::from_height(settlement_height)?);
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Maker gets LBTC branch (price > strike): input is COLLATERAL
        let amount_to_get = ratio_args.total_collateral_amount / 2; // 1100
        let grantor_burn = ratio_args.filler_token_amount / 2; // 100
        let available_collateral = ratio_args.total_collateral_amount;

        // 0: collateral change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            available_collateral - amount_to_get,
            AssetId::LIQUID_BTC,
            None,
        ));
        // 1: burn grantor collateral token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_burn,
            second_asset_id,
            None,
        ));
        // 2: burn grantor settlement token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_burn,
            third_asset_id,
            None,
        ));
        // 3: collateral to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            amount_to_get,
            AssetId::LIQUID_BTC,
            None,
        ));

        // Oracle signature for price > strike
        let price = strike_price + 2; // > strike
        let msg = oracle_msg(settlement_height, price);
        let sig = secp.sign_schnorr(
            &secp256k1::Message::from_digest_slice(&msg)?,
            &oracle_schnorr_kp,
        );

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: dcd_address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(available_collateral),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::Maker,
            DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &sig,
                index_to_spend: 0,
                amount_to_burn: grantor_burn,
                amount_to_get,
                is_change_needed: true,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success maker settlement (price > strike) -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_taker_settlement_path_price_le_strike() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let secp = Secp256k1::new();
        let oracle_sk = secp256k1::SecretKey::from_slice(&[3u8; 32])?;
        let oracle_kp = Keypair::from_secret_key(&secp, &oracle_sk);
        let oracle_schnorr_kp = Keypair::from_secret_key(&secp, &oracle_sk);

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let settlement_height = 100u32;
        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime =
            Some(elements::LockTime::from_height(settlement_height)?);
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Taker receives LBTC (price <= strike): input is COLLATERAL
        let amount_to_get = ratio_args.total_collateral_amount / 2; // 1100
        let filler_burn = ratio_args.filler_token_amount / 2; // 100
        let available_collateral = ratio_args.total_collateral_amount;

        // 0: collateral change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            available_collateral - amount_to_get,
            AssetId::LIQUID_BTC,
            None,
        ));
        // 1: burn filler token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            filler_burn,
            first_asset_id,
            None,
        ));
        // 2: collateral to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            amount_to_get,
            AssetId::LIQUID_BTC,
            None,
        ));

        // Oracle sig
        let price = strike_price - 2; // <= strike
        let msg = oracle_msg(settlement_height, price);
        let sig = secp.sign_schnorr(
            &secp256k1::Message::from_digest_slice(&msg)?,
            &oracle_schnorr_kp,
        );

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: dcd_address.script_pubkey(),
                asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                value: Value::Explicit(available_collateral),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &sig,
                index_to_spend: 0,
                amount_to_burn: filler_burn,
                amount_to_get,
                is_change_needed: true,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success taker settlement (price <= strike) -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_taker_settlement_path_price_gt_strike() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let secp = Secp256k1::new();
        let oracle_sk = secp256k1::SecretKey::from_slice(&[3u8; 32])?;
        let oracle_kp = Keypair::from_secret_key(&secp, &oracle_sk);
        let oracle_schnorr_kp = Keypair::from_secret_key(&secp, &oracle_sk);

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy); // FILLER
        let second_asset_id = AssetId::from_entropy(second_asset_entropy); // GRANTOR_COLLATERAL
        let third_asset_id = AssetId::from_entropy(third_asset_entropy); // GRANTOR_SETTLEMENT

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let settlement_height = 100u32;
        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime =
            Some(elements::LockTime::from_height(settlement_height)?);
        pst.add_input(Input::from_prevout(outpoint));
        pst.inputs_mut()[0].sequence = Some(elements::Sequence::ENABLE_LOCKTIME_NO_RBF);

        // Taker receives SETTLEMENT (price > strike): input is SETTLEMENT asset
        let amount_to_get = ratio_args.total_asset_amount / 2; // 11000
        let filler_burn = ratio_args.filler_token_amount / 2; // 100
        let available_settlement = ratio_args.total_asset_amount;

        // 0: settlement change
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            available_settlement - amount_to_get,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));
        // 1: burn filler token (OP_RETURN)
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            filler_burn,
            first_asset_id,
            None,
        ));
        // 2: settlement to user
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            amount_to_get,
            AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?,
            None,
        ));

        // Oracle sig
        let price = strike_price + 2; // > strike
        let msg = oracle_msg(settlement_height, price);
        let sig = secp.sign_schnorr(
            &secp256k1::Message::from_digest_slice(&msg)?,
            &oracle_schnorr_kp,
        );

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey: dcd_address.script_pubkey(),
                asset: Asset::Explicit(AssetId::from_str(LIQUID_TESTNET_TEST_ASSET_ID_STR)?),
                value: Value::Explicit(available_settlement),
            }],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &sig,
                index_to_spend: 0,
                amount_to_burn: filler_burn,
                amount_to_get,
                is_change_needed: true,
            },
            MergeBranch::default(),
        );

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success taker settlement (price > strike) -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_merge_2_tokens() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);
        let second_asset_id = AssetId::from_entropy(second_asset_entropy);
        let third_asset_id = AssetId::from_entropy(third_asset_entropy);

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // 2 tokens to merge + 1 fee => 3 inputs
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));

        // 3 outputs required
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values =
            build_dcd_witness(TokenBranch::default(), DcdBranch::Merge, MergeBranch::Two);

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success merge 2 tokens -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_merge_3_tokens() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);
        let second_asset_id = AssetId::from_entropy(second_asset_entropy);
        let third_asset_id = AssetId::from_entropy(third_asset_entropy);

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // 3 tokens to merge + 1 fee => 4 inputs
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));

        // 3 outputs required
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values =
            build_dcd_witness(TokenBranch::default(), DcdBranch::Merge, MergeBranch::Three);

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success merge 3 tokens -- dcd price attested");
        }

        Ok(())
    }

    #[test]
    fn test_dcd_merge_4_tokens() -> Result<()> {
        let now: u32 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;

        let oracle_kp = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[3u8; 32])?,
        );

        let outpoint = OutPoint::new(Txid::from_slice(&[2; 32])?, 33);

        let first_asset_entropy = get_new_asset_entropy(&outpoint, [1; 32]);
        let second_asset_entropy = get_new_asset_entropy(&outpoint, [2; 32]);
        let third_asset_entropy = get_new_asset_entropy(&outpoint, [3; 32]);

        let first_asset_id = AssetId::from_entropy(first_asset_entropy);
        let second_asset_id = AssetId::from_entropy(second_asset_entropy);
        let third_asset_id = AssetId::from_entropy(third_asset_entropy);

        let strike_price = 10;
        let incentive_basis_points = 1000; // 10%
        let ratio_args =
            DCDRatioArguments::build_from(1000, incentive_basis_points, strike_price, 10)?;

        let dcd_arguments = DCDArguments {
            taker_funding_start_time: now,
            taker_funding_end_time: now,
            contract_expiry_time: now,
            early_termination_end_time: now,
            settlement_height: 0,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le: AssetId::LIQUID_BTC.to_string(),
            settlement_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            filler_token_asset_id_hex_le: first_asset_id.to_string(),
            grantor_collateral_token_asset_id_hex_le: second_asset_id.to_string(),
            grantor_settlement_token_asset_id_hex_le: third_asset_id.to_string(),
            ratio_args: ratio_args.clone(),
            oracle_public_key: oracle_kp.x_only_public_key().0.to_string(),
        };

        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[1u8; 32])?,
        );
        let dcd_address = get_dcd_address(
            &keypair.x_only_public_key().0,
            &dcd_arguments,
            &AddressParams::LIQUID_TESTNET,
        )?;

        let mut pst = PartiallySignedTransaction::new_v2();
        // 4 tokens to merge + 1 fee => 5 inputs
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_input(Input::from_prevout(outpoint));

        // 3 outputs required
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));
        pst.add_output(Output::new_explicit(
            dcd_address.script_pubkey(),
            1,
            AssetId::LIQUID_BTC,
            None,
        ));

        let program = get_compiled_dcd_program(&dcd_arguments);

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
                ElementsUtxo {
                    script_pubkey: dcd_address.script_pubkey(),
                    asset: Asset::Explicit(LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(1),
                },
            ],
            0,
            simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let witness_values =
            build_dcd_witness(TokenBranch::default(), DcdBranch::Merge, MergeBranch::Four);

        if run_program(&program, witness_values, env, RunnerLogLevel::Debug).is_err() {
            panic!("expected success merge 4 tokens -- dcd price attested");
        }

        Ok(())
    }
}
