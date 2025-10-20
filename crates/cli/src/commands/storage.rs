use crate::modules::keys::derive_secret_key_from_index;
use crate::modules::store::Store;

use anyhow::Result;

use simplicityhl::CompiledProgram;
use simplicityhl::simplicity::bitcoin::key::Keypair;
use simplicityhl::simplicity::bitcoin::secp256k1::SecretKey;
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use std::collections::HashMap;
use std::sync::Arc;

use clap::Subcommand;
use simplicityhl::simplicity::ToXOnlyPubkey;

use contracts::{execute_storage_program, get_storage_address, get_storage_compiled_program};

use contracts::StorageArguments;
use simplicityhl::elements::OutPoint;
use simplicityhl::elements::bitcoin::{XOnlyPublicKey, secp256k1};
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::simplicity::elements::hex::ToHex;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::simplicity::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::simplicity::elements::{
    AddressParams, AssetId, BlockHash, Script, Transaction, TxInWitness, TxOut, TxOutSecrets,
};
use simplicityhl::simplicity::hashes::sha256;
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    Encodable, LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, TaprootPubkeyGen,
    broadcast_tx, control_block, create_p2tr_address, fetch_utxo, finalize_p2pk_transaction,
    get_new_asset_entropy, get_p2pk_address, get_random_seed,
};

#[derive(Subcommand, Debug)]
pub enum Storage {
    Import {
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        storage_taproot_pubkey_gen: String,
        /// Encoded options arguments
        #[arg(long = "encoded-options-arguments")]
        encoded_storage_arguments: String,
    },
    Export {
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        storage_taproot_pubkey_gen: String,
    },

    /// Create state and reissuance token
    InitState {
        /// Fee utxo
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Update state using previous state and reissuance token
    UpdateState {
        /// First fee utxo
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Storage utxo
        #[arg(long = "storage-utxo")]
        storage_utxo: OutPoint,
        /// Reissuance token utxo
        #[arg(long = "reissuance-token-utxo")]
        reissuance_token_utxo: OutPoint,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// Storage taproot pubkey gen
        #[arg(long = "taproot-pubkey-gen")]
        taproot_pubkey_gen: String,
        /// New value to store
        #[arg(long = "new-value")]
        new_value: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

impl Storage {
    pub fn handle(&self) -> Result<()> {
        match self {
            Storage::Import {
                storage_taproot_pubkey_gen,
                encoded_storage_arguments,
            } => {
                Store::load()?.import_arguments(
                    storage_taproot_pubkey_gen,
                    encoded_storage_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &get_storage_address,
                )?;
            }
            Storage::Export {
                storage_taproot_pubkey_gen,
            } => {
                println!(
                    "{}",
                    Store::load()?.export_arguments(storage_taproot_pubkey_gen)?
                );
            }
            Storage::InitState {
                fee_utxo,
                account_index,
                fee_amount,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let blinder_key = Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let utxo = fetch_utxo(*fee_utxo)?;

                let asset_entropy = get_random_seed();

                let mut issuance_tx = Input::from_prevout(*fee_utxo);
                issuance_tx.witness_utxo = Some(utxo.clone());
                issuance_tx.issuance_value_amount = Some(1);
                issuance_tx.issuance_inflation_keys = Some(1);
                issuance_tx.issuance_asset_entropy = Some(asset_entropy);

                let (asset, reissuance_asset) = issuance_tx.issuance_ids();

                let storage_arguments = StorageArguments {
                    public_key: keypair.x_only_public_key().0.serialize(),
                    slot_asset: asset.to_hex(),
                };

                let storage_taproot_pubkey_gen = TaprootPubkeyGen::from(
                    &storage_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &get_storage_address,
                )?;

                println!("taproot_pubkey_gen: {}", storage_taproot_pubkey_gen);

                store.import_arguments(
                    &storage_taproot_pubkey_gen.to_string(),
                    &storage_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &get_storage_address,
                )?;

                store.store.insert(
                    format!("entropy_{}", storage_taproot_pubkey_gen),
                    get_new_asset_entropy(fee_utxo, asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let total_input_fee = utxo.value.explicit().unwrap();

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.add_input(issuance_tx);

                pst.add_output(Output::new_explicit(
                    storage_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    asset,
                    None,
                ));

                let mut output = Output::new_explicit(
                    storage_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    reissuance_asset,
                    Some(blinder_key.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);

                // Add L-BTC change
                let output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                // Add fee
                let output = Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                // For explicit inputs, the blinding factors are zero and values/assets are explicit.
                let input_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: utxo
                        .value
                        .explicit()
                        .expect("expected explicit value for first issuance input"),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };

                let mut inp_txout_sec = HashMap::new();
                inp_txout_sec.insert(0, input_secrets);

                let input = &mut pst.inputs_mut()[0];
                input.blinded_issuance = Some(0x00);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

                let utxos = vec![utxo];
                let tx = finalize_p2pk_transaction(
                    pst.extract_tx()?,
                    &utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
            }
            Storage::UpdateState {
                fee_utxo,
                storage_utxo,
                reissuance_token_utxo,
                account_index,
                taproot_pubkey_gen,
                new_value,
                fee_amount,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let blinder_key = Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let storage = fetch_utxo(*storage_utxo)?;
                let reissuance = fetch_utxo(*reissuance_token_utxo)?;
                let fee = fetch_utxo(*fee_utxo)?;

                let total_input_fee = fee.value.explicit().unwrap();

                let Some(asset_entropy_hex) =
                    store.store.get(format!("entropy_{}", taproot_pubkey_gen))?
                else {
                    anyhow::bail!("First entropy not found");
                };

                let asset_entropy_hex = hex::decode(asset_entropy_hex)?;

                let mut asset_entropy_bytes: [u8; 32] = asset_entropy_hex.try_into().unwrap();
                asset_entropy_bytes.reverse();

                let asset_entropy = sha256::Midstate::from_byte_array(asset_entropy_bytes);

                let blinder_sk = SecretKey::from_slice(&[1; 32])?;
                let unblinded = reissuance.unblind(&Secp256k1::new(), blinder_sk)?;

                // Auto-unblind token UTXOs to obtain ABFs for reissuance nonce
                let token_abf = unblinded.asset_bf;

                let asset = AssetId::from_entropy(asset_entropy);
                let token_id = AssetId::reissuance_token_from_entropy(asset_entropy, false);

                let storage_arguments: StorageArguments =
                    store.get_arguments(taproot_pubkey_gen)?;

                let storage_taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    taproot_pubkey_gen,
                    &storage_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &get_storage_address,
                )?;

                assert_eq!(
                    storage_taproot_pubkey_gen.address.script_pubkey(),
                    storage.script_pubkey,
                    "Expected the taproot pubkey gen address to be the same as the option utxo script pubkey"
                );

                let old_value = storage
                    .value
                    .explicit()
                    .expect("storage UTXO value need to be explicit");
                let new_value = *new_value;

                if old_value == new_value {
                    anyhow::bail!("In this storage PoC we expect for the value to be changed!")
                }

                let (storage_change, is_burn) = {
                    if old_value < new_value {
                        (new_value - old_value, false)
                    } else {
                        (old_value - new_value, true)
                    }
                };

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();

                let mut asset_tx = Input::from_prevout(*storage_utxo);
                asset_tx.witness_utxo = Some(storage.clone());
                pst.add_input(asset_tx);

                if !is_burn {
                    let mut reissuance_tx = Input::from_prevout(*reissuance_token_utxo);
                    reissuance_tx.witness_utxo = Some(reissuance.clone());
                    reissuance_tx.issuance_value_amount = Some(storage_change);
                    reissuance_tx.issuance_inflation_keys = None;
                    reissuance_tx.issuance_asset_entropy = Some(asset_entropy.to_byte_array());

                    pst.add_input(reissuance_tx);
                }

                let mut fee_tx = Input::from_prevout(*fee_utxo);
                fee_tx.witness_utxo = Some(fee.clone());
                pst.add_input(fee_tx);

                // Output 0: storage state with new value
                let output = Output::new_explicit(
                    storage_taproot_pubkey_gen.address.script_pubkey(),
                    new_value,
                    asset,
                    None,
                );
                pst.add_output(output);

                if is_burn {
                    // Output 1: burn OP_RETURN of the storage asset
                    let output = Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        storage_change,
                        asset,
                        None,
                    );
                    pst.add_output(output);
                } else {
                    // Output 1: add reissuance token for minting
                    let mut output = Output::new_explicit(
                        reissuance.script_pubkey.clone(),
                        1,
                        token_id,
                        Some(blinder_key.public_key().into()),
                    );
                    output.blinder_index = Some(1);
                    pst.add_output(output);
                }

                // Add change
                let output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                // Add fee
                let output = Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                if !is_burn {
                    let input = &mut pst.inputs_mut()[1];
                    input.blinded_issuance = Some(0x00);
                    input.issuance_blinding_nonce = Some(token_abf.into_inner());
                }

                let token_secrets = TxOutSecrets {
                    asset_bf: unblinded.asset_bf,
                    value_bf: unblinded.value_bf,
                    value: unblinded.value,
                    asset: unblinded.asset,
                };

                let mut inp_txout_sec = HashMap::new();
                if !is_burn {
                    inp_txout_sec.insert(1, token_secrets);
                    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;
                }

                let utxos = if !is_burn {
                    vec![storage.clone(), reissuance.clone(), fee.clone()]
                } else {
                    vec![storage.clone(), fee.clone()]
                };
                let storage_program = get_storage_compiled_program(&storage_arguments);

                let tx = finalize_storage_transaction(
                    pst.extract_tx()?,
                    &storage_program,
                    &storage_taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    new_value,
                    &keypair,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let tx = if !is_burn {
                    finalize_storage_transaction(
                        tx,
                        &storage_program,
                        &storage_taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                        &utxos,
                        1,
                        new_value,
                        &keypair,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?
                } else {
                    tx
                };

                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    if is_burn { 1 } else { 2 },
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_storage_transaction(
    mut tx: Transaction,
    program: &CompiledProgram,
    storage_public_key: &XOnlyPublicKey,
    utxos: &[TxOut],
    input_index: u32,
    new_value: u64,
    keypair: &Keypair,
    params: &'static AddressParams,
    genesis_hash: BlockHash,
) -> Result<Transaction> {
    let cmr = program.commit().cmr();

    assert!(
        utxos.len() > input_index as usize,
        "UTXOs must be greater than input index"
    );

    let target_utxo = &utxos[input_index as usize];
    let script_pubkey = create_p2tr_address(cmr, storage_public_key, params).script_pubkey();

    assert_eq!(
        target_utxo.script_pubkey, script_pubkey,
        "Expected for the UTXO to be spent to have the same script."
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
        control_block(cmr, *storage_public_key),
        None,
        genesis_hash,
    );

    let pruned = execute_storage_program(new_value, keypair, program, env)?;

    let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
    let cmr = pruned.cmr();

    tx.input[input_index as usize].witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            simplicity_witness_bytes,
            simplicity_program_bytes,
            cmr.as_ref().to_vec(),
            control_block(cmr, *storage_public_key).serialize(),
        ],
        pegin_witness: vec![],
    };

    Ok(tx)
}
