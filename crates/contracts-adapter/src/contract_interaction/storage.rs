use anyhow::Result;

use simplicityhl::simplicity::bitcoin::key::Keypair;
use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplicityhl::{CompiledProgram, elements};
use std::collections::HashMap;
use std::sync::Arc;

use simplicityhl::simplicity::ToXOnlyPubkey;

use contracts::{execute_storage_program, get_storage_address, get_storage_compiled_program};

use contracts::StorageArguments;
use simplicityhl::elements::OutPoint;
use simplicityhl::elements::bitcoin::{XOnlyPublicKey, secp256k1};
use simplicityhl::simplicity::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::simplicity::elements::hex::ToHex;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::simplicity::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::simplicity::elements::{
    AddressParams, AssetId, BlockHash, Script, Transaction, TxInWitness, TxOut, TxOutSecrets,
};
use simplicityhl::simplicity::hashes::sha256;
use simplicityhl_core::{
    AssetEntropyBytes, TaprootPubkeyGen, control_block, create_p2tr_address,
    derive_public_blinder_key, fetch_utxo, finalize_p2pk_transaction, get_p2pk_address,
    get_random_seed, obtain_utxo_value,
};

#[allow(clippy::too_many_arguments)]
pub fn update_storage(
    keypair: &Keypair,
    blinder_key: &Keypair,
    fee_utxo: OutPoint,
    storage_utxo: OutPoint,
    reissuance_token_utxo: OutPoint,
    taproot_pubkey_gen: &str,
    new_value: u64,
    fee_amount: u64,
    asset_entropy_hex: impl AsRef<[u8]>,
    storage_arguments: &StorageArguments,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let storage_utxo_tx_out = fetch_utxo(storage_utxo)?;
    let reissuance_token_tx_out = fetch_utxo(reissuance_token_utxo)?;
    let fee_utxo_tx_out = fetch_utxo(fee_utxo)?;

    let total_input_fee = obtain_utxo_value(&fee_utxo_tx_out)?;

    let asset_entropy_hex = hex::decode(asset_entropy_hex)?;

    let mut asset_entropy_bytes: [u8; 32] = asset_entropy_hex.try_into().unwrap();
    asset_entropy_bytes.reverse();

    let asset_entropy = sha256::Midstate::from_byte_array(asset_entropy_bytes);

    let blinder_sk = derive_public_blinder_key().secret_key();
    let unblinded = reissuance_token_tx_out.unblind(&Secp256k1::new(), blinder_sk)?;

    // Auto-unblind token UTXOs to obtain ABFs for reissuance nonce
    let token_abf = unblinded.asset_bf;

    let asset = AssetId::from_entropy(asset_entropy);
    let token_id = AssetId::reissuance_token_from_entropy(asset_entropy, false);

    let storage_taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
        taproot_pubkey_gen,
        storage_arguments,
        address_params,
        &get_storage_address,
    )?;

    assert_eq!(
        storage_taproot_pubkey_gen.address.script_pubkey(),
        storage_utxo_tx_out.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the option utxo script pubkey"
    );

    let (new_value, old_value) = (new_value, obtain_utxo_value(&storage_utxo_tx_out)?);

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

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut inp_txout_sec = HashMap::new();
    let mut pst = PartiallySignedTransaction::new_v2();

    {
        let mut asset_tx = Input::from_prevout(storage_utxo);
        asset_tx.witness_utxo = Some(storage_utxo_tx_out.clone());
        asset_tx.blinded_issuance = Some(0x00);
        pst.add_input(asset_tx);
    }

    if !is_burn {
        let mut reissuance_tx = Input::from_prevout(reissuance_token_utxo);
        reissuance_tx.witness_utxo = Some(reissuance_token_tx_out.clone());
        reissuance_tx.issuance_value_amount = Some(storage_change);
        reissuance_tx.issuance_inflation_keys = None;
        reissuance_tx.issuance_asset_entropy = Some(asset_entropy.to_byte_array());

        pst.add_input(reissuance_tx);
    }

    let mut fee_tx = Input::from_prevout(fee_utxo);
    fee_tx.witness_utxo = Some(fee_utxo_tx_out.clone());
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
            reissuance_token_tx_out.script_pubkey.clone(),
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
        lbtc_asset,
        None,
    );
    pst.add_output(output);

    // Add fee
    let output = Output::new_explicit(Script::new(), fee_amount, lbtc_asset, None);
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

    if !is_burn {
        inp_txout_sec.insert(1, token_secrets);
        pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;
    }

    let utxos = if !is_burn {
        vec![
            storage_utxo_tx_out.clone(),
            reissuance_token_tx_out.clone(),
            fee_utxo_tx_out.clone(),
        ]
    } else {
        vec![storage_utxo_tx_out.clone(), fee_utxo_tx_out.clone()]
    };
    let storage_program = get_storage_compiled_program(storage_arguments);

    let tx = pst.extract_tx()?;
    let tx = finalize_storage_transaction(
        tx,
        &storage_program,
        &storage_taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        new_value,
        keypair,
        address_params,
        genesis_block_hash,
    )?;

    let tx = if !is_burn {
        finalize_storage_transaction(
            tx,
            &storage_program,
            &storage_taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
            &utxos,
            1,
            new_value,
            keypair,
            address_params,
            genesis_block_hash,
        )?
    } else {
        tx
    };

    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        keypair,
        if is_burn { 1 } else { 2 },
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    Ok(tx)
}

pub fn init_state(
    keypair: &Keypair,
    blinder_key: &Keypair,
    fee_utxo: OutPoint,
    fee_amount: u64,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<(
    AssetEntropyBytes,
    StorageArguments,
    TaprootPubkeyGen,
    Transaction,
)> {
    const INIT_TOKEN_SUPPLY: u64 = 1;

    let utxo_tx_out = fetch_utxo(fee_utxo)?;
    let utxo_total_input_fee = obtain_utxo_value(&utxo_tx_out)?;

    let asset_entropy = get_random_seed();

    let mut issuance_tx = {
        let mut input = Input::from_prevout(fee_utxo);
        input.witness_utxo = Some(utxo_tx_out.clone());
        input.issuance_value_amount = Some(1);
        input.issuance_inflation_keys = Some(1);
        input.issuance_asset_entropy = Some(asset_entropy);
        input
    };

    let (asset, reissuance_asset) = issuance_tx.issuance_ids();

    let storage_arguments = StorageArguments {
        public_key: keypair.x_only_public_key().0.serialize(),
        slot_asset: asset.to_hex(),
    };

    let storage_taproot_pubkey_gen =
        TaprootPubkeyGen::from(&storage_arguments, address_params, &get_storage_address)?;

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut inp_txout_sec = HashMap::new();
    let mut pst = PartiallySignedTransaction::new_v2();

    // Create issue tx input
    {
        issuance_tx.blinded_issuance = Some(0x00);

        pst.add_input(issuance_tx);
        // For explicit inputs, the blinding factors are zero and values/assets are explicit.
        let input_secrets = TxOutSecrets {
            asset_bf: AssetBlindingFactor::zero(),
            value_bf: ValueBlindingFactor::zero(),
            value: utxo_total_input_fee,
            asset: lbtc_asset,
        };

        inp_txout_sec.insert(0, input_secrets);
    }

    // Issuance out
    pst.add_output(Output::new_explicit(
        storage_taproot_pubkey_gen.address.script_pubkey(),
        INIT_TOKEN_SUPPLY,
        asset,
        None,
    ));

    // Reissuance token
    {
        let mut output = Output::new_explicit(
            storage_taproot_pubkey_gen.address.script_pubkey(),
            INIT_TOKEN_SUPPLY,
            reissuance_asset,
            Some(blinder_key.public_key().into()),
        );
        output.blinder_index = Some(0);
        pst.add_output(output);
    }

    // Add L-BTC change
    {
        let output = Output::new_explicit(
            change_recipient.script_pubkey(),
            utxo_total_input_fee - fee_amount,
            lbtc_asset,
            None,
        );
        pst.add_output(output);
    }

    // Add fee
    {
        let output = Output::new_explicit(Script::new(), fee_amount, lbtc_asset, None);
        pst.add_output(output);
    }

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

    let utxos = [utxo_tx_out];
    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        &utxos,
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok((
        asset_entropy,
        storage_arguments,
        storage_taproot_pubkey_gen,
        tx,
    ))
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
