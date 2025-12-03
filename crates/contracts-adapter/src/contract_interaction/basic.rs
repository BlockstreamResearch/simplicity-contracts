use anyhow::anyhow;

use simplicityhl::elements;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::hashes::sha256::Midstate;
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{AssetId, Script, Transaction, TxOutSecrets};
use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::confidential::Asset;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{Address, AddressParams, OutPoint, TxOut};
use simplicityhl_core::{
    AssetEntropyHex, LIQUID_TESTNET_BITCOIN_ASSET, fetch_utxo, finalize_p2pk_transaction,
    get_new_asset_entropy, get_p2pk_address, get_random_seed, obtain_utxo_value,
};
use tracing::instrument;

pub struct IssueAssetResponse {
    pub tx: Transaction,
    pub asset_id: AssetId,
    pub reissuance_asset_id: AssetId,
    pub asset_entropy: AssetEntropyHex,
}

pub struct ReissueAssetResponse {
    pub tx: Transaction,
    pub asset_id: AssetId,
    pub reissuance_asset_id: AssetId,
}

/// Reissue an existing asset by spending its reissuance token.
///
/// # Errors
/// Returns error if UTXO fetch fails, fee exceeds input, or transaction finalization fails.
///
/// # Panics
/// Panics if the fee UTXO value is confidential.
#[expect(clippy::too_many_arguments)]
pub async fn reissue_asset(
    keypair: &Keypair,
    blinding_key: &Keypair,
    reissue_asset_outpoint: OutPoint,
    fee_utxo_outpoint: OutPoint,
    reissue_amount: u64,
    fee_amount: u64,
    asset_entropy: Midstate,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<ReissueAssetResponse> {
    let reissue_utxo_tx_out = fetch_utxo(reissue_asset_outpoint).await?;
    let fee_utxo_tx_out = fetch_utxo(fee_utxo_outpoint).await?;

    let total_input_fee = fee_utxo_tx_out.value.explicit().unwrap();
    if fee_amount > total_input_fee {
        return Err(anyhow!(
            "fee exceeds fee input value, fee_input: {fee_amount}, total_input_fee: {total_input_fee}"
        ));
    }

    let blinding_sk = blinding_key.secret_key();

    let unblinded = reissue_utxo_tx_out.unblind(&Secp256k1::new(), blinding_sk)?;
    let asset_bf = unblinded.asset_bf;

    let asset_id = AssetId::from_entropy(asset_entropy);
    let reissuance_asset_id = AssetId::reissuance_token_from_entropy(asset_entropy, false);

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut inp_txout_sec = std::collections::HashMap::new();
    let mut pst = PartiallySignedTransaction::new_v2();

    // Reissuance token input
    {
        let mut reissuance_tx = Input::from_prevout(reissue_asset_outpoint);
        reissuance_tx.witness_utxo = Some(reissue_utxo_tx_out.clone());
        reissuance_tx.issuance_value_amount = Some(reissue_amount);
        reissuance_tx.issuance_inflation_keys = None;
        reissuance_tx.issuance_asset_entropy = Some(asset_entropy.to_byte_array());

        reissuance_tx.blinded_issuance = Some(0x00);
        reissuance_tx.issuance_blinding_nonce = Some(asset_bf.into_inner());

        pst.add_input(reissuance_tx);
        inp_txout_sec.insert(0, unblinded);
    }

    // Fee input
    {
        let mut fee_input = Input::from_prevout(fee_utxo_outpoint);
        fee_input.witness_utxo = Some(fee_utxo_tx_out.clone());
        pst.add_input(fee_input);
    }

    // Passing Reissuance token to new tx_out
    {
        let mut output = Output::new_explicit(
            change_recipient.script_pubkey(),
            1,
            reissuance_asset_id,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(0);
        pst.add_output(output);
    }

    //  Defining the amount of token to reissue
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        reissue_amount,
        asset_id,
        None,
    ));

    // Change
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_fee - fee_amount,
        lbtc_asset,
        None,
    ));

    // Fee
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

    let utxos = vec![reissue_utxo_tx_out, fee_utxo_tx_out];

    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        &utxos,
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;
    let tx = finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, genesis_block_hash)?;
    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(ReissueAssetResponse {
        tx,
        asset_id,
        reissuance_asset_id,
    })
}

/// Issue a new asset with given amount.
///
/// # Errors
/// Returns error if UTXO fetch fails, fee exceeds input, or transaction finalization fails.
///
/// # Panics
/// Panics if UTXO value is confidential.
#[expect(clippy::too_many_arguments)]
pub async fn issue_asset(
    keypair: &Keypair,
    blinding_key: &Keypair,
    fee_utxo_outpoint: OutPoint,
    issue_amount: u64,
    fee_amount: u64,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<IssueAssetResponse> {
    let fee_utxo_tx_out = fetch_utxo(fee_utxo_outpoint).await?;

    let total_input_fee = obtain_utxo_value(&fee_utxo_tx_out)?;
    if fee_amount > total_input_fee {
        return Err(anyhow!(
            "fee exceeds fee input value, fee_input: {fee_amount}, total_input_fee: {total_input_fee}"
        ));
    }

    let asset_entropy = get_random_seed();
    let asset_entropy_to_return = get_new_asset_entropy(&fee_utxo_outpoint, asset_entropy).to_hex();

    let mut issuance_tx = Input::from_prevout(fee_utxo_outpoint);
    issuance_tx.witness_utxo = Some(fee_utxo_tx_out.clone());
    issuance_tx.issuance_value_amount = Some(issue_amount);
    issuance_tx.issuance_inflation_keys = Some(1);
    issuance_tx.issuance_asset_entropy = Some(asset_entropy);

    let (asset_id, reissuance_asset_id) = issuance_tx.issuance_ids();

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut inp_txout_sec = std::collections::HashMap::new();
    let mut pst = PartiallySignedTransaction::new_v2();

    // Issuance token input
    {
        let issuance_secrets = TxOutSecrets {
            asset_bf: AssetBlindingFactor::zero(),
            value_bf: ValueBlindingFactor::zero(),
            value: fee_utxo_tx_out.value.explicit().unwrap(),
            asset: lbtc_asset,
        };

        issuance_tx.blinded_issuance = Some(0x00);
        pst.add_input(issuance_tx);

        inp_txout_sec.insert(0, issuance_secrets);
    }

    // Passing Reissuance token to new tx_out
    {
        let mut output = Output::new_explicit(
            change_recipient.script_pubkey(),
            1,
            reissuance_asset_id,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(0);
        pst.add_output(output);
    }

    //  Defining the amount of token issuance
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        issue_amount,
        asset_id,
        None,
    ));

    // Change
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_fee - fee_amount,
        lbtc_asset,
        None,
    ));

    // Fee
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        std::slice::from_ref(&fee_utxo_tx_out),
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[fee_utxo_tx_out])?;
    Ok(IssueAssetResponse {
        tx,
        asset_id,
        reissuance_asset_id,
        asset_entropy: asset_entropy_to_return,
    })
}

/// Transfer an asset to another address.
///
/// # Errors
/// Returns error if UTXO fetch fails, amount exceeds balance, or transaction finalization fails.
#[expect(clippy::too_many_arguments)]
pub async fn transfer_asset(
    keypair: &Keypair,
    asset_utxo_outpoint: OutPoint,
    fee_utxo_outpoint: OutPoint,
    to_address: &Address,
    send_amount: u64,
    fee_amount: u64,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let asset_utxo_tx_out = fetch_utxo(asset_utxo_outpoint).await?;
    let fee_utxo_tx_out = fetch_utxo(fee_utxo_outpoint).await?;

    let total_input_asset = obtain_utxo_value(&asset_utxo_tx_out)?;
    if send_amount > total_input_asset {
        return Err(anyhow!("send amount exceeds asset input value"));
    }

    let total_input_fee = obtain_utxo_value(&fee_utxo_tx_out)?;
    if fee_amount > total_input_fee {
        return Err(anyhow!(
            "fee exceeds fee input value, fee_input: {fee_amount}, total_input_fee: {total_input_fee}"
        ));
    }

    let Asset::Explicit(explicit_asset_id) = asset_utxo_tx_out.asset else {
        return Err(anyhow!("asset utxo must be explicit (unblinded) asset"));
    };

    // Ensure the fee input is LBTC
    match fee_utxo_tx_out.asset {
        Asset::Explicit(id) if id == LIQUID_TESTNET_BITCOIN_ASSET => {}
        _ => return Err(anyhow!("fee utxo must be LBTC")),
    }

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.add_input(Input::from_prevout(asset_utxo_outpoint));
    pst.add_input(Input::from_prevout(fee_utxo_outpoint));

    // Asset payment output
    pst.add_output(Output::new_explicit(
        to_address.script_pubkey(),
        send_amount,
        explicit_asset_id,
        None,
    ));

    // Asset change output
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_asset - send_amount,
        explicit_asset_id,
        None,
    ));

    // LBTC change output
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_fee - fee_amount,
        lbtc_asset,
        None,
    ));

    // Fee output
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

    let tx = pst.extract_tx()?;

    let utxos = vec![asset_utxo_tx_out, fee_utxo_tx_out];
    let tx = finalize_p2pk_transaction(tx, &utxos, keypair, 0, address_params, genesis_block_hash)?;
    let tx = finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, genesis_block_hash)?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(tx)
}

/// Split a native UTXO into three outputs of equal amount plus change.
///
/// # Errors
/// Returns error if UTXO fetch fails or transaction finalization fails.
#[expect(clippy::too_many_arguments)]
pub async fn split_native_three(
    keypair: &Keypair,
    utxo_outpoint: OutPoint,
    recipient_address: &Address,
    amount: u64,
    fee_amount: u64,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let utxo_tx_out = fetch_utxo(utxo_outpoint).await?;
    let total_input_amount = obtain_utxo_value(&utxo_tx_out)?;

    let first_amount = amount;
    let second_amount = first_amount;
    let third_amount = total_input_amount - first_amount - second_amount - fee_amount;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.add_input(Input::from_prevout(utxo_outpoint));

    // First amount
    pst.add_output(Output::new_explicit(
        recipient_address.script_pubkey(),
        first_amount,
        lbtc_asset,
        None,
    ));

    // Second amount
    pst.add_output(Output::new_explicit(
        recipient_address.script_pubkey(),
        second_amount,
        lbtc_asset,
        None,
    ));

    // Change
    pst.add_output(Output::new_explicit(
        recipient_address.script_pubkey(),
        third_amount,
        lbtc_asset,
        None,
    ));

    // Fee
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        std::slice::from_ref(&utxo_tx_out),
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_tx_out])?;
    Ok(tx)
}

/// Split a native UTXO into two outputs: specified amount and change.
///
/// # Errors
/// Returns error if UTXO fetch fails or transaction finalization fails.
#[expect(clippy::too_many_arguments)]
pub async fn split_native(
    keypair: &Keypair,
    utxo_outpoint: OutPoint,
    recipient_address: &Address,
    amount: u64,
    fee_amount: u64,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let utxo_tx_out = fetch_utxo(utxo_outpoint).await?;
    let utxo_total_input_amount = obtain_utxo_value(&utxo_tx_out)?;

    let first_amount = amount;
    let second_amount = utxo_total_input_amount - first_amount - fee_amount;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.add_input(Input::from_prevout(utxo_outpoint));

    // Amount to split
    pst.add_output(Output::new_explicit(
        recipient_address.script_pubkey(),
        first_amount,
        lbtc_asset,
        None,
    ));

    // Change
    pst.add_output(Output::new_explicit(
        recipient_address.script_pubkey(),
        second_amount,
        lbtc_asset,
        None,
    ));

    // Fee
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        std::slice::from_ref(&utxo_tx_out),
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_tx_out])?;
    Ok(tx)
}

/// Split a native UTXO into any number of outputs + change
///
/// # Errors
/// Returns error if UTXO fetch fails or transaction finalization fails.
#[instrument(skip_all, level = "debug", err)]
pub async fn split_native_any(
    keypair: Keypair,
    fee_utxo: OutPoint,
    parts_to_split: u64,
    mut fee_amount: u64,
    address_params: &'static AddressParams,
    change_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let (utxo_tx_out, utxo_outpoint) = (fetch_utxo(fee_utxo).await?, fee_utxo);

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;
    let total_input_utxo_value: u64 = obtain_utxo_value(&utxo_tx_out)?;

    let mut pst = PartiallySignedTransaction::new_v2();

    let issuance_tx = Input::from_prevout(utxo_outpoint);
    pst.add_input(issuance_tx);

    let split_amount = (total_input_utxo_value - fee_amount) / parts_to_split;
    tracing::debug!("Splitting utxo with amount: {total_input_utxo_value} on {split_amount}");
    fee_amount += total_input_utxo_value - fee_amount - split_amount * parts_to_split;

    for _ in 0..parts_to_split {
        let output = Output::new_explicit(
            change_recipient.script_pubkey(),
            split_amount,
            change_asset,
            None,
        );
        pst.add_output(output);
    }

    // Add fee
    let output = Output::new_explicit(Script::new(), fee_amount, change_asset, None);
    pst.add_output(output);

    let mut tx = pst.extract_tx()?;
    tracing::debug!("Formed for sending tx_id: {}", tx.txid().to_hex());

    let utxos = [utxo_tx_out];

    tx = finalize_p2pk_transaction(
        tx.clone(),
        &utxos,
        &keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    tracing::info!("Successfully formed tx_id: {}", tx.txid().to_hex());
    Ok(tx)
}

/// Transfer native asset (LBTC) to another address.
///
/// # Errors
/// Returns error if amount+fee exceeds balance or transaction finalization fails.
#[expect(clippy::too_many_arguments)]
pub async fn transfer_native(
    keypair: &Keypair,
    utxo_outpoint: OutPoint,
    to_address: &Address,
    amount_to_send: u64,
    fee_amount: u64,
    address_params: &'static AddressParams,
    lbtc_asset: AssetId,
    genesis_block_hash: elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let utxo_tx_out = fetch_utxo(utxo_outpoint).await?;
    let utxo_total_amount = obtain_utxo_value(&utxo_tx_out)?;

    if amount_to_send + fee_amount > utxo_total_amount {
        return Err(anyhow!("amount + fee exceeds input value"));
    }

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.add_input(Input::from_prevout(utxo_outpoint));

    // Amount to send
    pst.add_output(Output::new_explicit(
        to_address.script_pubkey(),
        amount_to_send,
        lbtc_asset,
        None,
    ));

    // Change
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        utxo_total_amount - amount_to_send - fee_amount,
        lbtc_asset,
        None,
    ));

    // Fee
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        std::slice::from_ref(&utxo_tx_out),
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_tx_out])?;
    Ok(tx)
}
