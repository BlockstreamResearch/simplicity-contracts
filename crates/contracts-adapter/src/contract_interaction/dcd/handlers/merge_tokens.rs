use contracts::{
    DCDArguments, DcdBranch, MergeBranch, TokenBranch, finalize_dcd_transaction_on_liquid_testnet,
    get_dcd_program,
};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{AddressParams, AssetId, LockTime, OutPoint, Script, Transaction};
use simplicityhl::simplicity;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl_core::{TaprootPubkeyGen, fetch_utxo, finalize_p2pk_transaction};

#[allow(clippy::too_many_arguments)]
pub fn handle(
    keypair: &secp256k1::Keypair,
    token_utxos: &[OutPoint],
    fee_utxo: OutPoint,
    fee_amount: u64,
    merge_branch: MergeBranch,
    dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
    dcd_arguments: &DCDArguments,
    address_params: &'static AddressParams,
    change_asset: AssetId,
    genesis_block_hash: simplicity::elements::BlockHash,
) -> anyhow::Result<Transaction> {
    // Fetch all token UTXOs
    let mut token_txouts = vec![];
    for utxo in token_utxos {
        token_txouts.push(fetch_utxo(*utxo)?);
    }

    // Fetch fee UTXO
    let fee_txout = fetch_utxo(fee_utxo)?;

    // Get token asset ID from first UTXO
    let token_asset_id = token_txouts[0]
        .asset
        .explicit()
        .ok_or_else(|| anyhow::anyhow!("Expected explicit asset for token"))?;

    // Calculate total token amount
    let mut total_token_amount = 0u64;
    for txout in &token_txouts {
        total_token_amount += txout
            .value
            .explicit()
            .ok_or_else(|| anyhow::anyhow!("Expected explicit value for token"))?;
    }

    let total_fee_amount = fee_txout
        .value
        .explicit()
        .ok_or_else(|| anyhow::anyhow!("Expected explicit value for fee"))?;

    // Build PST
    let mut pst = PartiallySignedTransaction::from_tx(Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    });

    // Add token inputs
    for (i, utxo) in token_utxos.iter().enumerate() {
        let mut input = Input::from_prevout(*utxo);
        input.witness_utxo = Some(token_txouts[i].clone());
        pst.add_input(input);
    }

    // Add fee input
    let mut fee_input = Input::from_prevout(fee_utxo);
    fee_input.witness_utxo = Some(fee_txout.clone());
    pst.add_input(fee_input);

    // Get DCD address from arguments
    let dcd_program = get_dcd_program(dcd_arguments)?;
    let dcd_pubkey = dcd_taproot_pubkey_gen.pubkey.to_x_only_pubkey();

    let dcd_address =
        contracts::get_dcd_address(&dcd_pubkey, dcd_arguments, &AddressParams::LIQUID_TESTNET)?;

    // Output 1: Merged tokens back to covenant
    pst.add_output(Output::new_explicit(
        dcd_address.script_pubkey(),
        total_token_amount,
        token_asset_id,
        None,
    ));

    // Output 2: Change
    let change_address = simplicityhl_core::get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    pst.add_output(Output::new_explicit(
        change_address.script_pubkey(),
        total_fee_amount - fee_amount,
        change_asset,
        None,
    ));

    // Output 3: Fee
    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        change_asset,
        None,
    ));

    let mut tx = pst.extract_tx()?;

    // Collect all UTXOs for finalization
    let mut all_utxos = token_txouts.clone();
    all_utxos.push(fee_txout);

    // Finalize each token input with DCD program
    for i in 0..token_utxos.len() {
        tx = finalize_dcd_transaction_on_liquid_testnet(
            tx,
            &dcd_program,
            &dcd_pubkey,
            &all_utxos,
            i as u32,
            TokenBranch::default(),
            DcdBranch::Merge,
            merge_branch,
        )?;
    }

    // Finalize fee input with P2PK
    tx = finalize_p2pk_transaction(
        tx,
        &all_utxos,
        keypair,
        token_utxos.len(),
        address_params,
        genesis_block_hash,
    )?;

    Ok(tx)
}
