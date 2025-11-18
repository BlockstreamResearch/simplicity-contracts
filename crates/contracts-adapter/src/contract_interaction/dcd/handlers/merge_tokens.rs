use crate::dcd::{BaseContractContext, CommonContext, DcdContractContext, MergeTokensContext};
use contracts::{
    DcdBranch, TokenBranch, finalize_dcd_transaction_on_liquid_testnet, get_dcd_program,
};
use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::elements::{AddressParams, LockTime, Script, Transaction};
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl_core::{fetch_utxo, finalize_p2pk_transaction};

pub fn handle(
    common_context: &CommonContext,
    merge_tokens_context: MergeTokensContext,
    dcd_contract_context: &DcdContractContext,
) -> anyhow::Result<Transaction> {
    let CommonContext { keypair } = common_context;
    let MergeTokensContext {
        token_utxos,
        fee_utxo,
        fee_amount,
        merge_branch,
    } = merge_tokens_context;
    let DcdContractContext {
        dcd_taproot_pubkey_gen,
        dcd_arguments,
        base_contract_context:
            BaseContractContext {
                address_params,
                lbtc_asset: change_asset,
                genesis_block_hash,
            },
    } = dcd_contract_context;

    // Fetch all token UTXOs
    let mut token_txouts = vec![];
    for utxo in token_utxos.iter() {
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
        *change_asset,
        None,
    ));

    // Output 3: Fee
    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        *change_asset,
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
        *genesis_block_hash,
    )?;

    Ok(tx)
}
