use crate::dcd::COLLATERAL_ASSET_ID;
use contracts::{
    build_dcd_witness, get_dcd_program, DCDArguments, DcdBranch, MergeBranch, TokenBranch,
};
use simplicity::elements::{AssetId, OutPoint, TxOut};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::Transaction;
use simplicityhl::simplicity;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::AddressParams;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address, TaprootPubkeyGen,
};

#[allow(clippy::too_many_arguments)]
pub fn handle(
    keypair: &secp256k1::Keypair,
    filler_token_utxo: OutPoint,
    collateral_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    fee_amount: u64,
    filler_token_amount_to_return: u64,
    dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
    dcd_arguments: &DCDArguments,
    address_params: &'static AddressParams,
    change_asset: AssetId,
    genesis_block_hash: simplicity::elements::BlockHash,
) -> anyhow::Result<Transaction> {
    let collateral_tx_out = fetch_utxo(collateral_token_utxo)?; // DCD input index 0
    let filler_tx_out = fetch_utxo(filler_token_utxo)?; // P2PK input index 1
    let fee_tx_out = fetch_utxo(fee_utxo)?; // P2PK input index 2

    anyhow::ensure!(
        dcd_taproot_pubkey_gen.address.script_pubkey() == collateral_tx_out.script_pubkey,
        "collateral_utxo must be locked by DCD covenant"
    );

    let available_collateral = collateral_tx_out.value.explicit().unwrap();
    let filler_asset_id = filler_tx_out.asset.explicit().unwrap();
    let available_filler = filler_tx_out.value.explicit().unwrap();
    let total_fee_input = fee_tx_out.value.explicit().unwrap();

    anyhow::ensure!(
        filler_token_amount_to_return <= available_filler,
        "filler tokens to return exceed available"
    );

    // collateral_to_get = filler_return * FILLER_PER_PRINCIPAL_COLLATERAL
    let collateral_per_principal = dcd_arguments.ratio_args.filler_per_principal_collateral;
    let collateral_to_get = filler_token_amount_to_return.saturating_mul(collateral_per_principal);

    anyhow::ensure!(
        collateral_to_get <= available_collateral,
        "required collateral exceeds available"
    );

    let is_change_needed = available_collateral != collateral_to_get;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    let mut pst = PartiallySignedTransaction::new_v2();

    {
        let mut in0 = Input::from_prevout(collateral_token_utxo);
        in0.witness_utxo = Some(collateral_tx_out.clone());
        pst.add_input(in0);
    }
    {
        let mut in1 = Input::from_prevout(filler_token_utxo);
        in1.witness_utxo = Some(filler_tx_out.clone());
        pst.add_input(in1);
    }
    {
        let mut in2 = Input::from_prevout(fee_utxo);
        in2.witness_utxo = Some(fee_tx_out.clone());
        pst.add_input(in2);
    }

    // Outputs per SIMF indices
    if is_change_needed {
        // 0: collateral change back to covenant
        pst.add_output(Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            available_collateral - collateral_to_get,
            COLLATERAL_ASSET_ID,
            None,
        ));
    }

    // return filler to covenant
    pst.add_output(Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        filler_token_amount_to_return,
        filler_asset_id,
        None,
    ));

    // return collateral to user
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        collateral_to_get,
        COLLATERAL_ASSET_ID,
        None,
    ));

    if filler_token_amount_to_return != available_filler {
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            available_filler - filler_token_amount_to_return,
            filler_asset_id,
            None,
        ));
    }

    // fee change
    anyhow::ensure!(fee_amount <= total_fee_input, "fee exceeds input value");
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_fee_input - fee_amount,
        change_asset,
        None,
    ));
    // fee
    pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, change_asset)));

    // Finalize
    let utxos = vec![collateral_tx_out, filler_tx_out, fee_tx_out];
    let dcd_program = get_dcd_program(dcd_arguments)?;

    // Attach DCD witness to input 0 only
    let witness_values = build_dcd_witness(
        TokenBranch::default(),
        DcdBranch::TakerEarlyTermination {
            is_change_needed,
            index_to_spend: 0,
            filler_token_amount_to_return,
            collateral_amount_to_get: collateral_to_get,
        },
        MergeBranch::default(),
    );

    let tx = finalize_transaction(
        pst.extract_tx()?,
        &dcd_program,
        &dcd_taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values,
        address_params,
        genesis_block_hash,
    )?;

    // Sign P2PK inputs 1 and 2
    let tx = finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, genesis_block_hash)?;
    let tx = finalize_p2pk_transaction(tx, &utxos, keypair, 2, address_params, genesis_block_hash)?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    Ok(tx)
}
