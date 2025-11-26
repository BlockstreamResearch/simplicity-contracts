use crate::dcd::{
    BaseContractContext, COLLATERAL_ASSET_ID, CommonContext, DcdContractContext,
    TakerFundingContext,
};
use anyhow::anyhow;
use contracts::{DcdBranch, MergeBranch, TokenBranch, build_dcd_witness, get_dcd_program};
use simplicity::elements::TxOut;
use simplicityhl::elements::Transaction;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::simplicity;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::elements::AddressParams;
use simplicityhl::simplicity::elements::LockTime;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address,
};

#[expect(clippy::too_many_lines)]
pub fn handle(
    common_context: &CommonContext,
    taker_funding_context: TakerFundingContext,
    dcd_contract_context: &DcdContractContext,
) -> anyhow::Result<Transaction> {
    let CommonContext { keypair } = common_context;
    let TakerFundingContext {
        filler_token_utxo,
        collateral_token_utxo,
        fee_amount,
        collateral_amount_to_deposit,
    } = taker_funding_context;
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

    let filler_tx_out = fetch_utxo(filler_token_utxo)?;
    let collateral_tx_out = fetch_utxo(collateral_token_utxo)?;

    assert_eq!(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        filler_tx_out.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the filler token utxo script pubkey"
    );

    let filler_asset_id = filler_tx_out
        .asset
        .explicit()
        .ok_or_else(|| anyhow!("No AssetId in filler utxo, {filler_token_utxo}"))?;
    let total_collateral = collateral_tx_out.value.explicit().unwrap();
    let total_filler = filler_tx_out.value.explicit().unwrap();

    anyhow::ensure!(
        collateral_amount_to_deposit <= total_collateral,
        "collateral amount to deposit exceeds input value"
    );

    let total_input_fee = total_collateral - collateral_amount_to_deposit;

    anyhow::ensure!(
        fee_amount <= total_input_fee,
        "fee amount exceeds input value"
    );

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.global.tx_data.fallback_locktime =
        Some(LockTime::from_time(dcd_arguments.taker_funding_start_time)?);

    pst.add_input(Input::from_prevout(filler_token_utxo));
    pst.add_input(Input::from_prevout(collateral_token_utxo));

    let filler_to_get =
        collateral_amount_to_deposit / dcd_arguments.ratio_args.filler_per_principal_collateral;

    let is_filler_change_needed = total_filler != filler_to_get;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    if is_filler_change_needed {
        pst.add_output(Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            total_filler - filler_to_get,
            filler_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        collateral_amount_to_deposit,
        COLLATERAL_ASSET_ID,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        filler_to_get,
        filler_asset_id,
        None,
    ));

    // LBTC change
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_fee - fee_amount,
        *change_asset,
        None,
    ));

    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        *change_asset,
    )));

    let utxos = vec![filler_tx_out, collateral_tx_out];

    let witness_values = build_dcd_witness(
        TokenBranch::default(),
        &DcdBranch::TakerFunding {
            collateral_amount_to_deposit,
            filler_token_amount_to_get: filler_to_get,
            is_change_needed: is_filler_change_needed,
        },
        MergeBranch::default(),
    );

    let dcd_program = get_dcd_program(dcd_arguments)?;

    let tx = finalize_transaction(
        pst.extract_tx()?,
        &dcd_program,
        &dcd_taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values,
        address_params,
        *genesis_block_hash,
    )?;

    let tx =
        finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, *genesis_block_hash)?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    Ok(tx)
}
