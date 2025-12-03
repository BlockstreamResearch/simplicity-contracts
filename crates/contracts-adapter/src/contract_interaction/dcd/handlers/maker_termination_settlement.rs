use contracts::{DcdBranch, MergeBranch, TokenBranch, build_dcd_witness, get_dcd_program};
use simplicity::elements::{AssetId, TxOut};
use simplicityhl::elements::Transaction;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::simplicity;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address,
};
use std::str::FromStr;

use crate::dcd::{
    BaseContractContext, CommonContext, DcdContractContext, MakerTerminationSettlementContext,
};
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{AddressParams, Script};

#[expect(clippy::too_many_lines)]
pub async fn handle(
    common_context: &CommonContext,
    maker_termination_context: MakerTerminationSettlementContext,
    dcd_contract_context: &DcdContractContext,
) -> anyhow::Result<Transaction> {
    let CommonContext { keypair } = common_context;
    let MakerTerminationSettlementContext {
        settlement_asset_utxo,
        grantor_settlement_token_utxo,
        fee_utxo,
        fee_amount,
        grantor_settlement_amount_to_burn,
    } = maker_termination_context;
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

    // Fetch UTXOs
    let settlement_txout = fetch_utxo(settlement_asset_utxo).await?; // DCD input 0
    let grantor_settle_txout = fetch_utxo(grantor_settlement_token_utxo).await?; // P2PK input 1
    let fee_txout = fetch_utxo(fee_utxo).await?; // P2PK input 2

    anyhow::ensure!(
        dcd_taproot_pubkey_gen.address.script_pubkey() == settlement_txout.script_pubkey,
        "settlement_asset_utxo must be locked by DCD covenant"
    );

    let available_settlement = settlement_txout.value.explicit().unwrap();
    let grantor_settle_asset_id = grantor_settle_txout.asset.explicit().unwrap();
    let available_grantor_settle = grantor_settle_txout.value.explicit().unwrap();
    let total_fee_input = fee_txout.value.explicit().unwrap();

    anyhow::ensure!(
        grantor_settlement_amount_to_burn <= available_grantor_settle,
        "grantor settlement burn amount exceeds available, has to be at least: {grantor_settlement_amount_to_burn}, got: {available_grantor_settle}"
    );

    // amount_to_get = burn * GRANTOR_SETTLEMENT_PER_DEPOSITED_ASSET
    let grantor_settle_per_deposited = dcd_arguments.ratio_args.total_asset_amount
        / dcd_arguments.ratio_args.grantor_settlement_token_amount;
    let amount_to_get =
        grantor_settlement_amount_to_burn.saturating_mul(grantor_settle_per_deposited);

    anyhow::ensure!(
        amount_to_get <= available_settlement,
        "required settlement exceeds available, has to be at least: {amount_to_get}, got: {available_settlement}"
    );

    let is_change_needed = available_settlement != amount_to_get;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    // Build PST
    let mut pst = PartiallySignedTransaction::new_v2();

    let mut in0 = Input::from_prevout(settlement_asset_utxo);
    in0.witness_utxo = Some(settlement_txout.clone());
    pst.add_input(in0);

    let mut in1 = Input::from_prevout(grantor_settlement_token_utxo);
    in1.witness_utxo = Some(grantor_settle_txout.clone());
    pst.add_input(in1);

    let mut in2 = Input::from_prevout(fee_utxo);
    in2.witness_utxo = Some(fee_txout.clone());
    pst.add_input(in2);

    if is_change_needed {
        // 0: settlement change back to covenant
        pst.add_output(Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            available_settlement - amount_to_get,
            AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
            None,
        ));
    }

    // 1: burn grantor settlement token (OP_RETURN)
    pst.add_output(Output::new_explicit(
        Script::new_op_return("burn".as_bytes()),
        grantor_settlement_amount_to_burn,
        grantor_settle_asset_id,
        None,
    ));

    // 2: return settlement to user
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        amount_to_get,
        AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
        None,
    ));

    if grantor_settlement_amount_to_burn != available_grantor_settle {
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            available_grantor_settle - grantor_settlement_amount_to_burn,
            grantor_settle_asset_id,
            None,
        ));
    }

    // fee change + fee
    anyhow::ensure!(
        fee_amount <= total_fee_input,
        "fee exceeds input value, has to be at least: {fee_amount}, got: {total_fee_input}"
    );
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_fee_input - fee_amount,
        *change_asset,
        None,
    ));
    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        *change_asset,
    )));

    // Finalize
    let utxos = vec![settlement_txout, grantor_settle_txout, fee_txout];
    let dcd_program = get_dcd_program(dcd_arguments)?;

    let witness_values = build_dcd_witness(
        TokenBranch::Taker,
        &DcdBranch::MakerTermination {
            is_change_needed,
            index_to_spend: 0,
            grantor_token_amount_to_burn: grantor_settlement_amount_to_burn,
            amount_to_get,
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
        *genesis_block_hash,
    )?;
    let tx =
        finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, *genesis_block_hash)?;
    let tx =
        finalize_p2pk_transaction(tx, &utxos, keypair, 2, address_params, *genesis_block_hash)?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    Ok(tx)
}
