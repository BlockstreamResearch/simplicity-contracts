use simplicity::elements::TxOut;
use simplicityhl::elements::Transaction;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::simplicity;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address,
};

use crate::dcd::{
    BaseContractContext, COLLATERAL_ASSET_ID, CommonContext, DcdContractContext,
    MakerTerminationCollateralContext,
};
use contracts::{DcdBranch, MergeBranch, TokenBranch, build_dcd_witness, get_dcd_program};
use simplicityhl::simplicity::elements::Script;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};

#[expect(clippy::too_many_lines)]
pub fn handle(
    common_context: &CommonContext,
    maker_termination_context: MakerTerminationCollateralContext,
    dcd_contract_context: &DcdContractContext,
) -> anyhow::Result<Transaction> {
    let CommonContext { keypair } = common_context;
    let MakerTerminationCollateralContext {
        collateral_token_utxo,
        grantor_collateral_token_utxo,
        fee_utxo,
        fee_amount,
        grantor_collateral_amount_to_burn,
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
    let collateral_txout = fetch_utxo(collateral_token_utxo)?; // DCD input 0
    let grantor_coll_txout = fetch_utxo(grantor_collateral_token_utxo)?; // P2PK input 1
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 2

    anyhow::ensure!(
        dcd_taproot_pubkey_gen.address.script_pubkey() == collateral_txout.script_pubkey,
        "collateral_utxo must be locked by DCD covenant"
    );

    let available_collateral = collateral_txout.value.explicit().unwrap();
    let grantor_coll_asset_id = grantor_coll_txout.asset.explicit().unwrap();
    let available_grantor_coll = grantor_coll_txout.value.explicit().unwrap();
    let total_fee_input = fee_txout.value.explicit().unwrap();

    anyhow::ensure!(
        grantor_collateral_amount_to_burn <= available_grantor_coll,
        "grantor collateral burn amount exceeds available"
    );

    // amount_to_get = burn * GRANTOR_COLLATERAL_PER_DEPOSITED_COLLATERAL
    let grantor_coll_per_deposited = dcd_arguments.ratio_args.interest_collateral_amount
        / dcd_arguments.ratio_args.grantor_collateral_token_amount;
    let amount_to_get =
        grantor_collateral_amount_to_burn.saturating_mul(grantor_coll_per_deposited);

    anyhow::ensure!(
        amount_to_get <= available_collateral,
        "required collateral exceeds available"
    );

    let is_change_needed = available_collateral != amount_to_get;

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    // Build PST
    let mut pst = PartiallySignedTransaction::new_v2();

    {
        let mut input = Input::from_prevout(collateral_token_utxo);
        input.witness_utxo = Some(collateral_txout.clone());
        pst.add_input(input);
    }
    {
        let mut input = Input::from_prevout(grantor_collateral_token_utxo);
        input.witness_utxo = Some(grantor_coll_txout.clone());
        pst.add_input(input);
    }
    {
        let mut input = Input::from_prevout(fee_utxo);
        input.witness_utxo = Some(fee_txout.clone());
        pst.add_input(input);
    }

    if is_change_needed {
        // 0: collateral change back to covenant
        pst.add_output(Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            available_collateral - amount_to_get,
            COLLATERAL_ASSET_ID,
            None,
        ));
    }

    // 1: burn grantor collateral token (OP_RETURN)
    pst.add_output(Output::new_explicit(
        Script::new_op_return("burn".as_bytes()),
        grantor_collateral_amount_to_burn,
        grantor_coll_asset_id,
        None,
    ));

    // 2: return collateral to user
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        amount_to_get,
        COLLATERAL_ASSET_ID,
        None,
    ));

    if grantor_collateral_amount_to_burn != available_grantor_coll {
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            available_grantor_coll - grantor_collateral_amount_to_burn,
            grantor_coll_asset_id,
            None,
        ));
    }

    // fee change + fee
    anyhow::ensure!(fee_amount <= total_fee_input, "fee exceeds input value");
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
    let utxos = vec![collateral_txout, grantor_coll_txout, fee_txout];
    let dcd_program = get_dcd_program(dcd_arguments)?;

    let witness_values = build_dcd_witness(
        TokenBranch::Maker,
        &DcdBranch::MakerTermination {
            is_change_needed,
            index_to_spend: 0,
            grantor_token_amount_to_burn: grantor_collateral_amount_to_burn,
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
