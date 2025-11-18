use crate::dcd::COLLATERAL_ASSET_ID;
use contracts::{
    build_dcd_witness, get_dcd_program, DCDArguments, DcdBranch, MergeBranch, TokenBranch,
};
use simplicity::elements::{AssetId, OutPoint, TxOut};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::Transaction;
use simplicityhl::simplicity;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{AddressParams, LockTime, Script, Sequence};
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address, TaprootPubkeyGen,
};
use std::str::FromStr;

#[allow(clippy::too_many_arguments)]
pub fn handle(
    keypair: &secp256k1::Keypair,
    asset_utxo: OutPoint,
    grantor_collateral_token_utxo: OutPoint,
    grantor_settlement_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    fee_amount: u64,
    price_at_current_block_height: u64,
    oracle_signature: String,
    grantor_amount_to_burn: u64,
    dcd_arguments: &DCDArguments,
    dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
    address_params: &'static AddressParams,
    change_asset: AssetId,
    genesis_block_hash: simplicity::elements::BlockHash,
) -> anyhow::Result<Transaction> {
    // Fetch UTXOs
    let asset_txout = fetch_utxo(asset_utxo)?; // DCD input 0
    let grantor_coll_txout = fetch_utxo(grantor_collateral_token_utxo)?; // P2PK input 1
    let grantor_settle_txout = fetch_utxo(grantor_settlement_token_utxo)?; // P2PK input 2
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 3

    anyhow::ensure!(
        dcd_taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
        "asset_utxo must be locked by DCD covenant"
    );

    let total_fee_input = fee_txout.value.explicit().unwrap();
    let available_onchain_asset = asset_txout.value.explicit().unwrap();

    //todo: add asset extracting
    let grantor_coll_asset_id = grantor_coll_txout.asset.explicit().unwrap();
    let grantor_settle_asset_id = grantor_settle_txout.asset.explicit().unwrap();
    let available_grantor_coll = grantor_coll_txout.value.explicit().unwrap();
    let available_grantor_settle = grantor_settle_txout.value.explicit().unwrap();

    anyhow::ensure!(
        grantor_amount_to_burn <= available_grantor_coll
            && grantor_amount_to_burn <= available_grantor_settle,
        "grantor burn amount exceeds available"
    );

    // Compute amount_to_get based on price branch
    let settlement_height = dcd_arguments.settlement_height;
    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.global.tx_data.fallback_locktime = Some(LockTime::from_height(settlement_height)?);

    // Inputs in order
    let mut in0 = Input::from_prevout(asset_utxo);
    in0.witness_utxo = Some(asset_txout.clone());
    in0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(in0);

    {
        let mut input = Input::from_prevout(grantor_collateral_token_utxo);
        input.witness_utxo = Some(grantor_coll_txout.clone());
        pst.add_input(input);
    }
    {
        let mut input = Input::from_prevout(grantor_settlement_token_utxo);
        input.witness_utxo = Some(grantor_settle_txout.clone());
        pst.add_input(input);
    }
    {
        let mut input = Input::from_prevout(fee_utxo);
        input.witness_utxo = Some(fee_txout.clone());
        pst.add_input(input);
    }

    // Decide branch and build outputs
    let price = price_at_current_block_height;

    // Parse oracle signature
    let oracle_sig = simplicityhl::simplicity::bitcoin::secp256k1::schnorr::Signature::from_slice(
        &hex::decode(oracle_signature)?,
    )?;

    // Maker gets ALT when price <= strike
    let tx = if price <= dcd_arguments.strike_price {
        // amount_to_get = burn * GRANTOR_PER_SETTLEMENT_ASSET
        let per_settlement_asset = dcd_arguments.ratio_args.total_asset_amount
            / dcd_arguments.ratio_args.grantor_collateral_token_amount;
        let amount_to_get = grantor_amount_to_burn.saturating_mul(per_settlement_asset);

        anyhow::ensure!(
            amount_to_get <= available_onchain_asset,
            "required settlement exceeds available"
        );

        let is_change_needed = available_onchain_asset != amount_to_get;

        if is_change_needed {
            // 0: settlement change back to covenant
            pst.add_output(Output::new_explicit(
                dcd_taproot_pubkey_gen.address.script_pubkey(),
                available_onchain_asset - amount_to_get,
                AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                None,
            ));
        }

        // Burn grantor settlement token
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_amount_to_burn,
            grantor_settle_asset_id,
            None,
        ));
        // Burn grantor collateral token
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_amount_to_burn,
            grantor_coll_asset_id,
            None,
        ));
        // settlement to user
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            amount_to_get,
            AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
            None,
        ));

        if grantor_amount_to_burn != available_grantor_coll {
            pst.add_output(Output::new_explicit(
                change_recipient.script_pubkey(),
                available_grantor_coll - grantor_amount_to_burn,
                grantor_coll_asset_id,
                None,
            ));
        }

        if grantor_amount_to_burn != available_grantor_settle {
            pst.add_output(Output::new_explicit(
                change_recipient.script_pubkey(),
                available_grantor_settle - grantor_amount_to_burn,
                grantor_settle_asset_id,
                None,
            ));
        }

        // fee change + fee
        anyhow::ensure!(fee_amount <= total_fee_input, "fee exceeds input value");
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            total_fee_input - fee_amount,
            change_asset,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, change_asset)));

        let utxos = vec![
            asset_txout,
            grantor_coll_txout,
            grantor_settle_txout,
            fee_txout,
        ];
        let dcd_program = get_dcd_program(dcd_arguments)?;
        let witness_values = build_dcd_witness(
            TokenBranch::Maker,
            DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &oracle_sig,
                index_to_spend: 0,
                amount_to_burn: grantor_amount_to_burn,
                amount_to_get,
                is_change_needed,
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
            &AddressParams::LIQUID_TESTNET,
            genesis_block_hash,
        )?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, genesis_block_hash)?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 2, address_params, genesis_block_hash)?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 3, address_params, genesis_block_hash)?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    } else {
        // Maker gets LBTC (price > strike)
        let per_settlement_collateral = dcd_arguments.ratio_args.total_collateral_amount
            / dcd_arguments.ratio_args.grantor_collateral_token_amount;
        let amount_to_get = grantor_amount_to_burn.saturating_mul(per_settlement_collateral);

        anyhow::ensure!(
            amount_to_get <= available_onchain_asset,
            "required collateral exceeds available"
        );

        let is_change_needed = available_onchain_asset != amount_to_get;

        if is_change_needed {
            // 0: collateral change back to covenant
            pst.add_output(Output::new_explicit(
                dcd_taproot_pubkey_gen.address.script_pubkey(),
                available_onchain_asset - amount_to_get,
                COLLATERAL_ASSET_ID,
                None,
            ));
        }

        // Burn grantor collateral token
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_amount_to_burn,
            grantor_coll_asset_id,
            None,
        ));
        // Burn grantor settlement token
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            grantor_amount_to_burn,
            grantor_settle_asset_id,
            None,
        ));
        // collateral to user
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            amount_to_get,
            COLLATERAL_ASSET_ID,
            None,
        ));

        if grantor_amount_to_burn != available_grantor_coll {
            pst.add_output(Output::new_explicit(
                change_recipient.script_pubkey(),
                available_grantor_coll - grantor_amount_to_burn,
                grantor_coll_asset_id,
                None,
            ));
        }

        if grantor_amount_to_burn != available_grantor_settle {
            pst.add_output(Output::new_explicit(
                change_recipient.script_pubkey(),
                available_grantor_settle - grantor_amount_to_burn,
                grantor_settle_asset_id,
                None,
            ));
        }
        // fee change + fee
        anyhow::ensure!(fee_amount <= total_fee_input, "fee exceeds input value");
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            total_fee_input - fee_amount,
            change_asset,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, change_asset)));

        let utxos = vec![
            asset_txout,
            grantor_coll_txout,
            grantor_settle_txout,
            fee_txout,
        ];
        let dcd_program = get_dcd_program(dcd_arguments)?;
        let witness_values = build_dcd_witness(
            TokenBranch::Maker,
            DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &oracle_sig,
                index_to_spend: 0,
                amount_to_burn: grantor_amount_to_burn,
                amount_to_get,
                is_change_needed,
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
            &AddressParams::LIQUID_TESTNET,
            genesis_block_hash,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            keypair,
            1,
            &AddressParams::LIQUID_TESTNET,
            genesis_block_hash,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            keypair,
            2,
            &AddressParams::LIQUID_TESTNET,
            genesis_block_hash,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            keypair,
            3,
            &AddressParams::LIQUID_TESTNET,
            genesis_block_hash,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    };

    Ok(tx)
}
