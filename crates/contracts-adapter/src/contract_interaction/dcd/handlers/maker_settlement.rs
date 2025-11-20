use crate::dcd::{
    BaseContractContext, COLLATERAL_ASSET_ID, CommonContext, DcdContractContext,
    MakerSettlementContext,
};
use contracts::{DcdBranch, MergeBranch, TokenBranch, build_dcd_witness, get_dcd_program};
use simplicity::elements::{AssetId, TxOut};
use simplicityhl::elements::Transaction;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::simplicity;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{AddressParams, LockTime, Script, Sequence};
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address,
    obtain_utxo_value,
};
use std::str::FromStr;

pub fn handle(
    common_context: &CommonContext,
    maker_settlement_context: MakerSettlementContext,
    dcd_contract_context: &DcdContractContext,
) -> anyhow::Result<Transaction> {
    let CommonContext { keypair } = common_context;
    let MakerSettlementContext {
        asset_utxo,
        grantor_collateral_token_utxo,
        grantor_settlement_token_utxo,
        fee_utxo,
        fee_amount,
        price_at_current_block_height,
        oracle_signature,
        grantor_amount_to_burn,
    } = maker_settlement_context;
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
    let asset_txout = fetch_utxo(asset_utxo)?; // DCD input 0
    let grantor_coll_txout = fetch_utxo(grantor_collateral_token_utxo)?; // P2PK input 1
    let grantor_settle_txout = fetch_utxo(grantor_settlement_token_utxo)?; // P2PK input 2
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 3

    anyhow::ensure!(
        dcd_taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
        "asset_utxo must be locked by DCD covenant"
    );

    let total_fee_input = obtain_utxo_value(&fee_txout)?;
    let available_onchain_asset = obtain_utxo_value(&asset_txout)?;

    let grantor_coll_asset_id = grantor_coll_txout.asset.explicit().unwrap();
    let grantor_settle_asset_id = grantor_settle_txout.asset.explicit().unwrap();
    let available_grantor_coll = obtain_utxo_value(&grantor_coll_txout)?;
    let available_grantor_settle = obtain_utxo_value(&grantor_settle_txout)?;

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
    let oracle_sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(oracle_signature)?)?;

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
            *change_asset,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(
            fee_amount,
            *change_asset,
        )));

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
            *genesis_block_hash,
        )?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, *genesis_block_hash)?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 2, address_params, *genesis_block_hash)?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 3, address_params, *genesis_block_hash)?;

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
            *change_asset,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(
            fee_amount,
            *change_asset,
        )));

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
            *genesis_block_hash,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            keypair,
            1,
            &AddressParams::LIQUID_TESTNET,
            *genesis_block_hash,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            keypair,
            2,
            &AddressParams::LIQUID_TESTNET,
            *genesis_block_hash,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            keypair,
            3,
            &AddressParams::LIQUID_TESTNET,
            *genesis_block_hash,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    };

    Ok(tx)
}
