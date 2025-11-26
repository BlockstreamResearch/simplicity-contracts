use crate::dcd::{
    BaseContractContext, COLLATERAL_ASSET_ID, CommonContext, DcdContractContext,
    TakerSettlementContext,
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
};
use std::str::FromStr;

#[expect(clippy::too_many_lines)]
pub fn handle(
    common_context: &CommonContext,
    taker_settlement_context: TakerSettlementContext,
    dcd_contract_context: &DcdContractContext,
) -> anyhow::Result<Transaction> {
    let CommonContext { keypair } = common_context;
    let TakerSettlementContext {
        asset_utxo,
        filler_token_utxo,
        fee_utxo,
        fee_amount,
        price_at_current_block_height,
        filler_amount_to_burn,
        oracle_signature,
    } = taker_settlement_context;
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
    let filler_txout = fetch_utxo(filler_token_utxo)?; // P2PK input 1
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 2

    anyhow::ensure!(
        dcd_taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
        "asset_utxo must be locked by DCD covenant"
    );

    let total_fee_input = fee_txout.value.explicit().unwrap();
    let available_onchain_asset = asset_txout.value.explicit().unwrap();
    let filler_asset_id = filler_txout.asset.explicit().unwrap();
    let available_filler = filler_txout.value.explicit().unwrap();

    anyhow::ensure!(
        filler_amount_to_burn <= available_filler,
        "filler burn amount exceeds available"
    );

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    let mut pst = PartiallySignedTransaction::new_v2();
    pst.global.tx_data.fallback_locktime =
        Some(LockTime::from_height(dcd_arguments.settlement_height)?);

    // Inputs
    {
        let mut input = Input::from_prevout(asset_utxo);
        input.witness_utxo = Some(asset_txout.clone());
        input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
        pst.add_input(input);
    }
    {
        let mut input = Input::from_prevout(filler_token_utxo);
        input.witness_utxo = Some(filler_txout.clone());
        pst.add_input(input);
    }
    {
        let mut input = Input::from_prevout(fee_utxo);
        input.witness_utxo = Some(fee_txout.clone());
        pst.add_input(input);
    }

    let price = price_at_current_block_height;
    let oracle_sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(oracle_signature)?)?;

    let tx = if price <= dcd_arguments.strike_price {
        // Taker receives LBTC: amount_to_get = burn * FILLER_PER_SETTLEMENT_COLLATERAL
        let per_settlement_collateral = dcd_arguments.ratio_args.total_collateral_amount
            / dcd_arguments.ratio_args.filler_token_amount;
        let amount_to_get = filler_amount_to_burn.saturating_mul(per_settlement_collateral);

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

        // Burn filler token
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            filler_amount_to_burn,
            filler_asset_id,
            None,
        ));

        // collateral to user
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            amount_to_get,
            COLLATERAL_ASSET_ID,
            None,
        ));

        if filler_amount_to_burn != available_filler {
            pst.add_output(Output::new_explicit(
                change_recipient.script_pubkey(),
                available_filler - filler_amount_to_burn,
                filler_asset_id,
                None,
            ));
        }

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

        let utxos = vec![asset_txout, filler_txout, fee_txout];
        let dcd_program = get_dcd_program(dcd_arguments)?;
        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            &DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &oracle_sig,
                index_to_spend: 0,
                amount_to_burn: filler_amount_to_burn,
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
            address_params,
            *genesis_block_hash,
        )?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 1, address_params, *genesis_block_hash)?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, keypair, 2, address_params, *genesis_block_hash)?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    } else {
        // Taker receives SETTLEMENT: amount_to_get = burn * FILLER_PER_SETTLEMENT_ASSET
        let per_settlement_asset = dcd_arguments.ratio_args.total_asset_amount
            / dcd_arguments.ratio_args.filler_token_amount;
        let amount_to_get = filler_amount_to_burn.saturating_mul(per_settlement_asset);

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

        // Burn filler token
        pst.add_output(Output::new_explicit(
            Script::new_op_return("burn".as_bytes()),
            filler_amount_to_burn,
            filler_asset_id,
            None,
        ));

        // settlement to user
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            amount_to_get,
            AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
            None,
        ));

        if filler_amount_to_burn != available_filler {
            pst.add_output(Output::new_explicit(
                change_recipient.script_pubkey(),
                available_filler - filler_amount_to_burn,
                filler_asset_id,
                None,
            ));
        }

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

        let utxos = vec![asset_txout, filler_txout, fee_txout];
        let dcd_program = get_dcd_program(dcd_arguments)?;
        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            &DcdBranch::Settlement {
                price_at_current_block_height: price,
                oracle_sig: &oracle_sig,
                index_to_spend: 0,
                amount_to_burn: filler_amount_to_burn,
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

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    };
    Ok(tx)
}
