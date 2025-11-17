use std::str::FromStr;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::hashes::sha256;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{AssetId, OutPoint, Sequence, TxOut, TxOutSecrets};
use simplicityhl::simplicity::ToXOnlyPubkey;

use simplicityhl_core::{
    AssetEntropyBytes, Encodable, LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS,
    TaprootPubkeyGen, fetch_utxo, finalize_p2pk_transaction, finalize_transaction,
    get_p2pk_address, get_random_seed,
};

use contracts::{
    DCDArguments, DCDRatioArguments, build_dcd_witness, finalize_dcd_transaction_on_liquid_testnet,
    get_dcd_program,
};
use contracts::{DcdBranch, MergeBranch, TokenBranch};
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{AddressParams, LockTime, Script, Transaction};

pub fn maker_settlement(
    keypair: &Keypair,
    asset_utxo: OutPoint,
    grantor_collateral_token_utxo: OutPoint,
    grantor_settlement_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    price_at_current_block_height: u64,
    oracle_signature: &str,
    grantor_amount_to_burn: u64,
    fee_amount: u64,
    dcd_arguments: &DCDArguments,
    taproot_pubkey_gen: &TaprootPubkeyGen,
) -> anyhow::Result<Transaction> {
    // Fetch UTXOs
    let asset_txout = fetch_utxo(asset_utxo)?; // DCD input 0
    let grantor_coll_txout = fetch_utxo(grantor_collateral_token_utxo)?; // P2PK input 1
    let grantor_settle_txout = fetch_utxo(grantor_settlement_token_utxo)?; // P2PK input 2
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 3

    anyhow::ensure!(
        taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
        "asset_utxo must be locked by DCD covenant"
    );

    let total_fee_input = fee_txout.value.explicit().unwrap();
    let available_onchain_asset = asset_txout.value.explicit().unwrap();

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

    let mut in1 = Input::from_prevout(grantor_collateral_token_utxo);
    in1.witness_utxo = Some(grantor_coll_txout.clone());
    pst.add_input(in1);

    let mut in2 = Input::from_prevout(grantor_settlement_token_utxo);
    in2.witness_utxo = Some(grantor_settle_txout.clone());
    pst.add_input(in2);

    let mut in3 = Input::from_prevout(fee_utxo);
    in3.witness_utxo = Some(fee_txout.clone());
    pst.add_input(in3);

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
                taproot_pubkey_gen.address.script_pubkey(),
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
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(
            fee_amount,
            LIQUID_TESTNET_BITCOIN_ASSET,
        )));

        let utxos = vec![
            asset_txout,
            grantor_coll_txout,
            grantor_settle_txout,
            fee_txout,
        ];
        let dcd_program = get_dcd_program(&dcd_arguments)?;
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
            &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
            &utxos,
            0,
            witness_values,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            1,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            2,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            3,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;

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
                taproot_pubkey_gen.address.script_pubkey(),
                available_onchain_asset - amount_to_get,
                LIQUID_TESTNET_BITCOIN_ASSET,
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
            LIQUID_TESTNET_BITCOIN_ASSET,
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
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(
            fee_amount,
            LIQUID_TESTNET_BITCOIN_ASSET,
        )));

        let utxos = vec![
            asset_txout,
            grantor_coll_txout,
            grantor_settle_txout,
            fee_txout,
        ];
        let dcd_program = get_dcd_program(&dcd_arguments)?;
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
            &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
            &utxos,
            0,
            witness_values,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            1,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            2,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            3,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    };
    Ok(tx)
}

pub fn taker_settlement(
    keypair: &Keypair,
    asset_utxo: OutPoint,
    filler_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    price_at_current_block_height: u64,
    oracle_signature: &str,
    filler_amount_to_burn: u64,
    fee_amount: u64,
    dcd_arguments: &DCDArguments,
    taproot_pubkey_gen: &TaprootPubkeyGen,
) -> anyhow::Result<Transaction> {
    // Fetch UTXOs
    let asset_txout = fetch_utxo(asset_utxo)?; // DCD input 0
    let filler_txout = fetch_utxo(filler_token_utxo)?; // P2PK input 1
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 2

    anyhow::ensure!(
        taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
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
    let mut in0 = Input::from_prevout(asset_utxo);
    in0.witness_utxo = Some(asset_txout.clone());
    in0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    pst.add_input(in0);

    let mut in1 = Input::from_prevout(filler_token_utxo);
    in1.witness_utxo = Some(filler_txout.clone());
    pst.add_input(in1);

    let mut in2 = Input::from_prevout(fee_utxo);
    in2.witness_utxo = Some(fee_txout.clone());
    pst.add_input(in2);

    let price = price_at_current_block_height;
    let oracle_sig = simplicityhl::simplicity::bitcoin::secp256k1::schnorr::Signature::from_slice(
        &hex::decode(oracle_signature)?,
    )?;

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
                taproot_pubkey_gen.address.script_pubkey(),
                available_onchain_asset - amount_to_get,
                LIQUID_TESTNET_BITCOIN_ASSET,
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
            LIQUID_TESTNET_BITCOIN_ASSET,
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
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(
            fee_amount,
            LIQUID_TESTNET_BITCOIN_ASSET,
        )));

        let utxos = vec![asset_txout, filler_txout, fee_txout];
        let dcd_program = get_dcd_program(&dcd_arguments)?;
        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            DcdBranch::Settlement {
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
            &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
            &utxos,
            0,
            witness_values,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            1,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            2,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;

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
                taproot_pubkey_gen.address.script_pubkey(),
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
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));
        pst.add_output(Output::from_txout(TxOut::new_fee(
            fee_amount,
            LIQUID_TESTNET_BITCOIN_ASSET,
        )));

        let utxos = vec![asset_txout, filler_txout, fee_txout];
        let dcd_program = get_dcd_program(&dcd_arguments)?;
        let witness_values = build_dcd_witness(
            TokenBranch::Taker,
            DcdBranch::Settlement {
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
            &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
            &utxos,
            0,
            witness_values,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            1,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;
        let tx = finalize_p2pk_transaction(
            tx,
            &utxos,
            &keypair,
            2,
            &AddressParams::LIQUID_TESTNET,
            *LIQUID_TESTNET_GENESIS,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        tx
    };
    Ok(tx)
}

pub fn maker_settlement_termination(
    keypair: &Keypair,
    settlement_asset_utxo: OutPoint,
    grantor_settlement_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    grantor_settlement_amount_to_burn: u64,
    fee_amount: u64,
    dcd_arguments: &DCDArguments,
    taproot_pubkey_gen: &TaprootPubkeyGen,
) -> anyhow::Result<Transaction> {
    // Fetch UTXOs
    let settlement_txout = fetch_utxo(settlement_asset_utxo)?; // DCD input 0
    let grantor_settle_txout = fetch_utxo(grantor_settlement_token_utxo)?; // P2PK input 1
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 2

    anyhow::ensure!(
        taproot_pubkey_gen.address.script_pubkey() == settlement_txout.script_pubkey,
        "settlement_asset_utxo must be locked by DCD covenant"
    );

    let available_settlement = settlement_txout.value.explicit().unwrap();
    let grantor_settle_asset_id = grantor_settle_txout.asset.explicit().unwrap();
    let available_grantor_settle = grantor_settle_txout.value.explicit().unwrap();
    let total_fee_input = fee_txout.value.explicit().unwrap();

    anyhow::ensure!(
        grantor_settlement_amount_to_burn <= available_grantor_settle,
        "grantor settlement burn amount exceeds available"
    );

    // amount_to_get = burn * GRANTOR_SETTLEMENT_PER_DEPOSITED_ASSET
    let grantor_settle_per_deposited = dcd_arguments.ratio_args.total_asset_amount
        / dcd_arguments.ratio_args.grantor_settlement_token_amount;
    let amount_to_get =
        grantor_settlement_amount_to_burn.saturating_mul(grantor_settle_per_deposited);

    anyhow::ensure!(
        amount_to_get <= available_settlement,
        "required settlement exceeds available"
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
            taproot_pubkey_gen.address.script_pubkey(),
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
    anyhow::ensure!(fee_amount <= total_fee_input, "fee exceeds input value");
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_fee_input - fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));
    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
    )));

    // Finalize
    let utxos = vec![settlement_txout, grantor_settle_txout, fee_txout];
    let dcd_program = get_dcd_program(&dcd_arguments)?;

    let witness_values = build_dcd_witness(
        TokenBranch::Taker,
        DcdBranch::MakerTermination {
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
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        1,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        2,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(tx)
}

pub fn maker_collateral_termination(
    keypair: &Keypair,
    collateral_utxo: OutPoint,
    grantor_collateral_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    grantor_collateral_amount_to_burn: u64,
    fee_amount: u64,
    dcd_arguments: &DCDArguments,
    taproot_pubkey_gen: &TaprootPubkeyGen,
) -> anyhow::Result<Transaction> {
    // Fetch UTXOs
    let collateral_txout = fetch_utxo(collateral_utxo)?; // DCD input 0
    let grantor_coll_txout = fetch_utxo(grantor_collateral_token_utxo)?; // P2PK input 1
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input 2

    anyhow::ensure!(
        taproot_pubkey_gen.address.script_pubkey() == collateral_txout.script_pubkey,
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

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    // Build PST
    let mut pst = PartiallySignedTransaction::new_v2();

    let mut in0 = Input::from_prevout(collateral_utxo);
    in0.witness_utxo = Some(collateral_txout.clone());
    pst.add_input(in0);

    let mut in1 = Input::from_prevout(grantor_collateral_token_utxo);
    in1.witness_utxo = Some(grantor_coll_txout.clone());
    pst.add_input(in1);

    let mut in2 = Input::from_prevout(fee_utxo);
    in2.witness_utxo = Some(fee_txout.clone());
    pst.add_input(in2);

    if is_change_needed {
        // 0: collateral change back to covenant
        pst.add_output(Output::new_explicit(
            taproot_pubkey_gen.address.script_pubkey(),
            available_collateral - amount_to_get,
            LIQUID_TESTNET_BITCOIN_ASSET,
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
        LIQUID_TESTNET_BITCOIN_ASSET,
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
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));
    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
    )));

    // Finalize
    let utxos = vec![collateral_txout, grantor_coll_txout, fee_txout];
    let dcd_program = get_dcd_program(&dcd_arguments)?;

    let witness_values = build_dcd_witness(
        TokenBranch::Maker,
        DcdBranch::MakerTermination {
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
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        1,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        2,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(tx)
}

pub fn taker_early_termination(
    keypair: &Keypair,
    collateral_utxo: OutPoint,
    filler_token_utxo: OutPoint,
    fee_utxo: OutPoint,
    dcd_taproot_pubkey_gen: &str,
    filler_token_amount_to_return: u64,
    fee_amount: u64,
    dcd_arguments: &DCDArguments,
) -> anyhow::Result<Transaction> {
    let collateral_txout = fetch_utxo(collateral_utxo)?; // DCD input index 0
    let filler_txout = fetch_utxo(filler_token_utxo)?; // P2PK input index 1
    let fee_txout = fetch_utxo(fee_utxo)?; // P2PK input index 2

    let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
        dcd_taproot_pubkey_gen,
        dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &contracts::get_dcd_address,
    )?;

    anyhow::ensure!(
        taproot_pubkey_gen.address.script_pubkey() == collateral_txout.script_pubkey,
        "collateral_utxo must be locked by DCD covenant"
    );

    let available_collateral = collateral_txout.value.explicit().unwrap();
    let filler_asset_id = filler_txout.asset.explicit().unwrap();
    let available_filler = filler_txout.value.explicit().unwrap();
    let total_fee_input = fee_txout.value.explicit().unwrap();

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

    let mut in0 = Input::from_prevout(collateral_utxo);
    in0.witness_utxo = Some(collateral_txout.clone());
    pst.add_input(in0);

    let mut in1 = Input::from_prevout(filler_token_utxo);
    in1.witness_utxo = Some(filler_txout.clone());
    pst.add_input(in1);

    let mut in2 = Input::from_prevout(fee_utxo);
    in2.witness_utxo = Some(fee_txout.clone());
    pst.add_input(in2);

    // Outputs per SIMF indices
    if is_change_needed {
        // 0: collateral change back to covenant
        pst.add_output(Output::new_explicit(
            taproot_pubkey_gen.address.script_pubkey(),
            available_collateral - collateral_to_get,
            LIQUID_TESTNET_BITCOIN_ASSET,
            None,
        ));
    }

    // return filler to covenant
    pst.add_output(Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        filler_token_amount_to_return,
        filler_asset_id,
        None,
    ));

    // return collateral to user
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        collateral_to_get,
        LIQUID_TESTNET_BITCOIN_ASSET,
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
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));
    // fee
    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
    )));

    // Finalize
    let utxos = vec![collateral_txout, filler_txout, fee_txout];
    let dcd_program = get_dcd_program(&dcd_arguments)?;

    // Attach DCD witness to input 0 only
    let witness_values = build_dcd_witness(
        TokenBranch::default(),
        DcdBranch::TakerEarlyTermination {
            is_change_needed,
            index_to_spend: 0,
            filler_token_amount_to_return: filler_token_amount_to_return,
            collateral_amount_to_get: collateral_to_get,
        },
        MergeBranch::default(),
    );

    let tx = finalize_transaction(
        pst.extract_tx()?,
        &dcd_program,
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    // Sign P2PK inputs 1 and 2
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        1,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        2,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(tx)
}

pub fn taker_funding_path(
    keypair: &Keypair,
    filler_token_utxo: OutPoint,
    collateral_utxo: OutPoint,
    dcd_taproot_pubkey_gen: &str,
    collateral_amount_to_deposit: u64,
    fee_amount: u64,
    dcd_arguments: &DCDArguments,
) -> anyhow::Result<Transaction> {
    let filler_utxo = fetch_utxo(filler_token_utxo)?;
    let collateral_token_utxo = fetch_utxo(collateral_utxo)?;

    let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
        dcd_taproot_pubkey_gen,
        dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &contracts::get_dcd_address,
    )?;

    assert_eq!(
        taproot_pubkey_gen.address.script_pubkey(),
        filler_utxo.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the filler token utxo script pubkey"
    );

    let filler_asset_id = filler_utxo.asset.explicit().unwrap();

    let total_collateral = collateral_token_utxo.value.explicit().unwrap();
    let total_filler = filler_utxo.value.explicit().unwrap();

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
    pst.add_input(Input::from_prevout(collateral_utxo));

    let filler_to_get =
        collateral_amount_to_deposit / dcd_arguments.ratio_args.filler_per_principal_collateral;

    let is_filler_change_needed = total_filler != filler_to_get;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    if is_filler_change_needed {
        pst.add_output(Output::new_explicit(
            taproot_pubkey_gen.address.script_pubkey(),
            total_filler - filler_to_get,
            filler_asset_id,
            None,
        ));
    }

    pst.add_output(Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        collateral_amount_to_deposit,
        LIQUID_TESTNET_BITCOIN_ASSET,
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
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
    )));

    let utxos = vec![filler_utxo, collateral_token_utxo];

    let witness_values = build_dcd_witness(
        TokenBranch::default(),
        DcdBranch::TakerFunding {
            collateral_amount_to_deposit: collateral_amount_to_deposit,
            filler_token_amount_to_get: filler_to_get,
            is_change_needed: is_filler_change_needed,
        },
        MergeBranch::default(),
    );

    let dcd_program = get_dcd_program(&dcd_arguments)?;

    let tx = finalize_transaction(
        pst.extract_tx()?,
        &dcd_program,
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        1,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(tx)
}

pub fn maker_funding_path(
    keypair: &Keypair,
    blinding_key: &Keypair,
    filler_token_utxo: OutPoint,
    grantor_collateral_token_utxo: OutPoint,
    grantor_settlement_token_utxo: OutPoint,
    settlement_asset_utxo: OutPoint,
    fee_utxo: OutPoint,
    dcd_taproot_pubkey_gen: &str,
    fee_amount: u64,
    first_entropy_hex: impl AsRef<[u8]>,
    second_entropy_hex: impl AsRef<[u8]>,
    third_entropy_hex: impl AsRef<[u8]>,
    dcd_arguments: &DCDArguments,
) -> anyhow::Result<Transaction> {
    let filler_utxo = fetch_utxo(filler_token_utxo)?;
    let grantor_collateral_utxo = fetch_utxo(grantor_collateral_token_utxo)?;
    let grantor_settlement_utxo = fetch_utxo(grantor_settlement_token_utxo)?;
    let settlement_utxo = fetch_utxo(settlement_asset_utxo)?;
    let fee_token_utxo = fetch_utxo(fee_utxo)?;

    let total_input_fee = fee_token_utxo.value.explicit().unwrap();
    let total_input_asset = settlement_utxo.value.explicit().unwrap();

    let first_entropy_hex = hex::decode(first_entropy_hex)?;
    let second_entropy_hex = hex::decode(second_entropy_hex)?;
    let third_entropy_hex = hex::decode(third_entropy_hex)?;

    let mut first_asset_entropy_bytes: [u8; 32] = first_entropy_hex.try_into().unwrap();
    first_asset_entropy_bytes.reverse();
    let mut second_asset_entropy_bytes: [u8; 32] = second_entropy_hex.try_into().unwrap();
    second_asset_entropy_bytes.reverse();
    let mut third_asset_entropy_bytes: [u8; 32] = third_entropy_hex.try_into().unwrap();
    third_asset_entropy_bytes.reverse();

    let first_asset_entropy = sha256::Midstate::from_byte_array(first_asset_entropy_bytes);
    let second_asset_entropy = sha256::Midstate::from_byte_array(second_asset_entropy_bytes);
    let third_asset_entropy = sha256::Midstate::from_byte_array(third_asset_entropy_bytes);

    let blinding_sk = blinding_key.secret_key();

    let first_unblinded = filler_utxo.unblind(&Secp256k1::new(), blinding_sk)?;
    let second_unblinded = grantor_collateral_utxo.unblind(&Secp256k1::new(), blinding_sk)?;
    let third_unblinded = grantor_settlement_utxo.unblind(&Secp256k1::new(), blinding_sk)?;

    let first_token_abf = first_unblinded.asset_bf;
    let second_token_abf = second_unblinded.asset_bf;
    let third_token_abf = third_unblinded.asset_bf;

    let first_asset_id = AssetId::from_entropy(first_asset_entropy);
    let second_asset_id = AssetId::from_entropy(second_asset_entropy);
    let third_asset_id = AssetId::from_entropy(third_asset_entropy);

    let first_token_id = AssetId::reissuance_token_from_entropy(first_asset_entropy, false);
    let second_token_id = AssetId::reissuance_token_from_entropy(second_asset_entropy, false);
    let third_token_id = AssetId::reissuance_token_from_entropy(third_asset_entropy, false);

    let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
        dcd_taproot_pubkey_gen,
        dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &contracts::get_dcd_address,
    )?;

    assert_eq!(
        taproot_pubkey_gen.address.script_pubkey(),
        filler_utxo.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the filler token utxo script pubkey"
    );

    assert_eq!(
        taproot_pubkey_gen.address.script_pubkey(),
        grantor_collateral_utxo.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the grantor collateral token utxo script pubkey"
    );

    assert_eq!(
        taproot_pubkey_gen.address.script_pubkey(),
        grantor_settlement_utxo.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the grantor settlement token utxo script pubkey"
    );

    let settlement_asset_id = AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    let mut pst = PartiallySignedTransaction::new_v2();

    let mut first_reissuance_tx = Input::from_prevout(filler_token_utxo);
    first_reissuance_tx.witness_utxo = Some(filler_utxo.clone());
    first_reissuance_tx.issuance_value_amount = Some(dcd_arguments.ratio_args.filler_token_amount);
    first_reissuance_tx.issuance_inflation_keys = None;
    first_reissuance_tx.issuance_asset_entropy = Some(first_asset_entropy.to_byte_array());

    let mut second_reissuance_tx = Input::from_prevout(grantor_collateral_token_utxo);
    second_reissuance_tx.witness_utxo = Some(grantor_collateral_utxo.clone());
    second_reissuance_tx.issuance_value_amount =
        Some(dcd_arguments.ratio_args.grantor_collateral_token_amount);
    second_reissuance_tx.issuance_inflation_keys = None;
    second_reissuance_tx.issuance_asset_entropy = Some(second_asset_entropy.to_byte_array());

    let mut third_reissuance_tx = Input::from_prevout(grantor_settlement_token_utxo);
    third_reissuance_tx.witness_utxo = Some(grantor_settlement_utxo.clone());
    third_reissuance_tx.issuance_value_amount =
        Some(dcd_arguments.ratio_args.grantor_settlement_token_amount);
    third_reissuance_tx.issuance_inflation_keys = None;
    third_reissuance_tx.issuance_asset_entropy = Some(third_asset_entropy.to_byte_array());

    pst.add_input(first_reissuance_tx);
    pst.add_input(second_reissuance_tx);
    pst.add_input(third_reissuance_tx);

    let mut asset_settlement_tx = Input::from_prevout(settlement_asset_utxo);
    asset_settlement_tx.witness_utxo = Some(settlement_utxo.clone());
    pst.add_input(asset_settlement_tx);

    let mut fee_tx = Input::from_prevout(fee_utxo);
    fee_tx.witness_utxo = Some(fee_token_utxo.clone());
    pst.add_input(fee_tx);

    let mut output = Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        1,
        first_token_id,
        Some(blinding_key.public_key().into()),
    );
    output.blinder_index = Some(0);
    pst.add_output(output);

    let mut output = Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        1,
        second_token_id,
        Some(blinding_key.public_key().into()),
    );
    output.blinder_index = Some(1);
    pst.add_output(output);

    let mut output = Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        1,
        third_token_id,
        Some(blinding_key.public_key().into()),
    );
    output.blinder_index = Some(2);
    pst.add_output(output);

    pst.add_output(Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        dcd_arguments.ratio_args.interest_collateral_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    pst.add_output(Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        dcd_arguments.ratio_args.total_asset_amount,
        settlement_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        taproot_pubkey_gen.address.script_pubkey(),
        dcd_arguments.ratio_args.filler_token_amount,
        first_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        dcd_arguments.ratio_args.grantor_collateral_token_amount,
        second_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        dcd_arguments.ratio_args.grantor_settlement_token_amount,
        third_asset_id,
        None,
    ));

    // Collateral change
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_fee - fee_amount - dcd_arguments.ratio_args.interest_collateral_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    // Asset change
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_asset - dcd_arguments.ratio_args.total_asset_amount,
        settlement_asset_id,
        None,
    ));

    // Fee
    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    {
        let input = &mut pst.inputs_mut()[0];
        input.blinded_issuance = Some(0x00);
        input.issuance_blinding_nonce = Some(first_token_abf.into_inner());
    }
    {
        let input = &mut pst.inputs_mut()[1];
        input.blinded_issuance = Some(0x00);
        input.issuance_blinding_nonce = Some(second_token_abf.into_inner());
    }
    {
        let input = &mut pst.inputs_mut()[2];
        input.blinded_issuance = Some(0x00);
        input.issuance_blinding_nonce = Some(third_token_abf.into_inner());
    }

    let mut inp_tx_out_sec = std::collections::HashMap::new();
    inp_tx_out_sec.insert(0, first_unblinded);
    inp_tx_out_sec.insert(1, second_unblinded);
    inp_tx_out_sec.insert(2, third_unblinded);

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_tx_out_sec)?;

    let utxos = vec![
        filler_utxo,
        grantor_collateral_utxo,
        grantor_settlement_utxo,
        settlement_utxo,
        fee_token_utxo,
    ];
    let dcd_program = get_dcd_program(&dcd_arguments)?;

    let witness_values = build_dcd_witness(
        TokenBranch::default(),
        DcdBranch::MakerFunding {
            principal_collateral_amount: dcd_arguments.ratio_args.principal_collateral_amount,
            principal_asset_amount: dcd_arguments.ratio_args.principal_asset_amount,
            interest_collateral_amount: dcd_arguments.ratio_args.interest_collateral_amount,
            interest_asset_amount: dcd_arguments.ratio_args.interest_asset_amount,
        },
        MergeBranch::default(),
    );
    let tx = finalize_transaction(
        pst.extract_tx()?,
        &dcd_program,
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        0,
        witness_values.clone(),
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_transaction(
        tx,
        &dcd_program,
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        1,
        witness_values.clone(),
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_transaction(
        tx,
        &dcd_program,
        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
        &utxos,
        2,
        witness_values,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        3,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        4,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok(tx)
}

pub fn dcd_creation(
    keypair: &Keypair,
    blinding_key: &Keypair,
    first_fee_utxo: OutPoint,
    second_fee_utxo: OutPoint,
    third_fee_utxo: OutPoint,
    taker_funding_start_time: u32,
    taker_funding_end_time: u32,
    contract_expiry_time: u32,
    early_termination_end_time: u32,
    settlement_height: u32,
    principal_collateral_amount: u64,
    incentive_basis_points: u64,
    filler_per_principal_collateral: u64,
    strike_price: u64,
    settlement_asset_id: &str,
    oracle_public_key: &str,
    fee_amount: u64,
) -> anyhow::Result<(
    AssetEntropyBytes,
    AssetEntropyBytes,
    AssetEntropyBytes,
    DCDArguments,
    TaprootPubkeyGen,
    Transaction,
)> {
    let first_utxo = fetch_utxo(first_fee_utxo)?;
    let second_utxo = fetch_utxo(second_fee_utxo)?;
    let third_utxo = fetch_utxo(third_fee_utxo)?;

    let first_asset_entropy = get_random_seed();
    let second_asset_entropy = get_random_seed();
    let third_asset_entropy = get_random_seed();

    let mut first_issuance_tx = Input::from_prevout(first_fee_utxo);
    first_issuance_tx.witness_utxo = Some(first_utxo.clone());
    first_issuance_tx.issuance_value_amount = None;
    first_issuance_tx.issuance_inflation_keys = Some(1);
    first_issuance_tx.issuance_asset_entropy = Some(first_asset_entropy);

    let mut second_issuance_tx = Input::from_prevout(second_fee_utxo);
    second_issuance_tx.witness_utxo = Some(second_utxo.clone());
    second_issuance_tx.issuance_value_amount = None;
    second_issuance_tx.issuance_inflation_keys = Some(1);
    second_issuance_tx.issuance_asset_entropy = Some(second_asset_entropy);

    let mut third_issuance_tx = Input::from_prevout(third_fee_utxo);
    third_issuance_tx.witness_utxo = Some(third_utxo.clone());
    third_issuance_tx.issuance_value_amount = None;
    third_issuance_tx.issuance_inflation_keys = Some(1);
    third_issuance_tx.issuance_asset_entropy = Some(third_asset_entropy);

    let (first_asset, first_reissuance_asset) = first_issuance_tx.issuance_ids();
    let (second_asset, second_reissuance_asset) = second_issuance_tx.issuance_ids();
    let (third_asset, third_reissuance_asset) = third_issuance_tx.issuance_ids();

    let ratio_args = DCDRatioArguments::build_from(
        principal_collateral_amount,
        incentive_basis_points,
        strike_price,
        filler_per_principal_collateral,
    )?;

    let dcd_arguments = DCDArguments {
        taker_funding_start_time: taker_funding_start_time,
        taker_funding_end_time: taker_funding_end_time,
        contract_expiry_time: contract_expiry_time,
        early_termination_end_time: early_termination_end_time,
        settlement_height: settlement_height,
        strike_price: strike_price,
        incentive_basis_points: incentive_basis_points,
        fee_basis_points: 0,
        collateral_asset_id_hex_le: LIQUID_TESTNET_BITCOIN_ASSET.to_string(),
        settlement_asset_id_hex_le: settlement_asset_id.to_string(),
        filler_token_asset_id_hex_le: first_asset.to_string(),
        grantor_collateral_token_asset_id_hex_le: second_asset.to_string(),
        grantor_settlement_token_asset_id_hex_le: third_asset.to_string(),
        ratio_args: ratio_args.clone(),
        oracle_public_key: oracle_public_key.to_string(),
    };

    let dcd_taproot_pubkey_gen = TaprootPubkeyGen::from(
        &dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &contracts::get_dcd_address,
    )?;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    let total_input_fee = first_utxo.value.explicit().unwrap()
        + second_utxo.value.explicit().unwrap()
        + third_utxo.value.explicit().unwrap();

    let mut pst = PartiallySignedTransaction::new_v2();

    pst.add_input(first_issuance_tx);
    pst.add_input(second_issuance_tx);
    pst.add_input(third_issuance_tx);

    // Add first reissuance token
    let mut output = Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        1,
        first_reissuance_asset,
        Some(blinding_key.public_key().into()),
    );
    output.blinder_index = Some(0);
    pst.add_output(output);

    // Add second reissuance token
    let mut output = Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        1,
        second_reissuance_asset,
        Some(blinding_key.public_key().into()),
    );
    output.blinder_index = Some(1);
    pst.add_output(output);

    // Add third reissuance token
    let mut output = Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        1,
        third_reissuance_asset,
        Some(blinding_key.public_key().into()),
    );
    output.blinder_index = Some(2);
    pst.add_output(output);

    // Add L-BTC
    let output = Output::new_explicit(
        change_recipient.script_pubkey(),
        total_input_fee - fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    );
    pst.add_output(output);

    // Add fee
    let output = Output::new_explicit(
        Script::new(),
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    );
    pst.add_output(output);

    let first_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: first_utxo.value.explicit().unwrap(),
        asset: LIQUID_TESTNET_BITCOIN_ASSET,
    };
    let second_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: second_utxo.value.explicit().unwrap(),
        asset: LIQUID_TESTNET_BITCOIN_ASSET,
    };
    let third_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: third_utxo.value.explicit().unwrap(),
        asset: LIQUID_TESTNET_BITCOIN_ASSET,
    };

    let mut inp_txout_sec = std::collections::HashMap::new();
    inp_txout_sec.insert(0, first_input_secrets);
    inp_txout_sec.insert(1, second_input_secrets);
    inp_txout_sec.insert(2, third_input_secrets);

    pst.inputs_mut()[0].blinded_issuance = Some(0x00);
    pst.inputs_mut()[1].blinded_issuance = Some(0x00);
    pst.inputs_mut()[2].blinded_issuance = Some(0x00);

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

    let utxos = vec![first_utxo, second_utxo, third_utxo];
    let tx = finalize_p2pk_transaction(
        pst.extract_tx()?,
        &utxos,
        &keypair,
        0,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        1,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;
    let tx = finalize_p2pk_transaction(
        tx,
        &utxos,
        &keypair,
        2,
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
    Ok((
        first_asset_entropy,
        second_asset_entropy,
        third_asset_entropy,
        dcd_arguments,
        dcd_taproot_pubkey_gen,
        tx,
    ))
}

pub fn handle_merge_tokens(
    keypair: &Keypair,
    dcd_arguments: &DCDArguments,
    token_utxos: &[OutPoint],
    fee_utxo: OutPoint,
    dcd_taproot_pubkey_gen: &str,
    fee_amount: u64,
    merge_branch: MergeBranch,
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
    let dcd_program = get_dcd_program(&dcd_arguments)?;
    let dcd_pubkey = simplicityhl_core::TaprootPubkeyGen::build_from_str(
        dcd_taproot_pubkey_gen,
        dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &contracts::get_dcd_address,
    )?
    .pubkey
    .to_x_only_pubkey();

    let dcd_address =
        contracts::get_dcd_address(&dcd_pubkey, &dcd_arguments, &AddressParams::LIQUID_TESTNET)?;

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
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    // Output 3: Fee
    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
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
        &keypair,
        token_utxos.len(),
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    Ok(tx)
}
