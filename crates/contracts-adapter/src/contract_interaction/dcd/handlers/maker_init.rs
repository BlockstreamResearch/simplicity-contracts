use crate::dcd::{
    BaseContractContext, COLLATERAL_ASSET_ID, CreationContext, DcdInitResponse,
    FillerTokenEntropyHex, GrantorCollateralAssetEntropyHex, GrantorSettlementAssetEntropyHex,
    MakerInitContext,
};
use contracts::{DCDArguments, DCDRatioArguments, get_dcd_address};
use simplicity::elements::{BlockHash, TxOut};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{Transaction, TxOutSecrets};
use simplicityhl::simplicity;
use simplicityhl::simplicity::elements::AddressParams;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl_core::{TaprootPubkeyGen, fetch_utxo, get_random_seed, obtain_utxo_value};
use simplicityhl_core::{finalize_p2pk_transaction, get_new_asset_entropy, get_p2pk_address};

#[tracing::instrument(level = "info", skip_all, err)]
#[expect(clippy::too_many_lines)]
pub fn handle(
    context: &CreationContext,
    maker_init_context: MakerInitContext,
    base_contract_context: &BaseContractContext,
) -> anyhow::Result<DcdInitResponse> {
    let CreationContext {
        keypair,
        blinding_key,
    } = context;
    let MakerInitContext {
        input_utxos,
        dcd_init_params,
        fee_amount,
    } = maker_init_context;
    let BaseContractContext {
        address_params,
        lbtc_asset: change_asset,
        genesis_block_hash,
    } = base_contract_context;

    tracing::debug!(
        input_utxos =? input_utxos,
        dcd_init_params =? dcd_init_params,
        fee_amount = fee_amount,
        "Executing maker init with params"
    );

    let first_utxo_tx_out = fetch_utxo(input_utxos[0])?;
    let first_utxo_value = obtain_utxo_value(&first_utxo_tx_out)?;

    let second_utxo_tx_out = fetch_utxo(input_utxos[1])?;
    let second_utxo_value = obtain_utxo_value(&second_utxo_tx_out)?;

    let third_utxo_tx_out = fetch_utxo(input_utxos[2])?;
    let third_utxo_value = obtain_utxo_value(&third_utxo_tx_out)?;

    let total_input_fee = first_utxo_value + second_utxo_value + third_utxo_value;

    let first_asset_entropy = get_random_seed();
    let second_asset_entropy = get_random_seed();
    let third_asset_entropy = get_random_seed();

    let mut first_issuance_tx = Input::from_prevout(input_utxos[0]);
    first_issuance_tx.witness_utxo = Some(first_utxo_tx_out.clone());
    first_issuance_tx.issuance_value_amount = None;
    first_issuance_tx.issuance_inflation_keys = Some(1);
    first_issuance_tx.issuance_asset_entropy = Some(first_asset_entropy);

    let mut second_issuance_tx = Input::from_prevout(input_utxos[1]);
    second_issuance_tx.witness_utxo = Some(second_utxo_tx_out.clone());
    second_issuance_tx.issuance_value_amount = None;
    second_issuance_tx.issuance_inflation_keys = Some(1);
    second_issuance_tx.issuance_asset_entropy = Some(second_asset_entropy);

    let mut third_issuance_tx = Input::from_prevout(input_utxos[2]);
    third_issuance_tx.witness_utxo = Some(third_utxo_tx_out.clone());
    third_issuance_tx.issuance_value_amount = None;
    third_issuance_tx.issuance_inflation_keys = Some(1);
    third_issuance_tx.issuance_asset_entropy = Some(third_asset_entropy);

    let (first_asset, first_reissuance_asset) = first_issuance_tx.issuance_ids();
    let (second_asset, second_reissuance_asset) = second_issuance_tx.issuance_ids();
    let (third_asset, third_reissuance_asset) = third_issuance_tx.issuance_ids();

    let ratio_args = DCDRatioArguments::build_from(
        dcd_init_params.principal_collateral_amount,
        dcd_init_params.incentive_basis_points,
        dcd_init_params.strike_price,
        dcd_init_params.filler_per_principal_collateral,
    )?;

    let dcd_arguments = DCDArguments {
        taker_funding_start_time: dcd_init_params.taker_funding_start_time,
        taker_funding_end_time: dcd_init_params.taker_funding_end_time,
        contract_expiry_time: dcd_init_params.contract_expiry_time,
        early_termination_end_time: dcd_init_params.early_termination_end_time,
        settlement_height: dcd_init_params.settlement_height,
        strike_price: dcd_init_params.strike_price,
        incentive_basis_points: dcd_init_params.incentive_basis_points,
        fee_basis_points: dcd_init_params.fee_basis_points,
        collateral_asset_id_hex_le: COLLATERAL_ASSET_ID.to_string(),
        settlement_asset_id_hex_le: dcd_init_params.settlement_asset_id,
        filler_token_asset_id_hex_le: first_asset.to_string(),
        grantor_collateral_token_asset_id_hex_le: second_asset.to_string(),
        grantor_settlement_token_asset_id_hex_le: third_asset.to_string(),
        fee_script_hash_hex_le: dcd_init_params.fee_script_hash,
        ratio_args: ratio_args.clone(),
        oracle_public_key: dcd_init_params.oracle_public_key,
    };

    tracing::info!("Generated dcd_arguments: {dcd_arguments:?}");
    let dcd_taproot_pubkey_gen = TaprootPubkeyGen::from(
        &dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &get_dcd_address,
    )?;

    let entropies_to_return: (
        FillerTokenEntropyHex,
        GrantorCollateralAssetEntropyHex,
        GrantorSettlementAssetEntropyHex,
    ) = (
        get_new_asset_entropy(&input_utxos[0], first_asset_entropy).to_hex(),
        get_new_asset_entropy(&input_utxos[1], second_asset_entropy).to_hex(),
        get_new_asset_entropy(&input_utxos[2], third_asset_entropy).to_hex(),
    );

    tracing::info!("dcd_taproot_pubkey_gen: {:?}", dcd_taproot_pubkey_gen);

    let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

    let mut pst = PartiallySignedTransaction::new_v2();

    {
        first_issuance_tx.blinded_issuance = Some(0x00);
        pst.add_input(first_issuance_tx);
    }
    {
        second_issuance_tx.blinded_issuance = Some(0x00);
        pst.add_input(second_issuance_tx);
    }
    {
        third_issuance_tx.blinded_issuance = Some(0x00);
        pst.add_input(third_issuance_tx);
    }

    // Add first reissuance token
    {
        let mut output = Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            1,
            first_reissuance_asset,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(0);
        pst.add_output(output);
    }

    // Add second reissuance token
    {
        let mut output = Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            1,
            second_reissuance_asset,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(1);
        pst.add_output(output);
    }

    // Add third reissuance token
    {
        let mut output = Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            1,
            third_reissuance_asset,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(2);
        pst.add_output(output);
    }

    // Add L-BTC change
    {
        let output = Output::new_explicit(
            change_recipient.script_pubkey(),
            total_input_fee - fee_amount,
            *change_asset,
            None,
        );
        pst.add_output(output);
    }

    // Add fee
    pst.add_output(Output::from_txout(TxOut::new_fee(
        fee_amount,
        *change_asset,
    )));

    let first_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: first_utxo_value,
        asset: COLLATERAL_ASSET_ID,
    };
    let second_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: second_utxo_value,
        asset: COLLATERAL_ASSET_ID,
    };
    let third_input_secrets = TxOutSecrets {
        asset_bf: AssetBlindingFactor::zero(),
        value_bf: ValueBlindingFactor::zero(),
        value: third_utxo_value,
        asset: COLLATERAL_ASSET_ID,
    };

    let mut inp_txout_sec = std::collections::HashMap::new();
    inp_txout_sec.insert(0, first_input_secrets);
    inp_txout_sec.insert(1, second_input_secrets);
    inp_txout_sec.insert(2, third_input_secrets);

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

    let utxos = [first_utxo_tx_out, second_utxo_tx_out, third_utxo_tx_out];

    let tx = finalize_tx_inner(keypair, address_params, *genesis_block_hash, &pst, &utxos)?;
    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    Ok(DcdInitResponse {
        tx,
        filler_token_entropy: entropies_to_return.0,
        grantor_collateral_token_entropy: entropies_to_return.1,
        grantor_settlement_token_entropy: entropies_to_return.2,
        taproot_pubkey_gen: dcd_taproot_pubkey_gen,
        dcd_args: dcd_arguments,
    })
}

fn finalize_tx_inner(
    keypair: &secp256k1::Keypair,
    address_params: &'static AddressParams,
    genesis_block_hash: BlockHash,
    pst: &PartiallySignedTransaction,
    utxos: &[TxOut; 3],
) -> anyhow::Result<Transaction> {
    let tx = finalize_p2pk_transaction(
        pst.clone().extract_tx()?,
        utxos,
        keypair,
        0,
        address_params,
        genesis_block_hash,
    )?;
    let tx = finalize_p2pk_transaction(tx, utxos, keypair, 1, address_params, genesis_block_hash)?;
    let tx = finalize_p2pk_transaction(tx, utxos, keypair, 2, address_params, genesis_block_hash)?;
    Ok(tx)
}
