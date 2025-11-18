use contracts::{
    build_dcd_witness, get_dcd_program, DCDArguments, DcdBranch, MergeBranch, TokenBranch,
};
use simplicity::elements::{BlockHash, TxOut};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::elements::{AssetId, OutPoint, Transaction};
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{AddressParams, Script};
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::{simplicity, CompiledProgram, WitnessValues};
use simplicityhl_core::{
    fetch_utxo, finalize_p2pk_transaction, finalize_transaction, get_p2pk_address,
    obtain_utxo_value, AssetEntropyBytes, TaprootPubkeyGen,
};

use crate::dcd::common::{raw_asset_entropy_bytes_to_midstate, AssetEntropyProcessed};
use crate::dcd::COLLATERAL_ASSET_ID;
use std::str::FromStr;
use tracing::instrument;

#[allow(clippy::too_many_arguments)]
#[instrument(level = "debug", skip_all, err)]
pub fn handle(
    keypair: &secp256k1::Keypair,
    blinding_key: &secp256k1::Keypair,
    filler_reissue_token_info: (OutPoint, AssetEntropyBytes),
    grantor_collateral_reissue_token_info: (OutPoint, AssetEntropyBytes),
    grantor_settlement_reissue_token_info: (OutPoint, AssetEntropyBytes),
    settlement_asset_utxo: OutPoint,
    fee_utxo: OutPoint,
    fee_amount: u64,
    dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
    dcd_arguments: &DCDArguments,
    address_params: &'static AddressParams,
    change_asset: AssetId,
    genesis_block_hash: simplicity::elements::BlockHash,
) -> anyhow::Result<Transaction> {
    tracing::debug!(
        filler_token_info =? filler_reissue_token_info,
        grantor_collateral_token_info =? grantor_collateral_reissue_token_info,
        grantor_settlement_token_info =? grantor_settlement_reissue_token_info,
        settlement_asset_info =? settlement_asset_utxo,
        fee_utxo =? fee_utxo,
        dcd_taproot_pubkey_gen =? dcd_taproot_pubkey_gen,
        fee_amount = fee_amount,
        "Executing maker fund with params"
    );

    let (filler_token_utxo, filler_token_utxo_tx_out) = (
        filler_reissue_token_info.0,
        fetch_utxo(filler_reissue_token_info.0)?,
    );
    let (grantor_collateral_token_utxo, grantor_collateral_token_utxo_tx_out) = (
        grantor_collateral_reissue_token_info.0,
        fetch_utxo(grantor_collateral_reissue_token_info.0)?,
    );
    let (grantor_settlement_token_utxo, grantor_settlement_token_utxo_tx_out) = (
        grantor_settlement_reissue_token_info.0,
        fetch_utxo(grantor_settlement_reissue_token_info.0)?,
    );
    let (settlement_utxo, settlement_utxo_tx_out) =
        (settlement_asset_utxo, fetch_utxo(settlement_asset_utxo)?);
    let fee_utxo_tx_out = fetch_utxo(fee_utxo)?;

    let total_input_fee = obtain_utxo_value(&fee_utxo_tx_out)?;
    let total_input_asset = obtain_utxo_value(&settlement_utxo_tx_out)?;

    let AssetEntropyProcessed {
        entropy: filler_token_asset_entropy,
        reversed_bytes: _filler_reversed_bytes,
    } = raw_asset_entropy_bytes_to_midstate(filler_reissue_token_info.1);
    let AssetEntropyProcessed {
        entropy: grantor_collateral_token_asset_entropy,
        reversed_bytes: _grantor_collateral_reversed_bytes,
    } = raw_asset_entropy_bytes_to_midstate(grantor_collateral_reissue_token_info.1);
    let AssetEntropyProcessed {
        entropy: grantor_settlement_token_asset_entropy,
        reversed_bytes: _grantor_settlement_reversed_bytes,
    } = raw_asset_entropy_bytes_to_midstate(grantor_settlement_reissue_token_info.1);

    let blinding_sk = blinding_key.secret_key();

    let filler_tx_out_unblinded =
        filler_token_utxo_tx_out.unblind(&Secp256k1::new(), blinding_sk)?;
    let grantor_collateral_tx_out_unblinded =
        grantor_collateral_token_utxo_tx_out.unblind(&Secp256k1::new(), blinding_sk)?;
    let grantor_settlement_tx_out_unblinded =
        grantor_settlement_token_utxo_tx_out.unblind(&Secp256k1::new(), blinding_sk)?;

    let filler_token_abf = filler_tx_out_unblinded.asset_bf;
    let grantor_collateral_token_abf = grantor_collateral_tx_out_unblinded.asset_bf;
    let grantor_settlement_token_abf = grantor_settlement_tx_out_unblinded.asset_bf;

    let filler_asset_id = AssetId::from_entropy(filler_token_asset_entropy);
    let grantor_collateral_asset_id = AssetId::from_entropy(grantor_collateral_token_asset_entropy);
    let grantor_settlement_asset_id = AssetId::from_entropy(grantor_settlement_token_asset_entropy);

    let filler_reissue_token_id =
        AssetId::reissuance_token_from_entropy(filler_token_asset_entropy, false);
    let grantor_collateral_reissue_token_id =
        AssetId::reissuance_token_from_entropy(grantor_collateral_token_asset_entropy, false);
    let grantor_settlement_reissue_token_id =
        AssetId::reissuance_token_from_entropy(grantor_settlement_token_asset_entropy, false);

    assert_eq!(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        filler_token_utxo_tx_out.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the filler token utxo script pubkey"
    );

    assert_eq!(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        grantor_collateral_token_utxo_tx_out.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the grantor collateral token utxo script pubkey"
    );

    assert_eq!(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        grantor_settlement_token_utxo_tx_out.script_pubkey,
        "Expected the taproot pubkey gen address to be the same as the grantor settlement token utxo script pubkey"
    );

    let settlement_asset_id = AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?;

    let change_recipient = get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    let mut inp_tx_out_sec = std::collections::HashMap::new();
    let mut pst = PartiallySignedTransaction::new_v2();

    {
        let mut filler_reissuance_tx = Input::from_prevout(filler_token_utxo);
        filler_reissuance_tx.witness_utxo = Some(filler_token_utxo_tx_out.clone());
        filler_reissuance_tx.issuance_value_amount =
            Some(dcd_arguments.ratio_args.filler_token_amount);
        filler_reissuance_tx.issuance_inflation_keys = None;
        filler_reissuance_tx.issuance_asset_entropy =
            Some(filler_token_asset_entropy.to_byte_array());

        filler_reissuance_tx.blinded_issuance = Some(0x00);
        filler_reissuance_tx.issuance_blinding_nonce = Some(filler_token_abf.into_inner());
        pst.add_input(filler_reissuance_tx);
        inp_tx_out_sec.insert(0, filler_tx_out_unblinded);
    }
    {
        let mut grantor_collateral_reissuance_tx =
            Input::from_prevout(grantor_collateral_token_utxo);
        grantor_collateral_reissuance_tx.witness_utxo =
            Some(grantor_collateral_token_utxo_tx_out.clone());
        grantor_collateral_reissuance_tx.issuance_value_amount =
            Some(dcd_arguments.ratio_args.grantor_collateral_token_amount);
        grantor_collateral_reissuance_tx.issuance_inflation_keys = None;
        grantor_collateral_reissuance_tx.issuance_asset_entropy =
            Some(grantor_collateral_token_asset_entropy.to_byte_array());

        grantor_collateral_reissuance_tx.blinded_issuance = Some(0x00);
        grantor_collateral_reissuance_tx.issuance_blinding_nonce =
            Some(grantor_collateral_token_abf.into_inner());
        pst.add_input(grantor_collateral_reissuance_tx);
        inp_tx_out_sec.insert(1, grantor_collateral_tx_out_unblinded);
    }
    {
        let mut grantor_settlement_reissuance_tx =
            Input::from_prevout(grantor_settlement_token_utxo);
        grantor_settlement_reissuance_tx.witness_utxo =
            Some(grantor_settlement_token_utxo_tx_out.clone());
        grantor_settlement_reissuance_tx.issuance_value_amount =
            Some(dcd_arguments.ratio_args.grantor_settlement_token_amount);
        grantor_settlement_reissuance_tx.issuance_inflation_keys = None;
        grantor_settlement_reissuance_tx.issuance_asset_entropy =
            Some(grantor_settlement_token_asset_entropy.to_byte_array());

        grantor_settlement_reissuance_tx.blinded_issuance = Some(0x00);
        grantor_settlement_reissuance_tx.issuance_blinding_nonce =
            Some(grantor_settlement_token_abf.into_inner());
        pst.add_input(grantor_settlement_reissuance_tx);
        inp_tx_out_sec.insert(2, grantor_settlement_tx_out_unblinded);
    }

    {
        let mut asset_settlement_tx = Input::from_prevout(settlement_utxo);
        asset_settlement_tx.witness_utxo = Some(settlement_utxo_tx_out.clone());
        pst.add_input(asset_settlement_tx);
    }
    {
        let mut fee_tx = Input::from_prevout(fee_utxo);
        fee_tx.witness_utxo = Some(fee_utxo_tx_out.clone());
        pst.add_input(fee_tx);
    }

    {
        let mut output = Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            1,
            filler_reissue_token_id,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(0);
        pst.add_output(output);
    }
    {
        let mut output = Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            1,
            grantor_collateral_reissue_token_id,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(1);
        pst.add_output(output);
    }
    {
        let mut output = Output::new_explicit(
            dcd_taproot_pubkey_gen.address.script_pubkey(),
            1,
            grantor_settlement_reissue_token_id,
            Some(blinding_key.public_key().into()),
        );
        output.blinder_index = Some(2);
        pst.add_output(output);
    }
    pst.add_output(Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        dcd_arguments.ratio_args.interest_collateral_amount,
        COLLATERAL_ASSET_ID,
        None,
    ));
    pst.add_output(Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        dcd_arguments.ratio_args.total_asset_amount,
        settlement_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        dcd_taproot_pubkey_gen.address.script_pubkey(),
        dcd_arguments.ratio_args.filler_token_amount,
        filler_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        dcd_arguments.ratio_args.grantor_collateral_token_amount,
        grantor_collateral_asset_id,
        None,
    ));

    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        dcd_arguments.ratio_args.grantor_settlement_token_amount,
        grantor_settlement_asset_id,
        None,
    ));

    // Collateral change
    let collateral_change_amount =
        total_input_fee - fee_amount - dcd_arguments.ratio_args.interest_collateral_amount;
    pst.add_output(Output::new_explicit(
        change_recipient.script_pubkey(),
        collateral_change_amount,
        AssetId::from_str(&dcd_arguments.collateral_asset_id_hex_le)?,
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
        change_asset,
        None,
    ));

    pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_tx_out_sec)?;

    let utxos = [
        filler_token_utxo_tx_out,
        grantor_collateral_token_utxo_tx_out,
        grantor_settlement_token_utxo_tx_out,
        settlement_utxo_tx_out,
        fee_utxo_tx_out,
    ];
    let dcd_program = get_dcd_program(dcd_arguments)?;

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

    let tx = finalize_transaction_inner(
        pst,
        keypair,
        dcd_program,
        dcd_taproot_pubkey_gen,
        &utxos,
        witness_values,
        address_params,
        genesis_block_hash,
    )?;

    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

    Ok(tx)
}

#[allow(clippy::too_many_arguments)]
fn finalize_transaction_inner(
    pst: PartiallySignedTransaction,
    keypair: &secp256k1::Keypair,
    dcd_program: CompiledProgram,
    taproot_pubkey_gen: &TaprootPubkeyGen,
    utxos: &[TxOut; 5],
    witness_values: WitnessValues,
    address_params: &'static AddressParams,
    genesis_block_hash: BlockHash,
) -> anyhow::Result<Transaction> {
    let taproot_x_only_pubkey = taproot_pubkey_gen.pubkey.to_x_only_pubkey();
    let tx = pst.extract_tx()?;
    let tx = finalize_transaction(
        tx,
        &dcd_program,
        &taproot_x_only_pubkey,
        utxos,
        0,
        witness_values.clone(),
        address_params,
        genesis_block_hash,
    )?;
    let tx = finalize_transaction(
        tx,
        &dcd_program,
        &taproot_x_only_pubkey,
        utxos,
        1,
        witness_values.clone(),
        address_params,
        genesis_block_hash,
    )?;
    let tx = finalize_transaction(
        tx,
        &dcd_program,
        &taproot_x_only_pubkey,
        utxos,
        2,
        witness_values,
        address_params,
        genesis_block_hash,
    )?;
    let tx = finalize_p2pk_transaction(tx, utxos, keypair, 3, address_params, genesis_block_hash)?;
    let tx = finalize_p2pk_transaction(tx, utxos, keypair, 4, address_params, genesis_block_hash)?;
    Ok(tx)
}
