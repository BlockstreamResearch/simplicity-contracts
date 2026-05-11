#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use crate::common::filters::{
    AmountFilter, filter_signer_utxos_by_asset_and_amount, filter_signer_utxos_by_asset_id,
    find_signer_utxo_by_asset_and_amount,
};
use simplex::provider::SimplicityNetwork;
use simplex::signer::Signer;
use simplex::simplicityhl::elements::{AssetId, Txid};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, RequiredSignature, UTXO,
};

pub fn finalize_and_broadcast(
    context: &simplex::TestContext,
    ft: &FinalTransaction,
) -> anyhow::Result<Txid> {
    let provider = context.get_default_provider();
    let (tx, _) = context.get_default_signer().finalize(ft)?;
    let txid = provider.broadcast_transaction(&tx)?;
    txid.wait()?;
    Ok(txid.txid())
}

pub fn ensure_exact_signer_utxo(
    context: &simplex::TestContext,
    asset_id: AssetId,
    amount: u64,
) -> anyhow::Result<UTXO> {
    let signer = context.get_default_signer();

    if let Some(exact_utxo) =
        find_signer_utxo_by_asset_and_amount(signer, asset_id, amount, AmountFilter::EqualTo)
    {
        return Ok(exact_utxo);
    }

    let funding_utxo =
        find_signer_utxo_by_asset_and_amount(signer, asset_id, amount, AmountFilter::GreaterThan)
            .ok_or_else(|| {
            anyhow::anyhow!(
                "missing signer funding utxo for asset {asset_id:?} and amount {amount}"
            )
        })?;

    let split_ft = get_split_utxo_ft(funding_utxo, vec![amount], signer, *context.get_network());
    let _ = finalize_and_broadcast(context, &split_ft)?;

    find_signer_utxo_by_asset_and_amount(signer, asset_id, amount, AmountFilter::EqualTo)
        .ok_or_else(|| {
            anyhow::anyhow!("missing exact signer utxo for asset {asset_id:?} and amount {amount}")
        })
}

#[must_use]
pub fn get_split_utxo_ft(
    utxo: UTXO,
    amounts: Vec<u64>,
    signer: &Signer,
    network: SimplicityNetwork,
) -> FinalTransaction {
    let (utxo_asset_id, utxo_amount) = (utxo.asset(), utxo.amount());

    let mut ft = FinalTransaction::new();
    ft.add_input(PartialInput::new(utxo), RequiredSignature::NativeEcdsa);

    let signer_script_pubkey = signer.get_address().script_pubkey();
    let mut total_amount = 0;

    for amount in amounts {
        ft.add_output(PartialOutput::new(
            signer_script_pubkey.clone(),
            amount,
            utxo_asset_id,
        ));
        total_amount += amount;
    }

    assert!(
        total_amount <= utxo_amount,
        "Total amounts after split must be less than the utxo amount"
    );

    if utxo_asset_id != network.policy_asset() && total_amount < utxo_amount {
        ft.add_output(PartialOutput::new(
            signer_script_pubkey,
            utxo_amount - total_amount,
            utxo_asset_id,
        ));
    }

    ft
}

pub fn split_first_signer_utxo(
    context: &simplex::TestContext,
    amounts: Vec<u64>,
) -> anyhow::Result<Txid> {
    let signer = context.get_default_signer();
    let signer_utxos = signer.get_utxos()?;
    let signer_utxo = signer_utxos
        .first()
        .expect("Signer does not have any utxos");

    let ft = get_split_utxo_ft(signer_utxo.clone(), amounts, signer, *context.get_network());
    finalize_and_broadcast(context, &ft)
}

pub fn get_lbtc_utxo(context: &simplex::TestContext) -> anyhow::Result<UTXO> {
    let signer = context.get_default_signer();

    let fee_sized_policy_utxos = filter_signer_utxos_by_asset_and_amount(
        signer,
        context.get_network().policy_asset(),
        100_000,
        AmountFilter::LessThan,
    );
    let first_utxo = fee_sized_policy_utxos
        .first()
        .cloned()
        .or_else(|| {
            filter_signer_utxos_by_asset_id(signer, context.get_network().policy_asset())
                .first()
                .cloned()
        })
        .ok_or_else(|| anyhow::anyhow!("Signer does not have any policy asset UTXOs"))?;

    Ok(first_utxo)
}
