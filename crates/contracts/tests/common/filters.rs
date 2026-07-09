#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use simplex::signer::Signer;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::UTXO;

#[derive(Clone, Copy)]
pub enum AmountFilter {
    LessThan,
    GreaterThan,
    EqualTo,
}

#[must_use]
pub fn filter_signer_utxos_by_asset_and_amount(
    signer: &Signer,
    asset_id: AssetId,
    amount: u64,
    amount_filter: AmountFilter,
) -> Vec<UTXO> {
    signer
        .get_utxos_filter(
            &|utxo| {
                utxo.explicit_asset() == asset_id
                    && matches_amount_filter(utxo.explicit_amount(), amount, amount_filter)
            },
            &|utxo| {
                utxo.unblinded_asset() == asset_id
                    && matches_amount_filter(utxo.unblinded_amount(), amount, amount_filter)
            },
        )
        .unwrap()
}

#[must_use]
pub fn find_signer_utxo_by_asset_and_amount(
    signer: &Signer,
    asset_id: AssetId,
    amount: u64,
    amount_filter: AmountFilter,
) -> Option<UTXO> {
    filter_signer_utxos_by_asset_and_amount(signer, asset_id, amount, amount_filter)
        .into_iter()
        .next()
}

#[must_use]
pub fn filter_signer_utxos_by_asset_id(signer: &Signer, asset_id: AssetId) -> Vec<UTXO> {
    signer
        .get_utxos_filter(&|utxo| utxo.explicit_asset() == asset_id, &|utxo| {
            utxo.unblinded_asset() == asset_id
        })
        .unwrap()
}

#[must_use]
pub fn find_utxo_by_asset_and_amount(
    utxos: &[UTXO],
    asset_id: AssetId,
    amount: u64,
) -> Option<UTXO> {
    utxos
        .iter()
        .find(|utxo| {
            utxo.txout.asset.explicit() == Some(asset_id)
                && utxo.txout.value.explicit() == Some(amount)
        })
        .cloned()
}

pub fn require_utxo_by_asset_and_amount(
    utxos: &[UTXO],
    asset_id: AssetId,
    amount: u64,
    missing_utxo_message: &str,
) -> anyhow::Result<UTXO> {
    find_utxo_by_asset_and_amount(utxos, asset_id, amount)
        .ok_or_else(|| anyhow::anyhow!("{missing_utxo_message}"))
}

#[must_use]
pub fn find_utxo_by_asset_amount_and_script(
    utxos: &[UTXO],
    asset_id: AssetId,
    amount: u64,
    script_pubkey: &Script,
) -> Option<UTXO> {
    utxos
        .iter()
        .find(|utxo| {
            utxo.txout.asset.explicit() == Some(asset_id)
                && utxo.txout.value.explicit() == Some(amount)
                && utxo.txout.script_pubkey == *script_pubkey
        })
        .cloned()
}

pub fn assert_has_utxo_by_asset_and_amount(utxos: &[UTXO], asset_id: AssetId, amount: u64) {
    assert!(
        find_utxo_by_asset_and_amount(utxos, asset_id, amount).is_some(),
        "missing utxo for asset {asset_id:?} and amount {amount}"
    );
}

pub fn assert_has_utxo_by_asset_amount_and_script(
    utxos: &[UTXO],
    asset_id: AssetId,
    amount: u64,
    script_pubkey: &Script,
) {
    assert!(
        find_utxo_by_asset_amount_and_script(utxos, asset_id, amount, script_pubkey).is_some(),
        "missing utxo for asset {asset_id:?}, amount {amount}, and expected script"
    );
}

const fn matches_amount_filter(utxo_amount: u64, amount: u64, amount_filter: AmountFilter) -> bool {
    match amount_filter {
        AmountFilter::LessThan => utxo_amount < amount,
        AmountFilter::GreaterThan => utxo_amount > amount,
        AmountFilter::EqualTo => utxo_amount == amount,
    }
}

/// Fetch the covenant UTXOs at `script_pubkey` and return the one matching
/// asset and amount, failing with `missing_utxo_message` if absent.
pub fn require_covenant_utxo(
    context: &simplex::TestContext,
    script_pubkey: &Script,
    asset_id: AssetId,
    amount: u64,
    missing_utxo_message: &str,
) -> anyhow::Result<UTXO> {
    let utxos = context
        .get_default_provider()
        .fetch_scripthash_utxos(script_pubkey)?;
    require_utxo_by_asset_and_amount(&utxos, asset_id, amount, missing_utxo_message)
}

/// Assert that a covenant UTXO with the given asset and amount exists at
/// `script_pubkey`.
pub fn assert_covenant_utxo(
    context: &simplex::TestContext,
    script_pubkey: &Script,
    asset_id: AssetId,
    amount: u64,
) -> anyhow::Result<()> {
    let utxos = context
        .get_default_provider()
        .fetch_scripthash_utxos(script_pubkey)?;
    assert_has_utxo_by_asset_and_amount(&utxos, asset_id, amount);
    Ok(())
}
