use crate::common::filters::assert_has_utxo_by_asset_and_amount;
use crate::program_builder::option_offer::{
    create_option_offer_with_premium, deposit_to_option_offer, prepare_option_offer,
};

use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn deposit_to_create_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();

    let deposit_lbtc_amount = 1000;

    let (option_offer, deposit_txid) =
        deposit_to_option_offer(&context, deposit_lbtc_amount, 10000, 10000, 1000)?;

    let transaction = provider.fetch_transaction(&deposit_txid)?;
    assert_eq!(
        transaction.output[0].value.explicit(),
        Some(deposit_lbtc_amount)
    );
    assert_eq!(
        transaction.output[0].asset.explicit(),
        Some(option_offer.parameters.collateral_asset_id)
    );
    assert_eq!(
        transaction.output[0].script_pubkey,
        option_offer.get_script_pubkey()
    );

    Ok(())
}

#[simplex::test]
fn deposit_to_create_option_offer_with_premium(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let provider = context.get_default_provider();

    let deposit_lbtc_amount = 1_000_u64;
    let expected_premium_amount = 10_000_u64;
    let expected_settlement_amount = 10_000_u64;

    let option_offer = prepare_option_offer(
        &context,
        deposit_lbtc_amount,
        expected_premium_amount,
        expected_settlement_amount,
        1_000,
    )?;

    create_option_offer_with_premium(
        &context,
        &option_offer,
        deposit_lbtc_amount,
        expected_premium_amount,
    )?;

    let program_utxos = provider.fetch_scripthash_utxos(&option_offer.get_script_pubkey())?;
    assert_has_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.collateral_asset_id,
        deposit_lbtc_amount,
    );
    assert_has_utxo_by_asset_and_amount(
        &program_utxos,
        option_offer.parameters.premium_asset_id,
        expected_premium_amount,
    );

    Ok(())
}
