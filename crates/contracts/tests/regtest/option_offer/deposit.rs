use crate::common::filters::assert_covenant_utxo;
use crate::program_builder::option_offer::{
    DEPOSIT_LBTC_AMOUNT, EXPECTED_PREMIUM_AMOUNT, deposit_to_option_offer, setup_offer_with_premium,
};

use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn deposit_to_create_option_offer(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();

    let (option_offer, deposit_txid) =
        deposit_to_option_offer(&context, DEPOSIT_LBTC_AMOUNT, 10_000, 10_000, 1_000)?;

    let transaction = provider.fetch_transaction(&deposit_txid)?;
    assert_eq!(
        transaction.output[0].value.explicit(),
        Some(DEPOSIT_LBTC_AMOUNT)
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
    let option_offer = setup_offer_with_premium(&context, 1_000)?;

    let script_pubkey = option_offer.get_script_pubkey();
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.collateral_asset_id,
        DEPOSIT_LBTC_AMOUNT,
    )?;
    assert_covenant_utxo(
        &context,
        &script_pubkey,
        option_offer.parameters.premium_asset_id,
        EXPECTED_PREMIUM_AMOUNT,
    )?;

    Ok(())
}
