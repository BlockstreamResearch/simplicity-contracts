use crate::common::filters::{assert_covenant_utxo, assert_has_utxo_by_asset_amount_and_script};
use crate::program_builder::options::{
    CONTRACT_COUNT, TOTAL_COLLATERAL_AMOUNT, setup_funded_options,
};

use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn fund_options_contract(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let funded = setup_funded_options(&context, -100, 1_000)?;
    let parameters = &funded.options.parameters;

    let funding_tx = provider.fetch_transaction(&funded.funding_txid)?;
    assert_eq!(funded.option_reissuance_token.outpoint.vout, 0);
    assert_eq!(
        funded.option_reissuance_token.asset(),
        parameters.option_reissuance_token_asset
    );
    assert_eq!(funded.option_reissuance_token.amount(), 1);
    assert_eq!(
        funded.option_reissuance_token.txout.script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(funded.grantor_reissuance_token.outpoint.vout, 1);
    assert_eq!(
        funded.grantor_reissuance_token.asset(),
        parameters.grantor_reissuance_token_asset
    );
    assert_eq!(funded.grantor_reissuance_token.amount(), 1);
    assert_eq!(
        funded.grantor_reissuance_token.txout.script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(
        funding_tx.output[2].asset.explicit(),
        Some(parameters.collateral_asset_id)
    );
    assert_eq!(
        funding_tx.output[2].value.explicit(),
        Some(TOTAL_COLLATERAL_AMOUNT)
    );
    assert_eq!(
        funding_tx.output[2].script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(
        funding_tx.output[3].asset.explicit(),
        Some(parameters.option_token_asset)
    );
    assert_eq!(funding_tx.output[3].value.explicit(), Some(CONTRACT_COUNT));
    assert_eq!(
        funding_tx.output[3].script_pubkey,
        signer.get_address().script_pubkey()
    );

    assert_eq!(
        funding_tx.output[4].asset.explicit(),
        Some(parameters.grantor_token_asset)
    );
    assert_eq!(funding_tx.output[4].value.explicit(), Some(CONTRACT_COUNT));
    assert_eq!(
        funding_tx.output[4].script_pubkey,
        signer.get_address().script_pubkey()
    );

    assert_covenant_utxo(
        &context,
        &funded.options.get_script_pubkey(),
        parameters.collateral_asset_id,
        TOTAL_COLLATERAL_AMOUNT,
    )?;

    let signer_utxos = signer.get_utxos_txid(funded.funding_txid)?;
    let receiver_script_pubkey = signer.get_address().script_pubkey();
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        parameters.option_token_asset,
        CONTRACT_COUNT,
        &receiver_script_pubkey,
    );
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        parameters.grantor_token_asset,
        CONTRACT_COUNT,
        &receiver_script_pubkey,
    );

    Ok(())
}
