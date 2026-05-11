use crate::common::filters::{
    assert_has_utxo_by_asset_amount_and_script, assert_has_utxo_by_asset_and_amount,
};
use crate::program_builder::options::{create_options, fund_options, prepare_options};

use contracts::programs::program::SimplexProgram;

#[simplex::test]
fn fund_options_contract(context: simplex::TestContext) -> anyhow::Result<()> {
    let provider = context.get_default_provider();
    let signer = context.get_default_signer();

    let total_collateral_amount = 1_000_u64;
    let expected_settlement_amount = 500_u64;
    let contract_count = 10_u64;

    let prepared = prepare_options(
        &context,
        total_collateral_amount,
        expected_settlement_amount,
        contract_count,
        -100,
        1_000,
    )?;
    let created = create_options(&context, prepared)?;
    let funded = fund_options(&context, created, total_collateral_amount, contract_count)?;

    let funding_tx = provider.fetch_transaction(&funded.funding_txid)?;
    assert_eq!(funded.option_reissuance_token.outpoint.vout, 0);
    assert_eq!(
        funded.option_reissuance_token.asset(),
        funded.options.parameters.option_reissuance_token_asset
    );
    assert_eq!(funded.option_reissuance_token.amount(), 1);
    assert_eq!(
        funded.option_reissuance_token.txout.script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(funded.grantor_reissuance_token.outpoint.vout, 1);
    assert_eq!(
        funded.grantor_reissuance_token.asset(),
        funded.options.parameters.grantor_reissuance_token_asset
    );
    assert_eq!(funded.grantor_reissuance_token.amount(), 1);
    assert_eq!(
        funded.grantor_reissuance_token.txout.script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(
        funding_tx.output[2].asset.explicit(),
        Some(funded.options.parameters.collateral_asset_id)
    );
    assert_eq!(
        funding_tx.output[2].value.explicit(),
        Some(total_collateral_amount)
    );
    assert_eq!(
        funding_tx.output[2].script_pubkey,
        funded.options.get_script_pubkey()
    );

    assert_eq!(
        funding_tx.output[3].asset.explicit(),
        Some(funded.options.parameters.option_token_asset)
    );
    assert_eq!(funding_tx.output[3].value.explicit(), Some(contract_count));
    assert_eq!(
        funding_tx.output[3].script_pubkey,
        signer.get_address().script_pubkey()
    );

    assert_eq!(
        funding_tx.output[4].asset.explicit(),
        Some(funded.options.parameters.grantor_token_asset)
    );
    assert_eq!(funding_tx.output[4].value.explicit(), Some(contract_count));
    assert_eq!(
        funding_tx.output[4].script_pubkey,
        signer.get_address().script_pubkey()
    );

    let program_utxos = provider.fetch_scripthash_utxos(&funded.options.get_script_pubkey())?;
    assert_eq!(
        funded.option_reissuance_token.asset(),
        funded.options.parameters.option_reissuance_token_asset
    );
    assert_eq!(funded.option_reissuance_token.amount(), 1);
    assert_eq!(
        funded.grantor_reissuance_token.asset(),
        funded.options.parameters.grantor_reissuance_token_asset
    );
    assert_eq!(funded.grantor_reissuance_token.amount(), 1);
    assert_has_utxo_by_asset_and_amount(
        &program_utxos,
        funded.options.parameters.collateral_asset_id,
        total_collateral_amount,
    );

    let signer_utxos = signer.get_utxos_txid(funded.funding_txid)?;
    let receiver_script_pubkey = signer.get_address().script_pubkey();
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        funded.options.parameters.option_token_asset,
        contract_count,
        &receiver_script_pubkey,
    );
    assert_has_utxo_by_asset_amount_and_script(
        &signer_utxos,
        funded.options.parameters.grantor_token_asset,
        contract_count,
        &receiver_script_pubkey,
    );

    Ok(())
}
