use wallet_abi::{Network, ProgramError, create_p2tr_address, load_program};

use simplicityhl::elements::Address;

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;

use simplicityhl::{CompiledProgram, TemplateProgram};

pub mod build_arguments;
pub mod build_witness;

pub use build_arguments::OptionOfferArguments;

pub const OPTION_OFFER_SOURCE: &str = include_str!("source_simf/option_offer.simf");
pub const OPTION_OFFER_URI: &str = include_str!("source_simf/option_offer.wallet.schema.json");

/// Get the option offer template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_option_offer_template_program() -> TemplateProgram {
    TemplateProgram::new(OPTION_OFFER_SOURCE)
        .expect("INTERNAL: expected Option Offer Program to compile successfully.")
}

/// Derive P2TR address for an option offer contract.
///
/// # Errors
///
/// Returns error if program compilation fails.
pub fn get_option_offer_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &OptionOfferArguments,
    network: Network,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_option_offer_program(arguments)?.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

/// Compile option offer program with the given arguments.
///
/// # Errors
///
/// Returns error if compilation fails.
pub fn get_option_offer_program(
    arguments: &OptionOfferArguments,
) -> Result<CompiledProgram, ProgramError> {
    load_program(OPTION_OFFER_SOURCE, arguments.build_arguments())
}

/// Get compiled option offer program, panicking on failure.
///
/// # Panics
///
/// Panics if program instantiation fails.
#[must_use]
pub fn get_compiled_option_offer_program(arguments: &OptionOfferArguments) -> CompiledProgram {
    let program = get_option_offer_template_program();

    program
        .instantiate(arguments.build_arguments(), true)
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_setup::{RuntimeFundingAsset, ensure_node_running, fund_runtime};
    use serde_json::Value;
    use std::collections::BTreeMap;
    use wallet_abi::{AssetVariant, InputSchema, LockVariant, OutputIntent, OutputSchema};

    use wallet_abi::runtime::params::RuntimeParamsEnvelope;
    use wallet_abi::runtime::{WalletRuntimeConfig, create_tx_v1};
    use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
    use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_option_offer_deposit() -> anyhow::Result<()> {
        let mut runtime_config =
            WalletRuntimeConfig::from_mnemonic(TEST_MNEMONIC, Network::LocaltestLiquid)?;

        ensure_node_running()?;
        let (collateral_asset_id, _, _) =
            fund_runtime(&mut runtime_config, RuntimeFundingAsset::Lbtc)?;
        let (premium_asset_id, _, _) =
            fund_runtime(&mut runtime_config, RuntimeFundingAsset::NewAsset)?;
        let (settlement_asset_id, _, _) =
            fund_runtime(&mut runtime_config, RuntimeFundingAsset::NewAsset)?;

        let args = OptionOfferArguments::new(
            collateral_asset_id,
            premium_asset_id,
            settlement_asset_id,
            100,
            10,
            1_700_000_000,
            runtime_config.signer.xpub().to_x_only_pub().serialize(),
        );

        let tap =
            TaprootPubkeyGen::from(&args, Network::LocaltestLiquid, &get_option_offer_address)?;

        let collateral_deposit_amount = 1000u64;
        let premium_deposit_amount = collateral_deposit_amount * args.premium_per_collateral();

        let mut extra: BTreeMap<String, Value> = BTreeMap::new();
        extra.insert("arguments".to_string(), args.to_json()?);
        extra.insert("internal_key".to_string(), tap.to_json()?);

        let response = create_tx_v1(
            &TxCreateRequest {
                abi_version: TX_CREATE_ABI_VERSION.to_string(),
                request_type: "tx.create".to_string(),
                request_id: "request-id".to_string(),
                network: Network::LocaltestLiquid,
                schema_uri: OPTION_OFFER_URI.to_string(),
                branch: "option_offer.deposit".to_string(),
                params: RuntimeParamsEnvelope {
                    inputs: vec![InputSchema::new("input0"), InputSchema::new("input1")],
                    outputs: vec![
                        OutputSchema {
                            id: "out0".to_string(),
                            intent: OutputIntent::Transfer,
                            asset: AssetVariant::AssetId {
                                asset_id: collateral_asset_id,
                            },
                            amount_sat: collateral_deposit_amount,
                            lock: LockVariant::Script {
                                script: tap.address.script_pubkey(),
                            },
                            blinding_pubkey: None,
                        },
                        OutputSchema {
                            id: "out1".to_string(),
                            intent: OutputIntent::Transfer,
                            asset: AssetVariant::AssetId {
                                asset_id: premium_asset_id,
                            },
                            amount_sat: premium_deposit_amount,
                            lock: LockVariant::Script {
                                script: tap.address.script_pubkey(),
                            },
                            blinding_pubkey: None,
                        },
                    ],
                    fee_rate_sat_vb: None,
                    locktime: None,
                    extra,
                }
                .to_request_params_value()?,
                broadcast: true,
            },
            &runtime_config,
        )?;
        assert_eq!(response.branch, "option_offer.deposit");

        Ok(())
    }
}
