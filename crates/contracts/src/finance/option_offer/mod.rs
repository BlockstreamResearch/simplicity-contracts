use wallet_abi::{Network, ProgramError, create_p2tr_address, load_program};

use simplicityhl::elements::Address;

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;

use simplicityhl::{CompiledProgram, TemplateProgram};

pub mod build_arguments;
pub mod build_witness;

pub use build_arguments::OptionOfferArguments;

pub const OPTION_OFFER_SOURCE: &str = include_str!("source_simf/option_offer.simf");

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

    use crate::test_setup::{
        RuntimeFundingAsset, ensure_node_running, fund_runtime, get_esplora_url, mine_blocks,
    };
    use anyhow::Context;

    use simplicityhl::elements::{AssetId, LockTime, OutPoint, Sequence, Txid};

    use wallet_abi::{AssetVariant, BlinderVariant, FinalizerSpec, InputBlinder, InputSchema, LockVariant, OutputSchema, RuntimeParams, UTXOSource};

    use crate::option_offer::build_witness::{
        OptionOfferSimfBranch, build_option_offer_simf_witness,
    };
    use wallet_abi::runtime::WalletRuntimeConfig;
    use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
    use wallet_abi::schema::values::{serialize_arguments, serialize_witness};
    use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;

    const COLLATERAL_PER_CONTRACT: u64 = 100;
    const PREMIUM_PER_COLLATERAL: u64 = 10;
    const EXPIRY_TIME: u32 = 1_700_000_000;

    struct RuntimeFixture {
        runtime: WalletRuntimeConfig,
        collateral_asset_id: AssetId,
        premium_asset_id: AssetId,
        settlement_asset_id: AssetId,
        args: OptionOfferArguments,
        tap: TaprootPubkeyGen,
    }

    pub fn wallet_data_root() -> std::path::PathBuf {
        std::env::var_os("SIMPLICITY_CLI_WALLET_DATA_DIR").map_or_else(
            || std::path::PathBuf::from(".cache/wallet"),
            std::path::PathBuf::from,
        )
    }

    impl RuntimeFixture {
        fn setup() -> anyhow::Result<Self> {
            ensure_node_running()?;

            let mut runtime_config = WalletRuntimeConfig::build_random(
                Network::LocaltestLiquid,
                &get_esplora_url()?,
                wallet_data_root(),
            )?;

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
                COLLATERAL_PER_CONTRACT,
                PREMIUM_PER_COLLATERAL,
                EXPIRY_TIME,
                runtime_config.signer_x_only_public_key()?.serialize(),
            );
            let tap =
                TaprootPubkeyGen::from(&args, Network::LocaltestLiquid, &get_option_offer_address)?;

            Ok(Self {
                runtime: runtime_config,
                collateral_asset_id,
                premium_asset_id,
                settlement_asset_id,
                args,
                tap,
            })
        }

        fn premium_amount(&self, collateral_amount: u64) -> anyhow::Result<u64> {
            collateral_amount
                .checked_mul(self.args.premium_per_collateral())
                .context("premium amount overflow")
        }

        fn settlement_amount(&self, collateral_amount: u64) -> anyhow::Result<u64> {
            collateral_amount
                .checked_mul(self.args.collateral_per_contract())
                .context("settlement amount overflow")
        }

        fn get_base_finalizer_spec(
            &self,
            witness: &OptionOfferSimfBranch,
        ) -> anyhow::Result<FinalizerSpec> {
            Ok(FinalizerSpec::Simf {
                source_simf: OPTION_OFFER_SOURCE.to_string(),
                internal_key: Box::new(self.tap.clone()),
                arguments: serialize_arguments(&self.args.build_simf_arguments())?,
                witness: serialize_witness(&build_option_offer_simf_witness(
                    witness,
                    self.runtime.signer_x_only_public_key()?,
                ))?,
            })
        }

        fn build_request(
            id: &str,
            inputs: Vec<InputSchema>,
            outputs: Vec<OutputSchema>,
            locktime: Option<LockTime>,
        ) -> TxCreateRequest {
            TxCreateRequest {
                abi_version: TX_CREATE_ABI_VERSION.to_string(),
                request_id: format!("request-{id}"),
                network: Network::LocaltestLiquid,
                params: RuntimeParams {
                    inputs,
                    outputs,
                    fee_rate_sat_vb: None,
                    locktime,
                },
                broadcast: true,
            }
        }

        fn build_deposit_request(
            &self,
            collateral_deposit_amount: u64,
        ) -> anyhow::Result<TxCreateRequest> {
            let premium_deposit_amount = self.premium_amount(collateral_deposit_amount)?;

            Ok(Self::build_request(
                "option_offer.deposit",
                vec![InputSchema::new("input0"), InputSchema::new("input1")],
                vec![
                    OutputSchema::from_script(
                        "out0",
                        self.collateral_asset_id,
                        collateral_deposit_amount,
                        self.tap.address.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out1",
                        self.premium_asset_id,
                        premium_deposit_amount,
                        self.tap.address.script_pubkey(),
                    ),
                ],
                None,
            ))
        }

        fn build_exercise_request(
            &self,
            creation_tx_id: Txid,
            collateral_amount: u64,
        ) -> anyhow::Result<TxCreateRequest> {
            let premium_amount = self.premium_amount(collateral_amount)?;
            let settlement_amount = self.settlement_amount(collateral_amount)?;

            let collateral_outpoint = OutPoint::new(creation_tx_id, 0);
            let collateral_tx_out = self.runtime.fetch_tx_out(&collateral_outpoint)?;
            let available_collateral = collateral_tx_out.value.explicit().expect("non-confidential");

            let premium_outpoint = OutPoint::new(creation_tx_id, 1);
            let premium_tx_out = self.runtime.fetch_tx_out(&premium_outpoint)?;
            let available_premium = premium_tx_out.value.explicit().expect("non-confidential");

            let collateral_change = available_collateral.checked_sub(collateral_amount).expect("should not overflow");
            let premium_change = available_premium.checked_sub(premium_amount).expect("should not overflow");

            let finalizer = self.get_base_finalizer_spec(&OptionOfferSimfBranch::Exercise {
                collateral_amount,
                is_change_needed: collateral_change != 0,
            })?;

            dbg!(collateral_change != 0);

            let receiver = self.runtime.signer_receive_address()?;

            let mut outputs: Vec<OutputSchema> = Vec::new();
            if collateral_change != 0 {
                outputs.push(
                    OutputSchema {
                        id: "covenant-collateral-change".to_string(),
                        amount_sat: collateral_change,
                        lock: LockVariant::Script { script: self.tap.address.script_pubkey() },
                        asset: AssetVariant::AssetId { asset_id: self.collateral_asset_id },
                        blinder: BlinderVariant::Explicit,
                    }
                );
                outputs.push(
                    OutputSchema {
                        id: "covenant-premium-change".to_string(),
                        amount_sat: premium_change,
                        lock: LockVariant::Script { script: self.tap.address.script_pubkey() },
                        asset: AssetVariant::AssetId { asset_id: self.premium_asset_id },
                        blinder: BlinderVariant::Explicit,
                    }
                );
            }

            outputs.extend(vec![
                OutputSchema {
                    id: "covenant-settlement-change".to_string(),
                    amount_sat: settlement_amount,
                    lock: LockVariant::Script { script: self.tap.address.script_pubkey() },
                    asset: AssetVariant::AssetId { asset_id: self.settlement_asset_id },
                    blinder: BlinderVariant::Explicit,
                },
                OutputSchema {
                    id: "user-collateral-requested".to_string(),
                    amount_sat: collateral_amount,
                    lock: LockVariant::Script { script: receiver.script_pubkey() },
                    asset: AssetVariant::AssetId { asset_id: self.collateral_asset_id },
                    blinder: BlinderVariant::Wallet,
                },
                OutputSchema {
                    id: "user-premium-requested".to_string(),
                    amount_sat: premium_amount,
                    lock: LockVariant::Script { script: receiver.script_pubkey() },
                    asset: AssetVariant::AssetId { asset_id: self.premium_asset_id },
                    blinder: BlinderVariant::Wallet,
                },
            ]);

            Ok(Self::build_request(
                "option_offer.exercise",
                vec![
                    InputSchema {
                        id: "input0".to_string(),
                        utxo_source: UTXOSource::Provided {
                            outpoint: OutPoint::new(creation_tx_id, 0),
                        },
                        blinder: InputBlinder::Explicit,
                        sequence: Sequence::default(),
                        issuance: None,
                        finalizer: finalizer.clone(),
                    },
                    InputSchema {
                        id: "input1".to_string(),
                        utxo_source: UTXOSource::Provided {
                            outpoint: OutPoint::new(creation_tx_id, 1),
                        },
                        blinder: InputBlinder::Explicit,
                        sequence: Sequence::default(),
                        issuance: None,
                        finalizer,
                    },
                    InputSchema::new("input2"),
                ],
                outputs,
                None,
            ))
        }

        fn build_withdraw_request(
            &self,
            exercise_tx_id: Txid,
            settlement_amount: u64,
        ) -> anyhow::Result<TxCreateRequest> {
            let finalizer = self.get_base_finalizer_spec(&OptionOfferSimfBranch::Withdraw)?;

            let receiver = self.runtime.signer_receive_address()?;

            Ok(Self::build_request(
                "option_offer.withdraw",
                vec![InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(exercise_tx_id, 0),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::default(),
                    issuance: None,
                    finalizer,
                }],
                vec![OutputSchema::from_script(
                    "out0",
                    self.settlement_asset_id,
                    settlement_amount,
                    receiver.script_pubkey(),
                )],
                None,
            ))
        }

        fn build_expiry_request(
            &self,
            creation_tx_id: Txid,
            collateral_amount: u64,
            premium_amount: u64,
        ) -> anyhow::Result<TxCreateRequest> {
            let finalizer = self.get_base_finalizer_spec(&OptionOfferSimfBranch::Expiry)?;

            let receiver = self.runtime.signer_receive_address()?;

            Ok(Self::build_request(
                "option_offer.expiry",
                vec![
                    InputSchema {
                        id: "input0".to_string(),
                        utxo_source: UTXOSource::Provided {
                            outpoint: OutPoint::new(creation_tx_id, 0),
                        },
                        blinder: InputBlinder::Explicit,
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        issuance: None,
                        finalizer: finalizer.clone(),
                    },
                    InputSchema {
                        id: "input1".to_string(),
                        utxo_source: UTXOSource::Provided {
                            outpoint: OutPoint::new(creation_tx_id, 1),
                        },
                        blinder: InputBlinder::Explicit,
                        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                        issuance: None,
                        finalizer,
                    },
                ],
                vec![
                    OutputSchema::from_script(
                        "out0",
                        self.collateral_asset_id,
                        collateral_amount,
                        receiver.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out1",
                        self.premium_asset_id,
                        premium_amount,
                        receiver.script_pubkey(),
                    ),
                ],
                Some(LockTime::from_time(self.args.expiry_time())?),
            ))
        }

        fn assert_broadcast_happy_path(
            &mut self,
            request: &TxCreateRequest,
        ) -> anyhow::Result<Txid> {
            let response = self.runtime.process_request(request)?;

            let Some(tx_info) = response.transaction else {
                panic!("Expected a response broadcast info");
            };

            dbg!(&tx_info.txid);

            Ok(tx_info.txid)
        }
    }

    #[test]
    fn test_option_offer_deposit() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let request = fixture.build_deposit_request(1_000u64)?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;
        Ok(())
    }

    #[test]
    fn test_option_offer_exercise() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let collateral_amount = 1_000u64;
        let request = fixture.build_deposit_request(collateral_amount)?;
        let creation_tx_id = fixture.assert_broadcast_happy_path(&request)?;
        mine_blocks(1)?;

        let request = fixture.build_exercise_request(creation_tx_id, collateral_amount)?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;
        Ok(())
    }

    #[test]
    fn test_option_offer_withdraw() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let collateral_amount = 1_000u64;
        let settlement_amount = fixture.settlement_amount(collateral_amount)?;

        let deposit_request = fixture.build_deposit_request(collateral_amount)?;
        let creation_tx_id = fixture.assert_broadcast_happy_path(&deposit_request)?;
        mine_blocks(1)?;

        let exercise_request =
            fixture.build_exercise_request(creation_tx_id, collateral_amount)?;
        let exercise_tx_id = fixture.assert_broadcast_happy_path(&exercise_request)?;
        mine_blocks(1)?;

        let request = fixture.build_withdraw_request(exercise_tx_id, settlement_amount)?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_option_offer_expiry() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let collateral_amount = 1_000u64;
        let premium_amount = fixture.premium_amount(collateral_amount)?;

        let deposit_request = fixture.build_deposit_request(collateral_amount)?;
        let creation_tx_id = fixture.assert_broadcast_happy_path(&deposit_request)?;
        mine_blocks(1)?;

        let request =
            fixture.build_expiry_request(creation_tx_id, collateral_amount, premium_amount)?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }
}
