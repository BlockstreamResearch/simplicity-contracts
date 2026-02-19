#![allow(clippy::similar_names)]

use wallet_abi::{create_p2tr_address, load_program, Network, ProgramError};

use simplicityhl::elements::Address;

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;

use simplicityhl::{CompiledProgram, TemplateProgram};

pub mod build_arguments;
pub mod build_witness;

pub use build_arguments::OptionsArguments;

pub const OPTION_SOURCE: &str = include_str!("source_simf/options.simf");

/// Get the options template program for instantiation.
///
/// # Panics
/// - if the embedded source fails to compile (should never happen).
#[must_use]
pub fn get_options_template_program() -> TemplateProgram {
    TemplateProgram::new(OPTION_SOURCE)
        .expect("INTERNAL: expected Options Program to compile successfully.")
}

/// Derive P2TR address for an options contract.
///
/// # Errors
/// Returns error if program compilation fails.
pub fn get_options_address(
    x_only_public_key: &XOnlyPublicKey,
    arguments: &OptionsArguments,
    network: Network,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        get_options_program(arguments)?.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

/// Compile options program with the given arguments.
///
/// # Errors
/// Returns error if compilation fails.
pub fn get_options_program(arguments: &OptionsArguments) -> Result<CompiledProgram, ProgramError> {
    load_program(OPTION_SOURCE, arguments.build_option_arguments())
}

/// Get compiled options program, panicking on failure.
///
/// # Panics
/// - if program instantiation fails.
#[must_use]
pub fn get_compiled_options_program(arguments: &OptionsArguments) -> CompiledProgram {
    let program = get_options_template_program();

    program
        .instantiate(arguments.build_option_arguments(), true)
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::options::build_witness::{
        blinding_factors_from_secrets, build_option_witness, OptionBranch,
    };
    use crate::test_setup::{
        ensure_node_running, fund_runtime, get_esplora_url, issue_and_fund_runtime_token,
        mine_blocks, RuntimeFundingAsset, RuntimeIssuedTokenPair,
    };

    use anyhow::Context;
    use lwk_common::Signer;

    use simplicityhl::elements::hashes::sha256::Midstate;
    use simplicityhl::elements::secp256k1_zkp::{PublicKey, SecretKey, SECP256K1};
    use simplicityhl::elements::{AssetId, LockTime, OutPoint, Script, Sequence, Txid};
    use simplicityhl::num::U256;

    use wallet_abi::{
        AssetVariant, BlinderVariant, FinalizerSpec, InputBlinder, InputIssuance,
        InputIssuanceKind, InputSchema, LockVariant, OutputSchema, RuntimeParams, UTXOSource,
    };

    use wallet_abi::runtime::WalletRuntimeConfig;
    use wallet_abi::schema::tx_create::{TxCreateRequest, TX_CREATE_ABI_VERSION};
    use wallet_abi::schema::values::{
        serialize_arguments, serialize_witness, SimfArguments, SimfWitness,
    };
    use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;

    const COLLATERAL_PER_CONTRACT: u64 = 100;
    const SETTLEMENT_PER_CONTRACT: u64 = 10;
    const START_TIME: u32 = 1_700_000_000;
    const EXPIRY_TIME: u32 = 1_700_000_100;
    const FULL_CONTRACTS: u64 = 10;
    const PARTIAL_CONTRACTS: u64 = 6;

    struct RuntimeFixture {
        runtime_config: WalletRuntimeConfig,
        collateral_asset_id: AssetId,
        settlement_asset_id: AssetId,
        option_tokens: RuntimeIssuedTokenPair,
        grantor_tokens: RuntimeIssuedTokenPair,
        covenant_blinder_pubkey: PublicKey,
        covenant_blinder_secret: SecretKey,
        args: OptionsArguments,
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
            let (settlement_asset_id, _, _) =
                fund_runtime(&mut runtime_config, RuntimeFundingAsset::NewAsset)?;

            let option_tokens = issue_and_fund_runtime_token(&mut runtime_config, 1)?;
            let grantor_tokens = issue_and_fund_runtime_token(&mut runtime_config, 1)?;
            let option_token_asset =
                AssetId::from_entropy(Midstate::from_byte_array(option_tokens.entropy));
            let grantor_token_asset =
                AssetId::from_entropy(Midstate::from_byte_array(grantor_tokens.entropy));

            let args = OptionsArguments::new(
                START_TIME,
                EXPIRY_TIME,
                COLLATERAL_PER_CONTRACT,
                SETTLEMENT_PER_CONTRACT,
                collateral_asset_id,
                settlement_asset_id,
                option_tokens.entropy,
                option_token_asset,
                option_tokens.token_id,
                grantor_token_asset,
                grantor_tokens.token_id,
            );

            let tap =
                TaprootPubkeyGen::from(&args, Network::LocaltestLiquid, &get_options_address)?;
            let covenant_blinder_secret = runtime_config
                .signer
                .slip77_master_blinding_key()?
                .blinding_private_key(&tap.address.script_pubkey());
            let covenant_blinder_pubkey =
                PublicKey::from_secret_key(SECP256K1, &covenant_blinder_secret);

            Ok(Self {
                runtime_config,
                collateral_asset_id,
                settlement_asset_id,
                option_tokens,
                grantor_tokens,
                covenant_blinder_pubkey,
                covenant_blinder_secret,
                args,
                tap,
            })
        }

        fn collateral_amount(&self, contracts: u64) -> anyhow::Result<u64> {
            contracts
                .checked_mul(self.args.collateral_per_contract())
                .context("collateral amount overflow")
        }

        fn settlement_amount(&self, contracts: u64) -> anyhow::Result<u64> {
            contracts
                .checked_mul(self.args.settlement_per_contract())
                .context("settlement amount overflow")
        }

        fn get_base_finalizer_spec(&self, branch: &OptionBranch) -> anyhow::Result<FinalizerSpec> {
            Ok(FinalizerSpec::Simf {
                source_simf: OPTION_SOURCE.to_string(),
                internal_key: Box::new(self.tap.clone()),
                arguments: serialize_arguments(&SimfArguments::new(
                    self.args.build_option_arguments(),
                ))?,
                witness: serialize_witness(&SimfWitness {
                    resolved: build_option_witness(branch),
                    runtime_arguments: vec![],
                })?,
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

        fn build_burn_output(id: &str, asset_id: AssetId, amount: u64) -> OutputSchema {
            OutputSchema::from_script(id, asset_id, amount, Script::new_op_return(b"burn"))
        }

        fn build_token_deposit_request(&self) -> TxCreateRequest {
            Self::build_request(
                "options.deposit_tokens",
                vec![InputSchema::new("input0"), InputSchema::new("input1")],
                vec![
                    OutputSchema {
                        id: "out0".to_string(),
                        amount_sat: 1,
                        lock: LockVariant::Script {
                            script: self.tap.address.script_pubkey(),
                        },
                        asset: AssetVariant::AssetId {
                            asset_id: self.option_tokens.token_id,
                        },
                        blinder: BlinderVariant::Provided {
                            pubkey: self.covenant_blinder_pubkey,
                        },
                    },
                    OutputSchema {
                        id: "out1".to_string(),
                        amount_sat: 1,
                        lock: LockVariant::Script {
                            script: self.tap.address.script_pubkey(),
                        },
                        asset: AssetVariant::AssetId {
                            asset_id: self.grantor_tokens.token_id,
                        },
                        blinder: BlinderVariant::Provided {
                            pubkey: self.covenant_blinder_pubkey,
                        },
                    },
                ],
                None,
            )
        }

        fn build_funding_request(
            &self,
            token_deposit_tx_id: Txid,
            contracts: u64,
        ) -> anyhow::Result<TxCreateRequest> {
            let collateral_amount = self.collateral_amount(contracts)?;
            let expected_asset_amount = self.settlement_amount(contracts)?;
            let option_token_outpoint = OutPoint::new(token_deposit_tx_id, 0);
            let grantor_token_outpoint = OutPoint::new(token_deposit_tx_id, 1);

            let option_token_tx_out = self.runtime_config.fetch_tx_out(&option_token_outpoint)?;
            let option_token_secrets = option_token_tx_out
                .unblind(SECP256K1, self.covenant_blinder_secret)
                .context("failed to unblind option reissuance token input")?;

            let grantor_token_tx_out = self.runtime_config.fetch_tx_out(&grantor_token_outpoint)?;
            let grantor_token_secrets = grantor_token_tx_out
                .unblind(SECP256K1, self.covenant_blinder_secret)
                .context("failed to unblind grantor reissuance token input")?;

            let (input_option_abf, input_option_vbf) =
                blinding_factors_from_secrets(&option_token_secrets);
            let (input_grantor_abf, input_grantor_vbf) =
                blinding_factors_from_secrets(&grantor_token_secrets);

            let finalizer = self.get_base_finalizer_spec(&OptionBranch::Funding {
                expected_asset_amount,
                input_option_abf,
                input_option_vbf,
                input_grantor_abf,
                input_grantor_vbf,
                output_option_abf: U256::from_byte_array([0; 32]),
                output_option_vbf: U256::from_byte_array([0; 32]),
                output_grantor_abf: U256::from_byte_array([0; 32]),
                output_grantor_vbf: U256::from_byte_array([0; 32]),
            })?;

            let receiver = self.runtime_config.signer_receive_address()?;

            Ok(Self::build_request(
                "options.funding",
                vec![
                    InputSchema {
                        id: "input0".to_string(),
                        utxo_source: UTXOSource::Provided {
                            outpoint: option_token_outpoint,
                        },
                        blinder: InputBlinder::Provided {
                            secret_key: self.covenant_blinder_secret,
                        },
                        sequence: Sequence::default(),
                        issuance: Some(InputIssuance {
                            kind: InputIssuanceKind::Reissue,
                            asset_amount_sat: contracts,
                            token_amount_sat: 0,
                            entropy: self.option_tokens.entropy,
                        }),
                        finalizer: finalizer.clone(),
                    },
                    InputSchema {
                        id: "input1".to_string(),
                        utxo_source: UTXOSource::Provided {
                            outpoint: grantor_token_outpoint,
                        },
                        blinder: InputBlinder::Provided {
                            secret_key: self.covenant_blinder_secret,
                        },
                        sequence: Sequence::default(),
                        issuance: Some(InputIssuance {
                            kind: InputIssuanceKind::Reissue,
                            asset_amount_sat: contracts,
                            token_amount_sat: 0,
                            entropy: self.grantor_tokens.entropy,
                        }),
                        finalizer,
                    },
                    InputSchema::new("input2"),
                ],
                vec![
                    OutputSchema::from_script(
                        "out0",
                        self.option_tokens.token_id,
                        1,
                        self.tap.address.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out1",
                        self.grantor_tokens.token_id,
                        1,
                        self.tap.address.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out2",
                        self.collateral_asset_id,
                        collateral_amount,
                        self.tap.address.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out3",
                        self.args.option_token(),
                        contracts,
                        receiver.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out4",
                        self.args.grantor_token(),
                        contracts,
                        receiver.script_pubkey(),
                    ),
                ],
                None,
            ))
        }

        fn build_exercise_request(
            &self,
            funding_tx_id: Txid,
            collateral_input_amount: u64,
            amount_to_burn: u64,
            is_change_needed: bool,
        ) -> anyhow::Result<TxCreateRequest> {
            let collateral_amount_to_get = self.collateral_amount(amount_to_burn)?;
            let asset_amount = self.settlement_amount(amount_to_burn)?;

            let finalizer = self.get_base_finalizer_spec(&OptionBranch::Exercise {
                is_change_needed,
                amount_to_burn,
                collateral_amount_to_get,
                asset_amount,
            })?;

            let mut outputs = Vec::new();
            if is_change_needed {
                let collateral_change = collateral_input_amount
                    .checked_sub(collateral_amount_to_get)
                    .context("exercise collateral change underflow")?;
                outputs.push(OutputSchema::from_script(
                    "out0",
                    self.collateral_asset_id,
                    collateral_change,
                    self.tap.address.script_pubkey(),
                ));
                outputs.push(Self::build_burn_output(
                    "out1",
                    self.args.option_token(),
                    amount_to_burn,
                ));
                outputs.push(OutputSchema::from_script(
                    "out2",
                    self.settlement_asset_id,
                    asset_amount,
                    self.tap.address.script_pubkey(),
                ));
            } else {
                outputs.push(Self::build_burn_output(
                    "out0",
                    self.args.option_token(),
                    amount_to_burn,
                ));
                outputs.push(OutputSchema::from_script(
                    "out1",
                    self.settlement_asset_id,
                    asset_amount,
                    self.tap.address.script_pubkey(),
                ));
            }

            Ok(Self::build_request(
                "options.exercise",
                vec![InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(funding_tx_id, 2),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    issuance: None,
                    finalizer,
                }],
                outputs,
                Some(LockTime::from_time(self.args.start_time())?),
            ))
        }

        fn build_settlement_request(
            &self,
            settlement_outpoint: OutPoint,
            settlement_input_amount: u64,
            grantor_token_amount_to_burn: u64,
            is_change_needed: bool,
        ) -> anyhow::Result<TxCreateRequest> {
            let asset_amount = self.settlement_amount(grantor_token_amount_to_burn)?;

            let finalizer = self.get_base_finalizer_spec(&OptionBranch::Settlement {
                is_change_needed,
                grantor_token_amount_to_burn,
                asset_amount,
            })?;

            let mut outputs = Vec::new();
            if is_change_needed {
                let settlement_change = settlement_input_amount
                    .checked_sub(asset_amount)
                    .context("settlement change underflow")?;
                outputs.push(OutputSchema::from_script(
                    "out0",
                    self.settlement_asset_id,
                    settlement_change,
                    self.tap.address.script_pubkey(),
                ));
                outputs.push(Self::build_burn_output(
                    "out1",
                    self.args.grantor_token(),
                    grantor_token_amount_to_burn,
                ));
            } else {
                outputs.push(Self::build_burn_output(
                    "out0",
                    self.args.grantor_token(),
                    grantor_token_amount_to_burn,
                ));
            }

            Ok(Self::build_request(
                "options.settlement",
                vec![InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: settlement_outpoint,
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    issuance: None,
                    finalizer,
                }],
                outputs,
                Some(LockTime::from_time(self.args.start_time())?),
            ))
        }

        fn build_expiry_request(
            &self,
            funding_tx_id: Txid,
            collateral_input_amount: u64,
            grantor_token_amount_to_burn: u64,
            is_change_needed: bool,
        ) -> anyhow::Result<TxCreateRequest> {
            let collateral_amount_to_withdraw =
                self.collateral_amount(grantor_token_amount_to_burn)?;

            let finalizer = self.get_base_finalizer_spec(&OptionBranch::Expiry {
                is_change_needed,
                grantor_token_amount_to_burn,
                collateral_amount_to_withdraw,
            })?;

            let mut outputs = Vec::new();
            if is_change_needed {
                let collateral_change = collateral_input_amount
                    .checked_sub(collateral_amount_to_withdraw)
                    .context("expiry collateral change underflow")?;
                outputs.push(OutputSchema::from_script(
                    "out0",
                    self.collateral_asset_id,
                    collateral_change,
                    self.tap.address.script_pubkey(),
                ));
                outputs.push(Self::build_burn_output(
                    "out1",
                    self.args.grantor_token(),
                    grantor_token_amount_to_burn,
                ));
            } else {
                outputs.push(Self::build_burn_output(
                    "out0",
                    self.args.grantor_token(),
                    grantor_token_amount_to_burn,
                ));
            }

            Ok(Self::build_request(
                "options.expiry",
                vec![InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(funding_tx_id, 2),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    issuance: None,
                    finalizer,
                }],
                outputs,
                Some(LockTime::from_time(self.args.expiry_time())?),
            ))
        }

        fn build_cancellation_request(
            &self,
            funding_tx_id: Txid,
            collateral_input_amount: u64,
            amount_to_burn: u64,
            is_change_needed: bool,
        ) -> anyhow::Result<TxCreateRequest> {
            let collateral_amount_to_withdraw = self.collateral_amount(amount_to_burn)?;

            let finalizer = self.get_base_finalizer_spec(&OptionBranch::Cancellation {
                is_change_needed,
                amount_to_burn,
                collateral_amount_to_withdraw,
            })?;

            let mut outputs = Vec::new();
            if is_change_needed {
                let collateral_change = collateral_input_amount
                    .checked_sub(collateral_amount_to_withdraw)
                    .context("cancellation collateral change underflow")?;
                outputs.push(OutputSchema::from_script(
                    "out0",
                    self.collateral_asset_id,
                    collateral_change,
                    self.tap.address.script_pubkey(),
                ));
                outputs.push(Self::build_burn_output(
                    "out1",
                    self.args.option_token(),
                    amount_to_burn,
                ));
                outputs.push(Self::build_burn_output(
                    "out2",
                    self.args.grantor_token(),
                    amount_to_burn,
                ));
            } else {
                outputs.push(Self::build_burn_output(
                    "out0",
                    self.args.option_token(),
                    amount_to_burn,
                ));
                outputs.push(Self::build_burn_output(
                    "out1",
                    self.args.grantor_token(),
                    amount_to_burn,
                ));
            }

            Ok(Self::build_request(
                "options.cancellation",
                vec![InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: OutPoint::new(funding_tx_id, 2),
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::default(),
                    issuance: None,
                    finalizer,
                }],
                outputs,
                None,
            ))
        }

        fn assert_broadcast_happy_path(
            &mut self,
            request: &TxCreateRequest,
        ) -> anyhow::Result<Txid> {
            let response = self.runtime_config.process_request(request)?;

            let Some(tx_info) = response.transaction else {
                panic!("Expected a response broadcast info");
            };

            dbg!(&tx_info.txid);

            Ok(tx_info.txid)
        }
    }

    fn setup_funded_position(fixture: &mut RuntimeFixture, contracts: u64) -> anyhow::Result<Txid> {
        let token_deposit_request = fixture.build_token_deposit_request();
        let token_deposit_tx_id = fixture.assert_broadcast_happy_path(&token_deposit_request)?;
        mine_blocks(1)?;

        let funding_request = fixture.build_funding_request(token_deposit_tx_id, contracts)?;
        let funding_tx_id = fixture.assert_broadcast_happy_path(&funding_request)?;

        Ok(funding_tx_id)
    }

    #[test]
    fn test_options_funding_happy_path() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let _ = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        Ok(())
    }

    #[test]
    fn test_options_exercise_no_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let request = fixture.build_exercise_request(
            funding_tx_id,
            collateral_input_amount,
            FULL_CONTRACTS,
            false,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_exercise_with_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let request = fixture.build_exercise_request(
            funding_tx_id,
            collateral_input_amount,
            PARTIAL_CONTRACTS,
            true,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_settlement_no_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let exercise_request = fixture.build_exercise_request(
            funding_tx_id,
            collateral_input_amount,
            FULL_CONTRACTS,
            false,
        )?;
        let exercise_tx_id = fixture.assert_broadcast_happy_path(&exercise_request)?;
        mine_blocks(1)?;

        let settlement_input_amount = fixture.settlement_amount(FULL_CONTRACTS)?;
        let settlement_outpoint = OutPoint::new(exercise_tx_id, 1);
        let request = fixture.build_settlement_request(
            settlement_outpoint,
            settlement_input_amount,
            FULL_CONTRACTS,
            false,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_settlement_with_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let exercise_request = fixture.build_exercise_request(
            funding_tx_id,
            collateral_input_amount,
            FULL_CONTRACTS,
            false,
        )?;
        let exercise_tx_id = fixture.assert_broadcast_happy_path(&exercise_request)?;
        mine_blocks(1)?;

        let settlement_input_amount = fixture.settlement_amount(FULL_CONTRACTS)?;
        let settlement_outpoint = OutPoint::new(exercise_tx_id, 1);
        let request = fixture.build_settlement_request(
            settlement_outpoint,
            settlement_input_amount,
            PARTIAL_CONTRACTS,
            true,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_expiry_no_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let request = fixture.build_expiry_request(
            funding_tx_id,
            collateral_input_amount,
            FULL_CONTRACTS,
            false,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_expiry_with_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let request = fixture.build_expiry_request(
            funding_tx_id,
            collateral_input_amount,
            PARTIAL_CONTRACTS,
            true,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_cancellation_no_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let request = fixture.build_cancellation_request(
            funding_tx_id,
            collateral_input_amount,
            FULL_CONTRACTS,
            false,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }

    #[test]
    fn test_options_cancellation_with_change() -> anyhow::Result<()> {
        let mut fixture = RuntimeFixture::setup()?;
        let funding_tx_id = setup_funded_position(&mut fixture, FULL_CONTRACTS)?;
        mine_blocks(1)?;

        let collateral_input_amount = fixture.collateral_amount(FULL_CONTRACTS)?;
        let request = fixture.build_cancellation_request(
            funding_tx_id,
            collateral_input_amount,
            PARTIAL_CONTRACTS,
            true,
        )?;
        let _ = fixture.assert_broadcast_happy_path(&request)?;

        Ok(())
    }
}
