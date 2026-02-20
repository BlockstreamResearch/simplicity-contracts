pub mod build_arguments;
pub mod build_witness;

pub use build_arguments::OptionOfferArguments;

use crate::option_offer::build_witness::{OptionOfferBranch, build_option_offer_witness};

use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
use wallet_abi::schema::values::{serialize_arguments, serialize_witness};
use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;
use wallet_abi::{
    AssetVariant, BlinderVariant, FinalizerSpec, InputBlinder, InputSchema, LockVariant, Network,
    OutputSchema, ProgramError, RuntimeParams, UTXOSource, WalletAbiError, create_p2tr_address,
    load_program,
};

use simplicityhl::elements::{Address, LockTime, OutPoint, Sequence, Txid};

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;

use simplicityhl::{CompiledProgram, TemplateProgram};

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

pub struct OptionOfferRuntime {
    runtime: WalletRuntimeConfig,
    args: OptionOfferArguments,
    tap: TaprootPubkeyGen,
}

impl OptionOfferRuntime {
    /// Create runtime helper from resolved runtime config, arguments, and taproot handle.
    #[must_use]
    pub const fn new(
        runtime: WalletRuntimeConfig,
        args: OptionOfferArguments,
        tap: TaprootPubkeyGen,
    ) -> Self {
        Self { runtime, args, tap }
    }

    /// Return immutable access to underlying wallet runtime.
    #[must_use]
    pub const fn runtime(&self) -> &WalletRuntimeConfig {
        &self.runtime
    }

    /// Return mutable access to underlying wallet runtime.
    pub const fn runtime_mut(&mut self) -> &mut WalletRuntimeConfig {
        &mut self.runtime
    }

    /// Return option-offer arguments used by this runtime.
    #[must_use]
    pub const fn args(&self) -> &OptionOfferArguments {
        &self.args
    }

    /// Return taproot handle used by this runtime.
    #[must_use]
    pub const fn tap(&self) -> &TaprootPubkeyGen {
        &self.tap
    }

    /// Compute premium amount from collateral amount.
    ///
    /// # Panics
    ///
    /// Panics if multiplication overflows `u64`.
    pub const fn premium_amount(&self, collateral_amount: u64) -> u64 {
        collateral_amount
            .checked_mul(self.args.premium_per_collateral())
            .expect("premium amount overflow")
    }

    /// Compute settlement amount from collateral amount.
    ///
    /// # Panics
    ///
    /// Panics if multiplication overflows `u64`.
    pub const fn settlement_amount(&self, collateral_amount: u64) -> u64 {
        collateral_amount
            .checked_mul(self.args.collateral_per_contract())
            .expect("settlement amount overflow")
    }

    fn get_base_finalizer_spec(
        &self,
        witness: &OptionOfferBranch,
    ) -> Result<FinalizerSpec, WalletAbiError> {
        Ok(FinalizerSpec::Simf {
            source_simf: OPTION_OFFER_SOURCE.to_string(),
            internal_key: Box::new(self.tap.clone()),
            arguments: serialize_arguments(&self.args.build_simf_arguments())?,
            witness: serialize_witness(&build_option_offer_witness(
                witness,
                self.runtime.signer_x_only_public_key()?,
            ))?,
        })
    }

    /// Build the initial deposit transaction request.
    ///
    /// This constructor is currently infallible and always returns `Ok`.
    ///
    /// # Panics
    ///
    /// Panics if premium amount multiplication overflows `u64`.
    pub fn build_deposit_request(&self, collateral_deposit_amount: u64) -> TxCreateRequest {
        let premium_deposit_amount = self.premium_amount(collateral_deposit_amount);

        TxCreateRequest {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: "request-option_offer.deposit".to_string(),
            network: self.runtime.network,
            params: RuntimeParams {
                inputs: vec![InputSchema::new("input0"), InputSchema::new("input1")],
                outputs: vec![
                    OutputSchema::from_script(
                        "out0",
                        self.args.get_collateral_asset_id(),
                        collateral_deposit_amount,
                        self.tap.address.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out1",
                        self.args.get_premium_asset_id(),
                        premium_deposit_amount,
                        self.tap.address.script_pubkey(),
                    ),
                ],
                fee_rate_sat_vb: Some(0.1),
                locktime: None,
            },
            broadcast: true,
        }
    }

    /// Build the exercise transaction request.
    ///
    /// # Errors
    ///
    /// Returns an error if covenant inputs are not explicit or if requested amounts exceed
    /// available covenant balances.
    ///
    /// # Panics
    ///
    /// Panics if premium/settlement amount multiplication overflows `u64`.
    #[expect(clippy::too_many_lines)]
    pub async fn build_exercise_request(
        &self,
        creation_tx_id: Txid,
        collateral_amount: u64,
    ) -> Result<TxCreateRequest, WalletAbiError> {
        let premium_amount = self.premium_amount(collateral_amount);
        let settlement_amount = self.settlement_amount(collateral_amount);

        let collateral_outpoint = OutPoint::new(creation_tx_id, 0);
        let collateral_tx_out = self.runtime.fetch_tx_out(&collateral_outpoint).await?;
        let available_collateral = collateral_tx_out.value.explicit().ok_or_else(|| {
            WalletAbiError::InvalidRequest(
                "covenant collateral output must be explicit".to_string(),
            )
        })?;

        let premium_outpoint = OutPoint::new(creation_tx_id, 1);
        let premium_tx_out = self.runtime.fetch_tx_out(&premium_outpoint).await?;
        let available_premium = premium_tx_out.value.explicit().ok_or_else(|| {
            WalletAbiError::InvalidRequest("covenant premium output must be explicit".to_string())
        })?;

        let collateral_change = available_collateral
            .checked_sub(collateral_amount)
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(
                    "requested collateral exceeds covenant collateral balance".to_string(),
                )
            })?;
        let premium_change = available_premium
            .checked_sub(premium_amount)
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(
                    "requested premium exceeds covenant premium balance".to_string(),
                )
            })?;

        let finalizer = self.get_base_finalizer_spec(&OptionOfferBranch::Exercise {
            collateral_amount,
            is_change_needed: collateral_change != 0,
        })?;

        let receiver = self.runtime.signer_receive_address()?;

        let mut outputs: Vec<OutputSchema> = Vec::new();
        if collateral_change != 0 {
            outputs.push(OutputSchema {
                id: "covenant-collateral-change".to_string(),
                amount_sat: collateral_change,
                lock: LockVariant::Script {
                    script: self.tap.address.script_pubkey(),
                },
                asset: AssetVariant::AssetId {
                    asset_id: self.args.get_collateral_asset_id(),
                },
                blinder: BlinderVariant::Explicit,
            });
            outputs.push(OutputSchema {
                id: "covenant-premium-change".to_string(),
                amount_sat: premium_change,
                lock: LockVariant::Script {
                    script: self.tap.address.script_pubkey(),
                },
                asset: AssetVariant::AssetId {
                    asset_id: self.args.get_premium_asset_id(),
                },
                blinder: BlinderVariant::Explicit,
            });
        }

        outputs.extend(vec![
            OutputSchema {
                id: "covenant-settlement-change".to_string(),
                amount_sat: settlement_amount,
                lock: LockVariant::Script {
                    script: self.tap.address.script_pubkey(),
                },
                asset: AssetVariant::AssetId {
                    asset_id: self.args.get_settlement_asset_id(),
                },
                blinder: BlinderVariant::Explicit,
            },
            OutputSchema {
                id: "user-collateral-requested".to_string(),
                amount_sat: collateral_amount,
                lock: LockVariant::Script {
                    script: receiver.script_pubkey(),
                },
                asset: AssetVariant::AssetId {
                    asset_id: self.args.get_collateral_asset_id(),
                },
                blinder: BlinderVariant::Explicit,
            },
            OutputSchema {
                id: "user-premium-requested".to_string(),
                amount_sat: premium_amount,
                lock: LockVariant::Script {
                    script: receiver.script_pubkey(),
                },
                asset: AssetVariant::AssetId {
                    asset_id: self.args.get_premium_asset_id(),
                },
                blinder: BlinderVariant::Explicit,
            },
        ]);

        Ok(TxCreateRequest {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: "request-option_offer.exercise".to_string(),
            network: self.runtime.network,
            params: RuntimeParams {
                inputs: vec![
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
                fee_rate_sat_vb: Some(0.1),
                locktime: None,
            },
            broadcast: true,
        })
    }

    /// Build the withdraw transaction request for an explicit covenant settlement outpoint.
    ///
    /// Settlement output index is not fixed. Resolve the concrete settlement outpoint from the
    /// actual exercise transaction outputs (exercise with change can shift `vout` positions).
    ///
    /// # Errors
    ///
    /// Returns an error if runtime-derived metadata cannot be serialized.
    pub fn build_withdraw_request_for_outpoint(
        &self,
        settlement_outpoint: OutPoint,
        settlement_amount: u64,
    ) -> Result<TxCreateRequest, WalletAbiError> {
        let finalizer = self.get_base_finalizer_spec(&OptionOfferBranch::Withdraw)?;

        let receiver = self.runtime.signer_receive_address()?;

        Ok(TxCreateRequest {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: "request-option_offer.withdraw".to_string(),
            network: self.runtime.network,
            params: RuntimeParams {
                inputs: vec![InputSchema {
                    id: "input0".to_string(),
                    utxo_source: UTXOSource::Provided {
                        outpoint: settlement_outpoint,
                    },
                    blinder: InputBlinder::Explicit,
                    sequence: Sequence::default(),
                    issuance: None,
                    finalizer,
                }],
                outputs: vec![OutputSchema::from_script(
                    "out0",
                    self.args.get_settlement_asset_id(),
                    settlement_amount,
                    receiver.script_pubkey(),
                )],
                fee_rate_sat_vb: Some(0.1),
                locktime: None,
            },
            broadcast: true,
        })
    }

    /// Build the expiry transaction request.
    ///
    /// # Errors
    ///
    /// Returns an error if locktime conversion or runtime metadata serialization fails.
    pub fn build_expiry_request(
        &self,
        creation_tx_id: Txid,
        collateral_amount: u64,
        premium_amount: u64,
    ) -> Result<TxCreateRequest, WalletAbiError> {
        let finalizer = self.get_base_finalizer_spec(&OptionOfferBranch::Expiry)?;

        let receiver = self.runtime.signer_receive_address()?;

        Ok(TxCreateRequest {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: "request-option_offer.expiry".to_string(),
            network: self.runtime.network,
            params: RuntimeParams {
                inputs: vec![
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
                outputs: vec![
                    OutputSchema::from_script(
                        "out0",
                        self.args.get_collateral_asset_id(),
                        collateral_amount,
                        receiver.script_pubkey(),
                    ),
                    OutputSchema::from_script(
                        "out1",
                        self.args.get_premium_asset_id(),
                        premium_amount,
                        receiver.script_pubkey(),
                    ),
                ],
                fee_rate_sat_vb: Some(0.1),
                locktime: Some(LockTime::from_time(self.args.expiry_time())?),
            },
            broadcast: true,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::utils::test_setup::{
        RuntimeFundingAsset, ensure_node_running, fund_runtime, get_esplora_url, mine_blocks,
        wallet_data_root,
    };

    use anyhow::anyhow;
    use simplicityhl::elements::{OutPoint, Txid};

    use wallet_abi::runtime::WalletRuntimeConfig;
    use wallet_abi::schema::tx_create::TxCreateRequest;
    use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;

    const COLLATERAL_PER_CONTRACT: u64 = 100;
    const PREMIUM_PER_COLLATERAL: u64 = 10;
    const EXPIRY_TIME: u32 = 1_700_000_000;

    fn setup() -> anyhow::Result<OptionOfferRuntime> {
        ensure_node_running()?;

        let runtime_config = WalletRuntimeConfig::build_random(
            Network::LocaltestLiquid,
            &get_esplora_url()?,
            wallet_data_root(),
        )?;

        let collateral_funding = fund_runtime(&runtime_config, RuntimeFundingAsset::Lbtc)?;
        let premium_funding = fund_runtime(&runtime_config, RuntimeFundingAsset::NewAsset)?;
        let settlement_funding = fund_runtime(&runtime_config, RuntimeFundingAsset::NewAsset)?;

        let args = OptionOfferArguments::new(
            collateral_funding.funded_asset_id,
            premium_funding.funded_asset_id,
            settlement_funding.funded_asset_id,
            COLLATERAL_PER_CONTRACT,
            PREMIUM_PER_COLLATERAL,
            EXPIRY_TIME,
            runtime_config.signer_x_only_public_key()?.serialize(),
        );
        let tap =
            TaprootPubkeyGen::from(&args, Network::LocaltestLiquid, &get_option_offer_address)?;

        Ok(OptionOfferRuntime {
            runtime: runtime_config,
            args,
            tap,
        })
    }

    async fn assert_broadcast_happy_path(
        runtime: &mut OptionOfferRuntime,
        request: &TxCreateRequest,
    ) -> anyhow::Result<Txid> {
        let response = runtime.runtime.process_request(request).await?;

        let Some(tx_info) = response.transaction else {
            panic!("Expected a response broadcast info");
        };

        Ok(tx_info.txid)
    }

    async fn find_settlement_outpoint(
        runtime: &OptionOfferRuntime,
        exercise_tx_id: Txid,
    ) -> anyhow::Result<(OutPoint, u64)> {
        let tx = {
            let inner_esplora = runtime.runtime.esplora.lock().await;
            inner_esplora.get_transaction(exercise_tx_id).await?
        };

        let covenant_script = runtime.tap.address.script_pubkey();
        let settlement_asset_id = runtime.args.get_settlement_asset_id();

        let Some((vout, value_sat)) = tx.output.iter().enumerate().find_map(|(vout, tx_out)| {
            if tx_out.script_pubkey != covenant_script {
                return None;
            }

            let asset = tx_out.asset.explicit()?;
            if asset != settlement_asset_id {
                return None;
            }

            let value_sat = tx_out.value.explicit()?;
            Some((vout, value_sat))
        }) else {
            return Err(anyhow!(
                "exercise tx {exercise_tx_id} does not contain explicit settlement output for covenant script"
            ));
        };

        Ok((
            OutPoint::new(
                exercise_tx_id,
                u32::try_from(vout).map_err(|_| anyhow!("exercise vout index overflow"))?,
            ),
            value_sat,
        ))
    }

    #[tokio::test]
    async fn test_option_offer_deposit() -> anyhow::Result<()> {
        let mut fixture = setup()?;
        let request = fixture.build_deposit_request(1_000u64);
        let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_option_offer_exercise() -> anyhow::Result<()> {
        let mut fixture = setup()?;
        let collateral_amount = 1_000u64;
        let request = fixture.build_deposit_request(collateral_amount);
        let creation_tx_id = assert_broadcast_happy_path(&mut fixture, &request).await?;
        mine_blocks(1)?;

        let request = fixture
            .build_exercise_request(creation_tx_id, collateral_amount)
            .await?;
        let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_option_offer_exercise_with_change() -> anyhow::Result<()> {
        let mut fixture = setup()?;
        let collateral_amount = 1_000u64;
        let request = fixture.build_deposit_request(collateral_amount);
        let creation_tx_id = assert_broadcast_happy_path(&mut fixture, &request).await?;
        mine_blocks(1)?;

        let request = fixture
            .build_exercise_request(creation_tx_id, collateral_amount - 500)
            .await?;
        let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_option_offer_withdraw() -> anyhow::Result<()> {
        let mut fixture = setup()?;
        let collateral_amount = 1_000u64;
        let exercise_collateral_amount = collateral_amount - 500;
        let expected_settlement_amount = fixture.settlement_amount(exercise_collateral_amount);

        let deposit_request = fixture.build_deposit_request(collateral_amount);
        let creation_tx_id = assert_broadcast_happy_path(&mut fixture, &deposit_request).await?;
        mine_blocks(1)?;

        let exercise_request = fixture
            .build_exercise_request(creation_tx_id, exercise_collateral_amount)
            .await?;
        let exercise_tx_id = assert_broadcast_happy_path(&mut fixture, &exercise_request).await?;
        mine_blocks(1)?;

        let (settlement_outpoint, settlement_amount) =
            find_settlement_outpoint(&fixture, exercise_tx_id).await?;
        assert_eq!(settlement_amount, expected_settlement_amount);

        let request =
            fixture.build_withdraw_request_for_outpoint(settlement_outpoint, settlement_amount)?;
        let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_option_offer_expiry() -> anyhow::Result<()> {
        let mut fixture = setup()?;
        let collateral_amount = 1_000u64;
        let premium_amount = fixture.premium_amount(collateral_amount);

        let deposit_request = fixture.build_deposit_request(collateral_amount);
        let creation_tx_id = assert_broadcast_happy_path(&mut fixture, &deposit_request).await?;
        mine_blocks(1)?;

        let request =
            fixture.build_expiry_request(creation_tx_id, collateral_amount, premium_amount)?;
        let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;

        Ok(())
    }
}
