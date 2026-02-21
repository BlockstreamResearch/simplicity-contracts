#![allow(clippy::similar_names)]

use wallet_abi::{
    AmountFilter, AssetFilter, AssetVariant, BlinderVariant, FinalizerSpec, InputBlinder,
    InputIssuance, InputIssuanceKind, InputSchema, InternalKeySource, LockFilter, LockVariant,
    Network, OutputSchema, ProgramError, RuntimeParams, UTXOSource, WalletAbiError,
    WalletSourceFilter, create_p2tr_address,
};

use simplicityhl::elements::{Address, AssetId, Sequence};

use simplicityhl::simplicity::bitcoin::XOnlyPublicKey;

use simplicityhl::elements::secp256k1_zkp::{SECP256K1, SecretKey};
use simplicityhl::{CompiledProgram, TemplateProgram};

pub mod build_arguments;
pub mod build_witness;

use crate::options::build_witness::{OptionBranch, build_options_witness};
pub use build_arguments::OptionsArguments;
use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
use wallet_abi::schema::values::{serialize_arguments, serialize_witness};
use wallet_abi::taproot_pubkey_gen::TaprootPubkeyGen;

pub const OPTIONS_SOURCE: &str = include_str!("source_simf/options.simf");

/// Get the options template program for instantiation.
///
/// # Panics
///
/// Panics if the embedded source fails to compile.
#[must_use]
pub fn get_options_template_program() -> TemplateProgram {
    TemplateProgram::new(OPTIONS_SOURCE)
        .expect("INTERNAL: expected Options Program to compile successfully.")
}

/// Derive P2TR address for an options contract.
///
/// # Errors
///
/// Returns error if program compilation fails.
pub fn get_options_address(
    x_only_public_key: &XOnlyPublicKey,
    program: &CompiledProgram,
    network: Network,
) -> Result<Address, ProgramError> {
    Ok(create_p2tr_address(
        program.commit().cmr(),
        x_only_public_key,
        network.address_params(),
    ))
}

pub struct OptionRuntime {
    runtime: WalletRuntimeConfig,
    args: OptionsArguments,
    resolved_tap: Option<TaprootPubkeyGen>,
    #[allow(dead_code)]
    resolved_option_ids: Option<(AssetId, AssetId)>,
    #[allow(dead_code)]
    resolved_grantor_ids: Option<(AssetId, AssetId)>,
}

impl OptionRuntime {
    /// Create runtime helper from resolved runtime config, arguments, and taproot handle.
    #[must_use]
    pub const fn new(runtime: WalletRuntimeConfig, args: OptionsArguments) -> Self {
        Self {
            runtime,
            args,
            resolved_tap: None,
            resolved_grantor_ids: None,
            resolved_option_ids: None,
        }
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
    pub const fn args(&self) -> &OptionsArguments {
        &self.args
    }

    /// Return taproot handle used by this runtime.
    ///
    /// # Panics
    ///
    /// Before the creation tx
    #[must_use]
    pub fn tap(&self) -> TaprootPubkeyGen {
        self.resolved_tap
            .clone()
            .expect("expected to be called after the creation tx")
    }

    /// Returns a deterministic secret key used as public blinder in tests/examples.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed 32-byte constant cannot be parsed as a secp256k1 secret key.
    #[must_use]
    pub fn get_public_blinder() -> SecretKey {
        SecretKey::from_slice([1; 32].as_ref()).unwrap()
    }

    fn get_base_finalizer_spec(
        &self,
        witness: &OptionBranch,
    ) -> Result<FinalizerSpec, WalletAbiError> {
        Ok(FinalizerSpec::Simf {
            source_simf: OPTIONS_SOURCE.to_string(),
            internal_key: InternalKeySource::default(),
            arguments: serialize_arguments(&self.args.build_simf_arguments())?,
            witness: serialize_witness(&build_options_witness(witness))?,
        })
    }

    /// Build the options contract creation transaction request.
    ///
    /// # Errors
    ///
    /// Returns an error if finalizer argument/witness serialization fails.
    pub fn build_creation_request(&self) -> Result<TxCreateRequest, WalletAbiError> {
        Ok(TxCreateRequest {
            abi_version: TX_CREATE_ABI_VERSION.to_string(),
            request_id: "request-option.create".to_string(),
            network: self.runtime.network,
            params: RuntimeParams {
                inputs: vec![
                    InputSchema {
                        id: "in0".to_string(),
                        utxo_source: UTXOSource::Wallet {
                            filter: WalletSourceFilter {
                                asset: AssetFilter::default(),
                                amount: AmountFilter::default(),
                                lock: LockFilter::default(),
                            },
                        },
                        blinder: InputBlinder::Provided {
                            secret_key: Self::get_public_blinder(),
                        },
                        sequence: Sequence::default(),
                        issuance: Some(InputIssuance {
                            kind: InputIssuanceKind::New,
                            asset_amount_sat: 0,
                            token_amount_sat: 1,
                            entropy: Self::get_public_blinder().secret_bytes(),
                        }),
                        finalizer: FinalizerSpec::default(),
                    },
                    InputSchema {
                        id: "in1".to_string(),
                        utxo_source: UTXOSource::Wallet {
                            filter: WalletSourceFilter {
                                asset: AssetFilter::default(),
                                amount: AmountFilter::default(),
                                lock: LockFilter::default(),
                            },
                        },
                        blinder: InputBlinder::Provided {
                            secret_key: Self::get_public_blinder(),
                        },
                        sequence: Sequence::default(),
                        issuance: Some(InputIssuance {
                            kind: InputIssuanceKind::New,
                            asset_amount_sat: 0,
                            token_amount_sat: 1,
                            entropy: Self::get_public_blinder().secret_bytes(),
                        }),
                        finalizer: FinalizerSpec::default(),
                    },
                ],
                outputs: vec![
                    OutputSchema {
                        id: "out0".to_string(),
                        amount_sat: 1,
                        lock: LockVariant::Finalizer {
                            finalizer: Box::new(
                                self.get_base_finalizer_spec(&OptionBranch::Creation)?,
                            ),
                        },
                        asset: AssetVariant::NewIssuanceToken { input_index: 0 },
                        blinder: BlinderVariant::Provided {
                            pubkey: Self::get_public_blinder().public_key(SECP256K1),
                        },
                    },
                    OutputSchema {
                        id: "out0".to_string(),
                        amount_sat: 1,
                        lock: LockVariant::Finalizer {
                            finalizer: Box::new(
                                self.get_base_finalizer_spec(&OptionBranch::Creation)?,
                            ),
                        },
                        asset: AssetVariant::NewIssuanceToken { input_index: 1 },
                        blinder: BlinderVariant::Provided {
                            pubkey: Self::get_public_blinder().public_key(SECP256K1),
                        },
                    },
                ],
                fee_rate_sat_vb: Some(0.1),
                locktime: None,
            },
            broadcast: true,
        })
    }

    // #[expect(clippy::too_many_lines)]
    // pub async fn build_funding_request(
    //     &self,
    //     creation_tx_id: Txid,
    //     collateral_amount: u64,
    // ) -> Result<TxCreateRequest, WalletAbiError> {
    //     let premium_amount = self.premium_amount(collateral_amount);
    //     let settlement_amount = self.settlement_amount(collateral_amount);
    //
    //     let collateral_outpoint = OutPoint::new(creation_tx_id, 0);
    //     let collateral_tx_out = self.runtime.fetch_tx_out(&collateral_outpoint).await?;
    //     let available_collateral = collateral_tx_out.value.explicit().ok_or_else(|| {
    //         WalletAbiError::InvalidRequest(
    //             "covenant collateral output must be explicit".to_string(),
    //         )
    //     })?;
    //
    //     let premium_outpoint = OutPoint::new(creation_tx_id, 1);
    //     let premium_tx_out = self.runtime.fetch_tx_out(&premium_outpoint).await?;
    //     let available_premium = premium_tx_out.value.explicit().ok_or_else(|| {
    //         WalletAbiError::InvalidRequest("covenant premium output must be explicit".to_string())
    //     })?;
    //
    //     let collateral_change = available_collateral
    //         .checked_sub(collateral_amount)
    //         .ok_or_else(|| {
    //             WalletAbiError::InvalidRequest(
    //                 "requested collateral exceeds covenant collateral balance".to_string(),
    //             )
    //         })?;
    //     let premium_change = available_premium
    //         .checked_sub(premium_amount)
    //         .ok_or_else(|| {
    //             WalletAbiError::InvalidRequest(
    //                 "requested premium exceeds covenant premium balance".to_string(),
    //             )
    //         })?;
    //
    //     let finalizer = self.get_base_finalizer_spec(&OptionOfferBranch::Exercise {
    //         collateral_amount,
    //         is_change_needed: collateral_change != 0,
    //     })?;
    //
    //     let receiver = self.runtime.signer_receive_address()?;
    //
    //     let mut outputs: Vec<OutputSchema> = Vec::new();
    //     if collateral_change != 0 {
    //         outputs.push(OutputSchema {
    //             id: "covenant-collateral-change".to_string(),
    //             amount_sat: collateral_change,
    //             lock: LockVariant::Script {
    //                 script: self.tap.address.script_pubkey(),
    //             },
    //             asset: AssetVariant::AssetId {
    //                 asset_id: self.args.get_collateral_asset_id(),
    //             },
    //             blinder: BlinderVariant::Explicit,
    //         });
    //         outputs.push(OutputSchema {
    //             id: "covenant-premium-change".to_string(),
    //             amount_sat: premium_change,
    //             lock: LockVariant::Script {
    //                 script: self.tap.address.script_pubkey(),
    //             },
    //             asset: AssetVariant::AssetId {
    //                 asset_id: self.args.get_premium_asset_id(),
    //             },
    //             blinder: BlinderVariant::Explicit,
    //         });
    //     }
    //
    //     outputs.extend(vec![
    //         OutputSchema {
    //             id: "covenant-settlement-change".to_string(),
    //             amount_sat: settlement_amount,
    //             lock: LockVariant::Script {
    //                 script: self.tap.address.script_pubkey(),
    //             },
    //             asset: AssetVariant::AssetId {
    //                 asset_id: self.args.get_settlement_asset_id(),
    //             },
    //             blinder: BlinderVariant::Explicit,
    //         },
    //         OutputSchema {
    //             id: "user-collateral-requested".to_string(),
    //             amount_sat: collateral_amount,
    //             lock: LockVariant::Script {
    //                 script: receiver.script_pubkey(),
    //             },
    //             asset: AssetVariant::AssetId {
    //                 asset_id: self.args.get_collateral_asset_id(),
    //             },
    //             blinder: BlinderVariant::Explicit,
    //         },
    //         OutputSchema {
    //             id: "user-premium-requested".to_string(),
    //             amount_sat: premium_amount,
    //             lock: LockVariant::Script {
    //                 script: receiver.script_pubkey(),
    //             },
    //             asset: AssetVariant::AssetId {
    //                 asset_id: self.args.get_premium_asset_id(),
    //             },
    //             blinder: BlinderVariant::Explicit,
    //         },
    //     ]);
    //
    //     Ok(TxCreateRequest {
    //         abi_version: TX_CREATE_ABI_VERSION.to_string(),
    //         request_id: "request-option_offer.exercise".to_string(),
    //         network: self.runtime.network,
    //         params: RuntimeParams {
    //             inputs: vec![
    //                 InputSchema {
    //                     id: "input0".to_string(),
    //                     utxo_source: UTXOSource::Provided {
    //                         outpoint: OutPoint::new(creation_tx_id, 0),
    //                     },
    //                     blinder: InputBlinder::Explicit,
    //                     sequence: Sequence::default(),
    //                     issuance: None,
    //                     finalizer: finalizer.clone(),
    //                 },
    //                 InputSchema {
    //                     id: "input1".to_string(),
    //                     utxo_source: UTXOSource::Provided {
    //                         outpoint: OutPoint::new(creation_tx_id, 1),
    //                     },
    //                     blinder: InputBlinder::Explicit,
    //                     sequence: Sequence::default(),
    //                     issuance: None,
    //                     finalizer,
    //                 },
    //                 InputSchema::new("input2"),
    //             ],
    //             outputs,
    //             fee_rate_sat_vb: Some(0.1),
    //             locktime: None,
    //         },
    //         broadcast: true,
    //     })
    // }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::utils::test_setup::{
        RuntimeFundingAsset, ensure_node_running, fund_runtime, get_esplora_url, wallet_data_root,
    };

    use simplicityhl::elements::Txid;

    use wallet_abi::runtime::WalletRuntimeConfig;
    use wallet_abi::schema::tx_create::TxCreateRequest;

    const COLLATERAL_PER_CONTRACT: u64 = 100;
    const SETTLEMENT_PER_COLLATERAL: u64 = 50;
    const SOME_TIME: u32 = 1_700_000_000;

    fn setup() -> anyhow::Result<OptionRuntime> {
        ensure_node_running()?;

        let runtime_config = WalletRuntimeConfig::build_random(
            Network::LocaltestLiquid,
            &get_esplora_url()?,
            wallet_data_root(),
        )?;

        let collateral_funding = fund_runtime(&runtime_config, RuntimeFundingAsset::Lbtc)?;
        // let _ = fund_runtime(&runtime_config, RuntimeFundingAsset::Lbtc)?;
        let settlement_funding = fund_runtime(&runtime_config, RuntimeFundingAsset::NewAsset)?;

        let args = OptionsArguments::new(
            SOME_TIME,
            SOME_TIME,
            COLLATERAL_PER_CONTRACT,
            SETTLEMENT_PER_COLLATERAL,
            collateral_funding.funded_asset_id,
            settlement_funding.funded_asset_id,
        );

        Ok(OptionRuntime {
            runtime: runtime_config,
            args,
            resolved_tap: None,
            resolved_option_ids: None,
            resolved_grantor_ids: None,
        })
    }

    async fn assert_broadcast_happy_path(
        runtime: &mut OptionRuntime,
        request: &TxCreateRequest,
    ) -> anyhow::Result<Txid> {
        let response = runtime.runtime.process_request(request).await?;

        let Some(tx_info) = response.transaction else {
            panic!("Expected a response broadcast info");
        };

        Ok(tx_info.txid)
    }

    #[tokio::test]
    async fn test_option_creation() -> anyhow::Result<()> {
        let mut fixture = setup()?;
        let request = fixture.build_creation_request()?;
        let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;
        Ok(())
    }

    // #[tokio::test]
    // async fn test_option_offer_exercise() -> anyhow::Result<()> {
    //     let mut fixture = setup()?;
    //     let collateral_amount = 1_000u64;
    //     let request = fixture.build_deposit_request(collateral_amount);
    //     let creation_tx_id = assert_broadcast_happy_path(&mut fixture, &request).await?;
    //     mine_blocks(1)?;
    //
    //     let request = fixture
    //         .build_exercise_request(creation_tx_id, collateral_amount)
    //         .await?;
    //     let _ = assert_broadcast_happy_path(&mut fixture, &request).await?;
    //     Ok(())
    // }
}
