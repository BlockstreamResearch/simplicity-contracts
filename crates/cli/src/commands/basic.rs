use crate::modules::store::Store;

use crate::modules::utils::execute_request;

use anyhow::{Context, anyhow};

use clap::Subcommand;

use simplicityhl::elements::encode;
use simplicityhl::elements::hashes::sha256::Midstate;
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::{Address, AssetId, Sequence, Transaction};

use wallet_abi::runtime::WalletRuntimeConfig;
use wallet_abi::schema::tx_create::{TX_CREATE_ABI_VERSION, TxCreateRequest};
use wallet_abi::taproot_pubkey_gen::get_random_seed;
use wallet_abi::{
    AmountFilter, AssetFilter, AssetVariant, BlinderVariant, FinalizerSpec, InputBlinder,
    InputIssuance, InputIssuanceKind, InputSchema, LockFilter, LockVariant, OutputSchema,
    RuntimeParams, UTXOSource, WalletSourceFilter, get_new_asset_entropy,
};

fn decode_transaction(tx_hex: &str) -> anyhow::Result<Transaction> {
    let tx_bytes = hex::decode(tx_hex).context("failed to decode transaction hex")?;
    encode::deserialize(&tx_bytes).context("failed to decode transaction bytes")
}

#[derive(Subcommand, Debug)]
pub enum Basic {
    /// Print a deterministic address
    Address,
    /// Print wallet balances grouped by asset id
    Balance,
    /// Build tx transferring an asset to recipient
    Transfer {
        /// Recipient Liquid address
        #[arg(long = "to-address")]
        to_address: Address,
        /// Asset to send, LBTC by default
        #[arg(long = "asset")]
        asset: Option<AssetId>,
        /// Amount to send to the recipient in satoshis
        #[arg(long = "send-sats")]
        amount_to_send: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx splitting funds into multiple outputs.
    Split {
        /// Asset to split, LBTC by default
        #[arg(long = "asset")]
        asset: Option<AssetId>,
        /// Number of UTXOs to split the UTXO into
        #[arg(long = "split-parts")]
        split_parts: u64,
        /// Value of single split
        #[arg(long = "part-amount")]
        part_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx issuing an asset
    IssueAsset {
        /// Asset name (this will be stored in the CLI's database only, so it will be not shown on the Esplora UI)
        #[arg(long = "asset-name")]
        asset_name: String,
        /// Amount to issue of the asset in its satoshi units
        #[arg(long = "issue-sats")]
        issue_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Reissue an asset
    ReissueAsset {
        /// Asset name (this will be stored in the CLI's database only, so it will be not shown on the Esplora UI)
        #[arg(long = "asset-name")]
        asset_name: String,
        /// Amount to reissue of the asset in its satoshi units
        #[arg(long = "reissue-sats")]
        reissue_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

impl Basic {
    /// Handle basic CLI subcommand execution.
    ///
    /// # Errors
    /// Returns error if the subcommand operation fails.
    ///
    /// # Panics
    /// Panics if asset entropy conversion fails.
    #[expect(clippy::too_many_lines)]
    pub async fn handle(&self, runtime: WalletRuntimeConfig) -> anyhow::Result<()> {
        let mut runtime = runtime;

        match self {
            Self::Address => {
                let receiver_address = runtime.signer_receive_address()?;

                let signer_address = runtime.signer_x_only_public_key()?;

                println!("Receiver Address: {receiver_address}");
                println!("Signer X Only Public Key: {signer_address}");

                Ok(())
            }
            Self::Balance => {
                runtime.sync_wallet().await?;

                let mut balances: std::collections::BTreeMap<AssetId, u64> =
                    std::collections::BTreeMap::new();
                for utxo in runtime.wollet.utxos()? {
                    let entry = balances.entry(utxo.unblinded.asset).or_insert(0);
                    *entry = entry
                        .checked_add(utxo.unblinded.value)
                        .ok_or_else(|| anyhow!("balance overflow while summing wallet UTXOs"))?;
                }

                if balances.is_empty() {
                    println!("No available assets");
                    return Ok(());
                }

                for (asset_id, amount_sat) in balances {
                    println!("{asset_id}: {amount_sat}");
                }

                Ok(())
            }
            Self::Transfer {
                asset,
                to_address,
                amount_to_send,
                broadcast,
            } => {
                let asset_to_send = asset.unwrap_or(*runtime.network.policy_asset());

                let blinder = to_address
                    .blinding_pubkey
                    .map_or(BlinderVariant::Explicit, |blinder| {
                        BlinderVariant::Provided { pubkey: blinder }
                    });

                let request = TxCreateRequest {
                    abi_version: TX_CREATE_ABI_VERSION.to_string(),
                    request_id: "request-basic.transfer".to_string(),
                    network: runtime.network,
                    params: RuntimeParams {
                        inputs: vec![InputSchema {
                            id: "input0".to_string(),
                            utxo_source: UTXOSource::Wallet {
                                filter: WalletSourceFilter {
                                    asset: AssetFilter::Exact {
                                        asset_id: asset_to_send,
                                    },
                                    amount: AmountFilter::default(),
                                    lock: LockFilter::default(),
                                },
                            },
                            blinder: InputBlinder::default(),
                            sequence: Sequence::default(),
                            issuance: None,
                            finalizer: FinalizerSpec::default(),
                        }],
                        outputs: vec![OutputSchema {
                            id: "to-recipient".to_string(),
                            amount_sat: *amount_to_send,
                            lock: LockVariant::Script {
                                script: to_address.script_pubkey(),
                            },
                            asset: AssetVariant::AssetId {
                                asset_id: asset_to_send,
                            },
                            blinder,
                        }],
                        fee_rate_sat_vb: Some(0.1),
                        locktime: None,
                    },
                    broadcast: *broadcast,
                };

                let _ = execute_request(&mut runtime, request).await?;

                Ok(())
            }
            Self::Split {
                asset,
                split_parts,
                part_amount,
                broadcast,
            } => {
                let asset_to_split = asset.unwrap_or(*runtime.network.policy_asset());

                if *split_parts == 0 {
                    return Err(anyhow!("split-parts must be > 0"));
                }

                let signer_address = runtime.signer_receive_address()?;

                let mut outputs = Vec::new();
                for output_index in 0..*split_parts {
                    outputs.push(OutputSchema {
                        id: format!("out{output_index}"),
                        amount_sat: *part_amount,
                        lock: LockVariant::Script {
                            script: signer_address.script_pubkey(),
                        },
                        asset: AssetVariant::AssetId {
                            asset_id: asset_to_split,
                        },
                        blinder: BlinderVariant::Wallet,
                    });
                }

                let request = TxCreateRequest {
                    abi_version: TX_CREATE_ABI_VERSION.to_string(),
                    request_id: "request-basic.split_native".to_string(),
                    network: runtime.network,
                    params: RuntimeParams {
                        inputs: vec![InputSchema {
                            id: "input0".to_string(),
                            utxo_source: UTXOSource::Wallet {
                                filter: WalletSourceFilter {
                                    asset: AssetFilter::Exact {
                                        asset_id: asset_to_split,
                                    },
                                    amount: AmountFilter::default(),
                                    lock: LockFilter::default(),
                                },
                            },
                            blinder: InputBlinder::default(),
                            sequence: Sequence::default(),
                            issuance: None,
                            finalizer: FinalizerSpec::default(),
                        }],
                        outputs,
                        fee_rate_sat_vb: Some(0.1),
                        locktime: None,
                    },
                    broadcast: *broadcast,
                };

                let _ = execute_request(&mut runtime, request).await?;

                Ok(())
            }
            Self::IssueAsset {
                asset_name,
                issue_amount,
                broadcast,
            } => {
                let store = Store::load()?;

                if store.store.get(asset_name)?.is_some() {
                    return Err(anyhow!("Asset name already exists"));
                }
                let issuance_entropy = get_random_seed();

                let policy_asset = *runtime.network.policy_asset();
                let signer_script = runtime.signer_receive_address()?.script_pubkey();

                let request = TxCreateRequest {
                    abi_version: TX_CREATE_ABI_VERSION.to_string(),
                    request_id: "request-basic.issue_asset".to_string(),
                    network: runtime.network,
                    params: RuntimeParams {
                        inputs: vec![InputSchema {
                            id: "in0".to_string(),
                            utxo_source: UTXOSource::Wallet {
                                filter: WalletSourceFilter {
                                    // TODO: really?
                                    asset: AssetFilter::Exact {
                                        asset_id: policy_asset,
                                    },
                                    amount: AmountFilter::default(),
                                    lock: LockFilter::default(),
                                },
                            },
                            blinder: InputBlinder::default(),
                            sequence: Sequence::default(),
                            issuance: Some(InputIssuance {
                                kind: InputIssuanceKind::New,
                                asset_amount_sat: *issue_amount,
                                token_amount_sat: 1,
                                entropy: issuance_entropy,
                            }),
                            finalizer: FinalizerSpec::default(),
                        }],
                        outputs: vec![
                            OutputSchema {
                                id: "out0".to_string(),
                                amount_sat: 1,
                                lock: LockVariant::Script {
                                    script: signer_script.clone(),
                                },
                                asset: AssetVariant::NewIssuanceToken { input_index: 0 },
                                blinder: BlinderVariant::Wallet,
                            },
                            OutputSchema {
                                id: "out1".to_string(),
                                amount_sat: *issue_amount,
                                lock: LockVariant::Script {
                                    script: signer_script,
                                },
                                asset: AssetVariant::NewIssuanceAsset { input_index: 0 },
                                blinder: BlinderVariant::Wallet,
                            },
                        ],
                        fee_rate_sat_vb: Some(0.1),
                        locktime: None,
                    },
                    broadcast: *broadcast,
                };

                let tx_info = execute_request(&mut runtime, request).await?;

                let tx = decode_transaction(&tx_info.tx_hex)?;
                let input = tx
                    .input
                    .first()
                    .ok_or_else(|| anyhow!("issued transaction is missing input[0]"))?;
                let (asset_id, reissuance_asset_id) = input.issuance_ids();

                let asset_entropy = get_new_asset_entropy(&input.previous_output, issuance_entropy);

                println!(
                    "Asset id: {asset_id}, Reissuance asset: {reissuance_asset_id}, Asset entropy: {}",
                    asset_entropy.to_hex()
                );

                store
                    .store
                    .insert(asset_name, &asset_entropy.to_byte_array())?;

                store
                    .store
                    .insert(format!("re-{asset_name}"), reissuance_asset_id.serialize())?;

                Ok(())
            }
            Self::ReissueAsset {
                asset_name,
                reissue_amount,
                broadcast,
            } => {
                let store = Store::load()?;

                let Some(asset_entropy) = store.store.get(asset_name)? else {
                    return Err(anyhow!("Asset name not found"));
                };
                let Some(reissue_token_id) = store.store.get(format!("re-{asset_name}"))? else {
                    return Err(anyhow!("Asset name not found"));
                };
                let asset_entropy = Midstate::from_slice(&asset_entropy)?;
                let reissue_token_id = AssetId::from_slice(&reissue_token_id)?;

                let signer_script = runtime.signer_receive_address()?.script_pubkey();

                let request = TxCreateRequest {
                    abi_version: TX_CREATE_ABI_VERSION.to_string(),
                    request_id: "request-basic.reissue_asset".to_string(),
                    network: runtime.network,
                    params: RuntimeParams {
                        inputs: vec![InputSchema {
                            id: "input0".to_string(),
                            utxo_source: UTXOSource::Wallet {
                                filter: WalletSourceFilter {
                                    asset: AssetFilter::Exact {
                                        asset_id: reissue_token_id,
                                    },
                                    amount: AmountFilter::Min { satoshi: 1 },
                                    lock: LockFilter::None,
                                },
                            },
                            blinder: InputBlinder::default(),
                            sequence: Sequence::default(),
                            issuance: Some(InputIssuance {
                                kind: InputIssuanceKind::Reissue,
                                asset_amount_sat: *reissue_amount,
                                token_amount_sat: 0,
                                entropy: asset_entropy.to_byte_array(),
                            }),
                            finalizer: FinalizerSpec::default(),
                        }],
                        outputs: vec![
                            OutputSchema {
                                id: "out0".to_string(),
                                amount_sat: 1,
                                lock: LockVariant::Script {
                                    script: signer_script.clone(),
                                },
                                asset: AssetVariant::AssetId {
                                    asset_id: reissue_token_id,
                                },
                                blinder: BlinderVariant::Wallet,
                            },
                            OutputSchema {
                                id: "out1".to_string(),
                                amount_sat: *reissue_amount,
                                lock: LockVariant::Script {
                                    script: signer_script,
                                },
                                asset: AssetVariant::ReIssuanceAsset { input_index: 0 },
                                blinder: BlinderVariant::Wallet,
                            },
                        ],
                        fee_rate_sat_vb: Some(0.1),
                        locktime: None,
                    },
                    broadcast: *broadcast,
                };

                let _ = execute_request(&mut runtime, request).await?;

                Ok(())
            }
        }
    }
}
