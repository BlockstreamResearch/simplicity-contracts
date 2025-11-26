use anyhow::anyhow;

use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;
use clap::Subcommand;
use contracts_adapter::basic;
use contracts_adapter::basic::{IssueAssetResponse, ReissueAssetResponse};
use simplicityhl::elements::hashes::sha256;
use simplicityhl::simplicity::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::elements::{Address, AddressParams, OutPoint};
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, broadcast_tx, derive_public_blinder_key,
    get_p2pk_address,
};

#[derive(Subcommand, Debug)]
pub enum Basic {
    /// Print a deterministic Liquid testnet address derived from index
    Address {
        /// Address index (0-based)
        index: u32,
    },
    /// Build unsigned tx hex transferring LBTC (explicit) to recipient
    TransferNative {
        /// Transaction id (hex) and output index (vout) of the UTXO you will spend
        #[arg(long = "utxo")]
        utxo_outpoint: OutPoint,
        /// Recipient address (Liquid testnet bech32m)
        #[arg(long = "to-address")]
        to_address: Address,
        /// Amount to send to the recipient in satoshis (LBTC)
        #[arg(long = "send-sats")]
        amount_to_send: u64,
        /// Miner fee in satoshis (LBTC). A separate fee output is added.
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account index to use for change address
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx splitting one LBTC UTXO into two recipients
    SplitNative {
        /// Transaction id (hex) and output index (vout) of the UTXO you will spend
        #[arg(long = "utxo")]
        utxo_outpoint: OutPoint,
        /// Recipient address (Liquid testnet bech32m)
        #[arg(long = "recipient-address")]
        recipient_address: Address,
        /// Amount to send to the recipient in satoshis (LBTC)
        #[arg(long = "send-sats", default_value_t = 1000)]
        amount: u64,
        /// Miner fee in satoshis (LBTC). A separate fee output is added.
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account index to use for signing input
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx splitting one LBTC UTXO into three recipients
    SplitNativeThree {
        /// Transaction id (hex) and output index (vout) of the UTXO you will spend
        #[arg(long = "utxo")]
        utxo_outpoint: OutPoint,
        /// Recipient address (Liquid testnet bech32m)
        #[arg(long = "recipient-address")]
        recipient_address: Address,
        /// Amount to send to the recipient in satoshis (LBTC)
        #[arg(long = "send-sats", default_value_t = 1000)]
        amount: u64,
        /// Miner fee in satoshis (LBTC). A separate fee output is added.
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account index to use for signing input
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    #[command(about = "Splits given utxo into given amount of outs")]
    SplitNativeAny {
        /// Parts on which utxo would be split
        #[arg(long = "split-parts")]
        split_parts: u64,
        /// Fee utxo
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        #[arg(long = "fee-amount", default_value_t = 500)]
        fee_amount: u64,
        /// Account index to use for change address
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build unsigned tx hex transferring an asset UTXO to recipient (LBTC UTXO pays fees)
    TransferAsset {
        /// Transaction id (hex) and output index (vout) of the ASSET UTXO you will spend
        #[arg(long = "asset-utxo")]
        asset_utxo_outpoint: OutPoint,
        /// Transaction id (hex) and output index (vout) of the LBTC UTXO used to pay fees
        #[arg(long = "fee-utxo")]
        fee_utxo_outpoint: OutPoint,
        /// Recipient address (Liquid testnet bech32m)
        #[arg(long = "to-address")]
        to_address: Address,
        /// Amount to send of the asset in its satoshi units
        #[arg(long = "send-sats")]
        send_amount: u64,
        /// Miner fee in satoshis (LBTC). A separate fee output is added.
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account index to use for change address
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx issuing an asset
    IssueAsset {
        /// Transaction id (hex) and output index (vout) of the LBTC UTXO used to pay fees and issue the asset
        #[arg(long = "fee-utxo")]
        fee_utxo_outpoint: OutPoint,
        /// Asset name
        #[arg(long = "asset-name")]
        asset_name: String,
        /// Amount to issue of the asset in its satoshi units
        #[arg(long = "issue-sats")]
        issue_amount: u64,
        /// Miner fee in satoshis (LBTC). A separate fee output is added.
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account index to use for change address
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Reissue an asset
    ReissueAsset {
        /// Transaction id (hex) and output index (vout) of the REISSUANCE ASSET UTXO you will spend
        #[arg(long = "reissue-asset-utxo")]
        reissue_asset_outpoint: OutPoint,
        /// Transaction id (hex) and output index (vout) of the LBTC UTXO used to pay fees and reissue the asset
        #[arg(long = "fee-utxo")]
        fee_utxo_outpoint: OutPoint,
        /// Asset name
        #[arg(long = "asset-name")]
        asset_name: String,
        /// Amount to reissue of the asset in its satoshi units
        #[arg(long = "reissue-sats")]
        reissue_amount: u64,
        /// Miner fee in satoshis (LBTC). A separate fee output is added.
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account index to use for change address
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

impl Basic {
    #[allow(unused)]
    pub fn handle(&self) -> anyhow::Result<()> {
        match self {
            Basic::Address { index } => {
                let keypair = derive_keypair(*index);

                let public_key = keypair.x_only_public_key().0;
                let address = get_p2pk_address(&public_key, &AddressParams::LIQUID_TESTNET)?;

                println!("X Only Public Key: {}", public_key);
                println!("P2PK Address: {}", address);

                Ok(())
            }
            Basic::TransferNative {
                utxo_outpoint,
                to_address,
                amount_to_send,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let tx = contracts_adapter::basic::transfer_native(
                    &keypair,
                    *utxo_outpoint,
                    to_address,
                    *amount_to_send,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Basic::SplitNative {
                utxo_outpoint,
                recipient_address,
                amount,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let tx = contracts_adapter::basic::split_native(
                    &keypair,
                    *utxo_outpoint,
                    recipient_address,
                    *amount,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Basic::SplitNativeThree {
                utxo_outpoint,
                recipient_address,
                amount,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let tx = contracts_adapter::basic::split_native_three(
                    &keypair,
                    *utxo_outpoint,
                    recipient_address,
                    *amount,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Basic::SplitNativeAny {
                split_parts: split_amount,
                fee_utxo,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let transaction = basic::split_native_any(
                    keypair,
                    *fee_utxo,
                    *split_amount,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&transaction)?),
                    false => println!("{}", transaction.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Basic::TransferAsset {
                asset_utxo_outpoint,
                fee_utxo_outpoint,
                to_address,
                send_amount,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let tx = contracts_adapter::basic::transfer_asset(
                    &keypair,
                    *asset_utxo_outpoint,
                    *fee_utxo_outpoint,
                    to_address,
                    *send_amount,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Basic::IssueAsset {
                fee_utxo_outpoint,
                asset_name,
                issue_amount,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                if store.store.get(asset_name)?.is_some() {
                    return Err(anyhow!("Asset name already exists"));
                };

                let keypair = derive_keypair(*account_index);
                let blinding_key = derive_public_blinder_key();

                let IssueAssetResponse {
                    tx,
                    asset_id,
                    reissuance_asset_id,
                    asset_entropy,
                } = contracts_adapter::basic::issue_asset(
                    &keypair,
                    &blinding_key,
                    *fee_utxo_outpoint,
                    *issue_amount,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                println!(
                    "Asset id: {asset_id}, Reissuance asset: {reissuance_asset_id}, Asset entropy: {}",
                    asset_entropy
                );

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                store.store.insert(asset_name, asset_entropy.as_bytes())?;

                Ok(())
            }
            Basic::ReissueAsset {
                reissue_asset_outpoint,
                fee_utxo_outpoint,
                asset_name,
                reissue_amount,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let Some(asset_entropy) = store.store.get(asset_name)? else {
                    return Err(anyhow!("Asset name not found"));
                };
                let asset_entropy = String::from_utf8(asset_entropy.to_vec())?;
                let asset_entropy = hex::decode(asset_entropy)?;

                let mut asset_entropy_bytes: [u8; 32] = asset_entropy.try_into().unwrap();
                asset_entropy_bytes.reverse();
                let asset_entropy = sha256::Midstate::from_byte_array(asset_entropy_bytes);

                let keypair = derive_keypair(*account_index);
                let blinding = derive_public_blinder_key();
                let ReissueAssetResponse {
                    tx,
                    asset_id,
                    reissuance_asset_id,
                } = contracts_adapter::basic::reissue_asset(
                    &keypair,
                    &blinding,
                    *reissue_asset_outpoint,
                    *fee_utxo_outpoint,
                    *reissue_amount,
                    *fee_amount,
                    asset_entropy,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                println!("Asset id: {asset_id}, Reissuance id: {reissuance_asset_id}");

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
        }
    }
}
