use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;

use anyhow::anyhow;

use crate::explorer::{broadcast_tx, fetch_utxo};
use clap::Subcommand;
use simplicityhl::elements::hashes::{Hash, sha256};
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::secp256k1_zkp::SECP256K1;
use simplicityhl::elements::{AssetId, ContractHash};
use simplicityhl::simplicity::elements::{Address, AddressParams, OutPoint};
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    LIQUID_TESTNET_GENESIS, create_p2pk_signature, derive_public_blinder_key,
    finalize_p2pk_transaction, get_p2pk_address, hash_script,
};

#[derive(Subcommand, Debug)]
pub enum Basic {
    /// Print a deterministic Liquid testnet address derived from index
    Address {
        /// Address index (0-based)
        index: u32,
    },
    /// Build tx transferring LBTC (explicit) to recipient
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
        /// Miner fee in satoshis (LBTC)
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx splitting one LBTC UTXO into any number of UTXOs.
    SplitNative {
        /// Transaction id (hex) and output index (vout) of the UTXO you will split
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Number of UTXOs to split the LBTC UTXO into
        #[arg(long = "split-parts")]
        split_parts: u64,
        /// Miner fee in satoshis (LBTC)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account that will pay for transaction fees and that owns a tokens to split
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Build tx transferring an asset UTXO to recipient (LBTC UTXO pays fees)
    TransferAsset {
        /// Transaction id (hex) and output index (vout) of the ASSET UTXO you will spend
        #[arg(long = "asset-utxo")]
        asset_utxo: OutPoint,
        /// Transaction id (hex) and output index (vout) of the LBTC UTXO used to pay fees
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Recipient address (Liquid testnet bech32m)
        #[arg(long = "to-address")]
        to_address: Address,
        /// Amount to send of the asset in its smallest units (it does not account for decimals)
        #[arg(long = "send-sats")]
        send_amount: u64,
        /// Miner fee in satoshis (LBTC)
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account that will pay for transaction fees and that owns a tokens to send
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
        /// Asset name (this will be stored in the CLI's database only, so it will be not shown on the Esplora UI)
        #[arg(long = "asset-name")]
        asset_name: String,
        /// Amount to issue of the asset in its satoshi units
        #[arg(long = "issue-sats")]
        issue_amount: u64,
        /// Miner fee in satoshis (LBTC)
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account that will pay for transaction fees and that owns a tokens to send
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
        /// Asset name (this will be stored in the CLI's database only, so it will be not shown on the Esplora UI)
        #[arg(long = "asset-name")]
        asset_name: String,
        /// Amount to reissue of the asset in its satoshi units
        #[arg(long = "reissue-sats")]
        reissue_amount: u64,
        /// Miner fee in satoshis (LBTC)
        #[arg(long = "fee-sats")]
        fee_amount: u64,
        /// Account that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
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
    pub async fn handle(&self) -> anyhow::Result<()> {
        match self {
            Self::Address { index } => {
                let keypair = derive_keypair(*index);

                let public_key = keypair.x_only_public_key().0;
                let address = get_p2pk_address(&public_key, &AddressParams::LIQUID_TESTNET)?;

                let mut script_hash: [u8; 32] = hash_script(&address.script_pubkey());
                script_hash.reverse();

                println!("X Only Public Key: {public_key}");
                println!("P2PK Address: {address}");
                println!("Script hash: {}", hex::encode(script_hash));

                Ok(())
            }
            Self::TransferNative {
                utxo_outpoint,
                to_address,
                amount_to_send,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let tx_out = fetch_utxo(*utxo_outpoint).await?;

                let pst = contracts::sdk::transfer_native(
                    (*utxo_outpoint, tx_out.clone()),
                    to_address,
                    *amount_to_send,
                    *fee_amount,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = &[tx_out];

                let x_only_public_key = keypair.x_only_public_key().0;
                let signature = create_p2pk_signature(
                    &tx,
                    utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let tx = finalize_p2pk_transaction(
                    tx,
                    utxos,
                    &x_only_public_key,
                    &signature,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&tx).await?);
                } else {
                    println!("{}", tx.serialize().to_lower_hex_string());
                }

                Ok(())
            }
            Self::SplitNative {
                split_parts,
                fee_utxo,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let tx_out = fetch_utxo(*fee_utxo).await?;

                let pst = contracts::sdk::split_native_any(
                    (*fee_utxo, tx_out.clone()),
                    *split_parts,
                    *fee_amount,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = &[tx_out];

                let x_only_public_key = keypair.x_only_public_key().0;
                let signature = create_p2pk_signature(
                    &tx,
                    utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let tx = finalize_p2pk_transaction(
                    tx,
                    utxos,
                    &x_only_public_key,
                    &signature,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&tx).await?);
                } else {
                    println!("{}", tx.serialize().to_lower_hex_string());
                }

                Ok(())
            }
            Self::TransferAsset {
                asset_utxo: asset_utxo_outpoint,
                fee_utxo: fee_utxo_outpoint,
                to_address,
                send_amount,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let asset_tx_out = fetch_utxo(*asset_utxo_outpoint).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo_outpoint).await?;

                let pst = contracts::sdk::transfer_asset(
                    (*asset_utxo_outpoint, asset_tx_out.clone()),
                    (*fee_utxo_outpoint, fee_tx_out.clone()),
                    to_address,
                    *send_amount,
                    *fee_amount,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![asset_tx_out, fee_tx_out];
                let x_only_public_key = keypair.x_only_public_key().0;

                let signature_0 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_0,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let signature_1 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_1,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&tx).await?);
                } else {
                    println!("{}", tx.serialize().to_lower_hex_string());
                }

                Ok(())
            }
            Self::IssueAsset {
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
                }

                let keypair = derive_keypair(*account_index);
                let blinding_keypair = derive_public_blinder_key();

                let fee_tx_out = fetch_utxo(*fee_utxo_outpoint).await?;

                let pst = contracts::sdk::issue_asset(
                    &blinding_keypair.public_key(),
                    (*fee_utxo_outpoint, fee_tx_out.clone()),
                    *issue_amount,
                    *fee_amount,
                )?;

                let (asset_id, reissuance_asset_id) = pst.inputs()[0].issuance_ids();
                let asset_entropy = pst.inputs()[0]
                    .issuance_asset_entropy
                    .expect("expected entropy");
                let asset_entropy = AssetId::generate_asset_entropy(
                    *fee_utxo_outpoint,
                    ContractHash::from_byte_array(asset_entropy),
                );

                let tx = pst.extract_tx()?;
                let utxos = &[fee_tx_out];

                let x_only_public_key = keypair.x_only_public_key().0;
                let signature = create_p2pk_signature(
                    &tx,
                    utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let tx = finalize_p2pk_transaction(
                    tx,
                    utxos,
                    &x_only_public_key,
                    &signature,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                println!(
                    "Asset id: {asset_id}, \
                    Reissuance asset: {reissuance_asset_id}, \
                    Asset entropy: {}",
                    hex::encode(asset_entropy)
                );

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&tx).await?);
                } else {
                    println!("{}", tx.serialize().to_lower_hex_string());
                }

                store
                    .store
                    .insert(asset_name, hex::encode(asset_entropy).as_bytes())?;

                Ok(())
            }
            Self::ReissueAsset {
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

                let asset_entropy_bytes: [u8; 32] =
                    asset_entropy.try_into().expect("expected 32 bytes");
                let asset_entropy = sha256::Midstate::from_byte_array(asset_entropy_bytes);

                let keypair = derive_keypair(*account_index);
                let blinding_keypair = derive_public_blinder_key();

                let reissue_tx_out = fetch_utxo(*reissue_asset_outpoint).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo_outpoint).await?;

                let reissue_utxo_secrets =
                    reissue_tx_out.unblind(SECP256K1, blinding_keypair.secret_key())?;

                let pst = contracts::sdk::reissue_asset(
                    &blinding_keypair.public_key(),
                    (*reissue_asset_outpoint, reissue_tx_out.clone()),
                    reissue_utxo_secrets,
                    (*fee_utxo_outpoint, fee_tx_out.clone()),
                    *reissue_amount,
                    *fee_amount,
                    asset_entropy,
                )?;

                let (asset_id, reissuance_asset_id) = pst.inputs()[0].issuance_ids();

                let tx = pst.extract_tx()?;
                let utxos = vec![reissue_tx_out, fee_tx_out];
                let x_only_public_key = keypair.x_only_public_key().0;

                let signature_0 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_0,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let signature_1 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_1,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                println!("Asset id: {asset_id}, Reissuance id: {reissuance_asset_id}");

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&tx).await?);
                } else {
                    println!("{}", tx.serialize().to_lower_hex_string());
                }

                Ok(())
            }
        }
    }
}
