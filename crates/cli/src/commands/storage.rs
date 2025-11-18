use anyhow::Result;

use clap::Subcommand;

use contracts::get_storage_address;

use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;
use contracts::StorageArguments;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::OutPoint;
use simplicityhl::simplicity::elements::hex::ToHex;
use simplicityhl::simplicity::elements::AddressParams;
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    broadcast_tx, derive_public_blinder_key, get_new_asset_entropy, Encodable,
    LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS,
};

#[derive(Subcommand, Debug)]
pub enum Storage {
    Import {
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        storage_taproot_pubkey_gen: String,
        /// Encoded options arguments
        #[arg(long = "encoded-options-arguments")]
        encoded_storage_arguments: String,
    },
    Export {
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        storage_taproot_pubkey_gen: String,
    },

    /// Create state and reissuance token
    InitState {
        /// Fee utxo
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Update state using previous state and reissuance token
    UpdateState {
        /// First fee utxo
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Storage utxo
        #[arg(long = "storage-utxo")]
        storage_utxo: OutPoint,
        /// Reissuance token utxo
        #[arg(long = "reissuance-token-utxo")]
        reissuance_token_utxo: OutPoint,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// Storage taproot pubkey gen
        #[arg(long = "taproot-pubkey-gen")]
        taproot_pubkey_gen: String,
        /// New value to store
        #[arg(long = "new-value")]
        new_value: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

impl Storage {
    #[allow(unused)]
    pub fn handle(&self) -> Result<()> {
        match self {
            Storage::Import {
                storage_taproot_pubkey_gen,
                encoded_storage_arguments,
            } => {
                Store::load()?.import_arguments(
                    storage_taproot_pubkey_gen,
                    encoded_storage_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &get_storage_address,
                )?;
            }
            Storage::Export {
                storage_taproot_pubkey_gen,
            } => {
                println!(
                    "{}",
                    Store::load()?.export_arguments(storage_taproot_pubkey_gen)?
                );
            }
            Storage::InitState {
                fee_utxo,
                account_index,
                fee_amount,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = derive_keypair(*account_index);
                let blinder_key = derive_public_blinder_key();

                let (asset_entropy, storage_arguments, storage_taproot_pubkey_gen, tx) =
                    contracts_adapter::storage::init_state(
                        &keypair,
                        &blinder_key,
                        *fee_utxo,
                        *fee_amount,
                        &AddressParams::LIQUID_TESTNET,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;

                store.import_arguments(
                    &storage_taproot_pubkey_gen.to_string(),
                    &storage_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &get_storage_address,
                )?;

                store.store.insert(
                    format!("entropy_{}", storage_taproot_pubkey_gen),
                    get_new_asset_entropy(fee_utxo, asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
            }
            Storage::UpdateState {
                fee_utxo,
                storage_utxo,
                reissuance_token_utxo,
                account_index,
                taproot_pubkey_gen,
                new_value,
                fee_amount,
                broadcast,
            } => {
                let store = Store::load()?;

                let Some(asset_entropy_hex) =
                    store.store.get(format!("entropy_{}", taproot_pubkey_gen))?
                else {
                    anyhow::bail!("First entropy not found");
                };

                let storage_arguments: StorageArguments =
                    store.get_arguments(taproot_pubkey_gen)?;

                let keypair = derive_keypair(*account_index);
                let blinder_key = derive_public_blinder_key();

                let tx = contracts_adapter::storage::update_storage(
                    &keypair,
                    &blinder_key,
                    *fee_utxo,
                    *storage_utxo,
                    *reissuance_token_utxo,
                    taproot_pubkey_gen,
                    *new_value,
                    *fee_amount,
                    asset_entropy_hex,
                    &storage_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
            }
        }
        Ok(())
    }
}
