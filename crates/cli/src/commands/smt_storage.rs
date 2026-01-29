use crate::commands::NETWORK;
use crate::explorer::{broadcast_tx, fetch_utxo};
use crate::modules::utils::derive_keypair;
use clap::Subcommand;
use contracts::smt_storage::{
    DEPTH, SMTWitness, SparseMerkleTree, finalize_get_storage_transaction, get_path_bits,
    get_smt_storage_compiled_program, smt_storage_taproot_spend_info,
};
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::elements::OutPoint;
use simplicityhl::simplicity::elements::Script;
use simplicityhl::simplicity::elements::taproot::TaprootSpendInfo;
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl_core::{create_p2pk_signature, finalize_p2pk_transaction, hash_script};

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|_| "Invalid hex string".to_string())?;

    if bytes.len() != 32 {
        return Err(format!(
            "Expected 32 bytes (64 hex characters), got {}",
            bytes.len()
        ));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn parse_bit_path(s: &str) -> Result<[bool; DEPTH], String> {
    if s.len() != DEPTH {
        return Err(format!("Expected 7 bits, got {}", s.len()));
    }

    let mut path = [false; DEPTH];

    for (ind, char) in s.char_indices() {
        if char == 'r' {
            path[ind] = true;
        } else if char == 'l' {
            path[ind] = false;
        } else {
            return Err(String::from(
                "Expected only 'r' and 'l' symbols, got something else.",
            ));
        }
    }

    Ok(path)
}

/// SMT Storage contract utilities
#[derive(Subcommand, Debug)]
pub enum SMTStorage {
    /// Lock collateral on the storage contract (Mint/Fund operation)
    GetStorageAddress {
        /// The initial 32-byte data payload to store in the tree at the specified path
        #[arg(long = "storage-bytes", value_parser = parse_hex_32)]
        storage_bytes: [u8; 32],
        /// The path in the Merkle Tree use for the contract logic (e.g., "rrll...")
        #[arg(long = "path", value_parser = parse_bit_path)]
        path: [bool; DEPTH],

        /// Account that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
    },
    /// Build tx transferring an asset UTXO to recipient (LBTC UTXO pays fees) and updating state
    TransferFromStorageAddress {
        /// Transaction id (hex) and output index (vout) of the ASSET UTXO you will spend
        #[arg(long = "storage-utxo")]
        storage_utxo: OutPoint,
        /// Transaction id (hex) and output index (vout) of the LBTC UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Miner fee in satoshis (LBTC)
        #[arg(long = "fee-sats")]
        fee_amount: u64,

        /// The current 32-byte data payload stored in the contract (Pre-state)
        #[arg(long = "storage-bytes", value_parser = parse_hex_32)]
        storage_bytes: [u8; 32],
        /// The new 32-byte data payload to replace the old one (Post-state)
        #[arg(long = "changed-bytes", value_parser = parse_hex_32)]
        changed_bytes: [u8; 32],
        /// The Merkle path used to generate the witness for the state transition
        #[arg(long = "path", value_parser = parse_bit_path)]
        path: [bool; DEPTH],

        /// Account that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index", default_value_t = 0)]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

impl SMTStorage {
    /// Handle basic CLI subcommand execution.
    ///
    /// # Errors
    /// Returns error if the subcommand operation fails.
    ///
    /// # Panics
    /// Panics if asset entropy conversion fails.
    pub async fn handle(&self) -> anyhow::Result<()> {
        match self {
            Self::GetStorageAddress {
                storage_bytes,
                path,
                account_index,
            } => {
                let keypair = derive_keypair(*account_index);
                let public_key = keypair.x_only_public_key().0;

                let address = contracts::sdk::get_storage_address(
                    &public_key,
                    storage_bytes,
                    *path,
                    NETWORK,
                )?;

                let mut script_hash: [u8; 32] = hash_script(&address.script_pubkey());
                script_hash.reverse();

                println!("X Only Public Key: {public_key}");
                println!("P2PK Address: {address}");
                println!("Script hash: {}", hex::encode(script_hash));

                Ok(())
            }
            Self::TransferFromStorageAddress {
                storage_utxo: storage_utxo_outpoint,
                fee_utxo: fee_utxo_outpoint,
                fee_amount,
                storage_bytes,
                changed_bytes,
                path,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);
                let public_key = keypair.x_only_public_key().0;

                let storage_tx_out = fetch_utxo(*storage_utxo_outpoint).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo_outpoint).await?;

                let mut smt = SparseMerkleTree::new();
                let merkle_hashes = smt.update(storage_bytes, *path);

                let merkle_data =
                    std::array::from_fn(|i| (merkle_hashes[DEPTH - i - 1], path[DEPTH - i - 1]));

                let witness = SMTWitness::new(
                    &public_key.serialize(),
                    storage_bytes,
                    get_path_bits(path, true),
                    &merkle_data,
                );
                smt.update(changed_bytes, *path);

                let program = get_smt_storage_compiled_program();
                let cmr = program.commit().cmr();

                let old_spend_info: TaprootSpendInfo =
                    smt_storage_taproot_spend_info(public_key, storage_bytes, &merkle_data, cmr);

                let new_spend_info =
                    smt_storage_taproot_spend_info(public_key, changed_bytes, &merkle_data, cmr);
                let new_script_pubkey = Script::new_v1_p2tr_tweaked(new_spend_info.output_key());

                let pst = contracts::sdk::transfer_asset_with_storage(
                    (*storage_utxo_outpoint, storage_tx_out.clone()),
                    (*fee_utxo_outpoint, fee_tx_out.clone()),
                    *fee_amount,
                    &new_script_pubkey,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![storage_tx_out, fee_tx_out];

                let tx = finalize_get_storage_transaction(
                    tx,
                    &old_spend_info,
                    &witness,
                    &program,
                    &utxos,
                    0,
                    NETWORK,
                    TrackerLogLevel::None,
                )?;

                let signature = create_p2pk_signature(&tx, &utxos, &keypair, 1, NETWORK)?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &public_key,
                    &signature,
                    1,
                    NETWORK,
                    TrackerLogLevel::None,
                )?;

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
