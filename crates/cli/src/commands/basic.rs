use crate::modules::keys::derive_secret_key_from_index;
use anyhow::anyhow;

use clap::Subcommand;

use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::confidential::Asset;
use simplicityhl::simplicity::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{Address, AddressParams, OutPoint, TxOut};
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, broadcast_tx, fetch_utxo,
    finalize_p2pk_transaction, get_p2pk_address,
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
}

impl Basic {
    pub fn handle(&self) -> anyhow::Result<()> {
        match self {
            Basic::Address { index } => {
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*index),
                );

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
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let utxo = fetch_utxo(*utxo_outpoint)?;

                let total_amount = utxo.value.explicit().unwrap();
                if amount_to_send + fee_amount > total_amount {
                    return Err(anyhow!("amount + fee exceeds input value"));
                }

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.add_input(Input::from_prevout(*utxo_outpoint));
                pst.add_output(Output::new_explicit(
                    to_address.script_pubkey(),
                    *amount_to_send,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_amount - amount_to_send - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                let tx = finalize_p2pk_transaction(
                    pst.extract_tx()?,
                    std::slice::from_ref(&utxo),
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo])?;

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
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let utxo = fetch_utxo(*utxo_outpoint)?;

                let total_input_amount = utxo.value.explicit().unwrap();

                let first_amount = *amount;
                let second_amount = total_input_amount - first_amount - *fee_amount;

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.add_input(Input::from_prevout(*utxo_outpoint));
                pst.add_output(Output::new_explicit(
                    recipient_address.script_pubkey(),
                    first_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::new_explicit(
                    recipient_address.script_pubkey(),
                    second_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                let tx = finalize_p2pk_transaction(
                    pst.extract_tx()?,
                    std::slice::from_ref(&utxo),
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo])?;

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
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let utxo = fetch_utxo(*utxo_outpoint)?;

                let total_input_amount = utxo.value.explicit().unwrap();

                let first_amount = *amount;
                let second_amount = first_amount;
                let third_amount = total_input_amount - first_amount - second_amount - *fee_amount;

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.add_input(Input::from_prevout(*utxo_outpoint));

                pst.add_output(Output::new_explicit(
                    recipient_address.script_pubkey(),
                    first_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::new_explicit(
                    recipient_address.script_pubkey(),
                    second_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::new_explicit(
                    recipient_address.script_pubkey(),
                    third_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                let tx = finalize_p2pk_transaction(
                    pst.extract_tx()?,
                    std::slice::from_ref(&utxo),
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo])?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
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
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let utxo_asset = fetch_utxo(*asset_utxo_outpoint)?;
                let utxo_fee = fetch_utxo(*fee_utxo_outpoint)?;

                let total_input_asset = utxo_asset.value.explicit().unwrap();
                if *send_amount > total_input_asset {
                    return Err(anyhow!("send amount exceeds asset input value"));
                }

                let total_input_fee = utxo_fee.value.explicit().unwrap();
                if *fee_amount > total_input_fee {
                    return Err(anyhow!("fee exceeds fee input value"));
                }

                let explicit_asset_id = match utxo_asset.asset {
                    Asset::Explicit(id) => id,
                    _ => return Err(anyhow!("asset utxo must be explicit (unblinded) asset")),
                };

                // Ensure the fee input is LBTC
                match utxo_fee.asset {
                    Asset::Explicit(id) if id == LIQUID_TESTNET_BITCOIN_ASSET => {}
                    _ => return Err(anyhow!("fee utxo must be LBTC")),
                }

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.add_input(Input::from_prevout(*asset_utxo_outpoint));
                pst.add_input(Input::from_prevout(*fee_utxo_outpoint));

                // asset payment output
                pst.add_output(Output::new_explicit(
                    to_address.script_pubkey(),
                    *send_amount,
                    explicit_asset_id,
                    None,
                ));

                // asset change output
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_asset - send_amount,
                    explicit_asset_id,
                    None,
                ));

                // LBTC change output
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                // fee output
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                let tx = pst.extract_tx()?;

                let utxos = vec![utxo_asset, utxo_fee];
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
        }
    }
}
