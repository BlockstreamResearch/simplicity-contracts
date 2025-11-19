use crate::modules::keys::derive_secret_key_from_index;
use crate::modules::store::Store;
use anyhow::anyhow;

use clap::Subcommand;

use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::hashes::sha256;
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::secp256k1_zkp::{Secp256k1, SecretKey};
use simplicityhl::elements::{AssetId, TxOutSecrets};
use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::confidential::Asset;
use simplicityhl::simplicity::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{Address, AddressParams, OutPoint, TxOut};
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, broadcast_tx, fetch_utxo,
    finalize_p2pk_transaction, get_new_asset_entropy, get_p2pk_address, get_random_seed,
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let utxo_fee = fetch_utxo(*fee_utxo_outpoint)?;

                let total_input_fee = utxo_fee.value.explicit().unwrap();
                if *fee_amount > total_input_fee {
                    return Err(anyhow!("fee exceeds fee input value"));
                }

                let blinding_key = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let asset_entropy = get_random_seed();

                let mut issuance_tx = Input::from_prevout(*fee_utxo_outpoint);
                issuance_tx.witness_utxo = Some(utxo_fee.clone());
                issuance_tx.issuance_value_amount = Some(*issue_amount);
                issuance_tx.issuance_inflation_keys = Some(1);
                issuance_tx.issuance_asset_entropy = Some(asset_entropy);

                let (asset, reissuance_asset) = issuance_tx.issuance_ids();

                println!("Asset: {}", asset);
                println!("Reissuance Asset: {}", reissuance_asset);

                store.store.insert(
                    asset_name,
                    get_new_asset_entropy(fee_utxo_outpoint, asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();

                pst.add_input(issuance_tx);

                let mut output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    1,
                    reissuance_asset,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    *issue_amount,
                    asset,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                let issuance_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: utxo_fee.value.explicit().unwrap(),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };

                let mut inp_txout_sec = std::collections::HashMap::new();
                inp_txout_sec.insert(0, issuance_secrets);

                pst.inputs_mut()[0].blinded_issuance = Some(0x00);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

                let tx = finalize_p2pk_transaction(
                    pst.extract_tx()?,
                    std::slice::from_ref(&utxo_fee),
                    &keypair,
                    0,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_fee])?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

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
                let asset_entropy = hex::decode(asset_entropy)?;

                let mut asset_entropy_bytes: [u8; 32] = asset_entropy.try_into().unwrap();
                asset_entropy_bytes.reverse();
                let asset_entropy = sha256::Midstate::from_byte_array(asset_entropy_bytes);

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let utxo_reissue = fetch_utxo(*reissue_asset_outpoint)?;
                let utxo_fee = fetch_utxo(*fee_utxo_outpoint)?;

                let total_input_fee = utxo_fee.value.explicit().unwrap();
                if *fee_amount > total_input_fee {
                    return Err(anyhow!("fee exceeds fee input value"));
                }

                let blinding_key = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let blinding_sk = blinding_key.secret_key();

                let unblinded = utxo_reissue.unblind(&Secp256k1::new(), blinding_sk)?;
                let asset_bf = unblinded.asset_bf;

                let asset_id = AssetId::from_entropy(asset_entropy);
                let reissuance_asset_id =
                    AssetId::reissuance_token_from_entropy(asset_entropy, false);

                println!("Asset: {}", asset_id);
                println!("Reissuance Asset: {}", reissuance_asset_id);

                let mut reissuance_tx = Input::from_prevout(*reissue_asset_outpoint);
                reissuance_tx.witness_utxo = Some(utxo_reissue.clone());
                reissuance_tx.issuance_value_amount = Some(*reissue_amount);
                reissuance_tx.issuance_inflation_keys = None;
                reissuance_tx.issuance_asset_entropy = Some(asset_entropy.to_byte_array());

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();

                pst.add_input(reissuance_tx);

                let mut fee_input = Input::from_prevout(*fee_utxo_outpoint);
                fee_input.witness_utxo = Some(utxo_fee.clone());
                pst.add_input(fee_input);

                let mut output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    1,
                    reissuance_asset_id,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    *reissue_amount,
                    asset_id,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                {
                    let input = &mut pst.inputs_mut()[0];
                    input.blinded_issuance = Some(0x00);
                    input.issuance_blinding_nonce = Some(asset_bf.into_inner());
                }

                let mut inp_txout_sec = std::collections::HashMap::new();
                inp_txout_sec.insert(0, unblinded);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

                let utxos = vec![utxo_reissue, utxo_fee];

                let tx = finalize_p2pk_transaction(
                    pst.extract_tx()?,
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
