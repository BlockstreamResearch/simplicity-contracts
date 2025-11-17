use crate::modules::store::Store;
use anyhow::anyhow;

use crate::modules::utils::derive_keypair;
use clap::Subcommand;
use simplicityhl::elements;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::hashes::sha256;
use simplicityhl::elements::hashes::sha256::Midstate;
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::secp256k1_zkp::{Secp256k1, SecretKey};
use simplicityhl::elements::{AssetId, Transaction, TxOutSecrets};
use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::confidential::Asset;
use simplicityhl::simplicity::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{Address, AddressParams, OutPoint, TxOut};
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl_core::{
    AssetEntropyBytes, LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, broadcast_tx,
    derive_public_blinder_key, fetch_utxo, finalize_p2pk_transaction, get_p2pk_address,
    get_random_seed, obtain_utxo_value,
};

struct IssueAssetResponse {
    tx: Transaction,
    asset_id: AssetId,
    reissuance_asset_id: AssetId,
    asset_entropy: AssetEntropyBytes,
}

struct ReissueAssetResponse {
    tx: Transaction,
    asset_id: AssetId,
    reissuance_asset_id: AssetId,
}

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

                let tx = Self::transfer_native(
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

                let tx = Self::split_native(
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

                let tx = Self::split_native_three(
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

                let tx = Self::transfer_asset(
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
                let blinding_key = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let IssueAssetResponse {
                    tx,
                    asset_id,
                    reissuance_asset_id,
                    asset_entropy,
                } = Self::issue_asset(
                    &keypair,
                    &blinding_key,
                    *fee_utxo_outpoint,
                    *issue_amount,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                store
                    .store
                    .insert(asset_name, asset_entropy.to_hex().as_bytes())?;

                println!(
                    "Asset id: {asset_id}, Reissuance asset: {reissuance_asset_id}, Asset entropy: {}",
                    asset_entropy.to_hex()
                );

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

                let keypair = derive_keypair(*account_index);
                let blinding = derive_public_blinder_key()?;
                let ReissueAssetResponse {
                    tx,
                    asset_id,
                    reissuance_asset_id,
                } = Self::reissue_asset(
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

    fn reissue_asset(
        keypair: &Keypair,
        blinding_key: &Keypair,
        reissue_asset_outpoint: OutPoint,
        fee_utxo_outpoint: OutPoint,
        reissue_amount: u64,
        fee_amount: u64,
        asset_entropy: Midstate,
        address_params: &'static AddressParams,
        lbtc_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<ReissueAssetResponse> {
        let reissue_utxo_tx_out = fetch_utxo(reissue_asset_outpoint)?;
        let fee_utxo_tx_out = fetch_utxo(fee_utxo_outpoint)?;

        let total_input_fee = fee_utxo_tx_out.value.explicit().unwrap();
        if fee_amount > total_input_fee {
            return Err(anyhow!("fee exceeds fee input value"));
        }

        let blinding_sk = blinding_key.secret_key();

        let unblinded = reissue_utxo_tx_out.unblind(&Secp256k1::new(), blinding_sk)?;
        let asset_bf = unblinded.asset_bf;

        let asset_id = AssetId::from_entropy(asset_entropy);
        let reissuance_asset_id = AssetId::reissuance_token_from_entropy(asset_entropy, false);

        let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

        let mut inp_txout_sec = std::collections::HashMap::new();
        let mut pst = PartiallySignedTransaction::new_v2();

        // Reissuance token input
        {
            let mut reissuance_tx = Input::from_prevout(reissue_asset_outpoint);
            reissuance_tx.witness_utxo = Some(reissue_utxo_tx_out.clone());
            reissuance_tx.issuance_value_amount = Some(reissue_amount);
            reissuance_tx.issuance_inflation_keys = None;
            reissuance_tx.issuance_asset_entropy = Some(asset_entropy.to_byte_array());

            reissuance_tx.blinded_issuance = Some(0x00);
            reissuance_tx.issuance_blinding_nonce = Some(asset_bf.into_inner());

            pst.add_input(reissuance_tx);
            inp_txout_sec.insert(0, unblinded);
        }

        // Fee input
        {
            let mut fee_input = Input::from_prevout(fee_utxo_outpoint);
            fee_input.witness_utxo = Some(fee_utxo_tx_out.clone());
            pst.add_input(fee_input);
        }

        // Passing Reissuance token to new tx_out
        {
            let mut output = Output::new_explicit(
                change_recipient.script_pubkey(),
                1,
                reissuance_asset_id,
                Some(blinding_key.public_key().into()),
            );
            output.blinder_index = Some(0);
            pst.add_output(output);
        }

        //  Defining the amount of token to reissue
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            reissue_amount,
            asset_id,
            None,
        ));

        // Change
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            total_input_fee - fee_amount,
            lbtc_asset,
            None,
        ));

        // Fee
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

        pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

        let utxos = vec![reissue_utxo_tx_out, fee_utxo_tx_out];

        let tx = finalize_p2pk_transaction(
            pst.extract_tx()?,
            &utxos,
            &keypair,
            0,
            address_params,
            genesis_block_hash,
        )?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, &keypair, 1, address_params, genesis_block_hash)?;
        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        Ok(ReissueAssetResponse {
            tx,
            asset_id,
            reissuance_asset_id,
        })
    }

    fn issue_asset(
        keypair: &Keypair,
        blinding_key: &Keypair,
        fee_utxo_outpoint: OutPoint,
        issue_amount: u64,
        fee_amount: u64,
        address_params: &'static AddressParams,
        lbtc_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<IssueAssetResponse> {
        let fee_utxo_tx_out = fetch_utxo(fee_utxo_outpoint)?;

        let total_input_fee = obtain_utxo_value(&fee_utxo_tx_out)?;
        if fee_amount > total_input_fee {
            return Err(anyhow!("fee exceeds fee input value"));
        }

        let asset_entropy = get_random_seed();

        let mut issuance_tx = Input::from_prevout(fee_utxo_outpoint);
        issuance_tx.witness_utxo = Some(fee_utxo_tx_out.clone());
        issuance_tx.issuance_value_amount = Some(issue_amount);
        issuance_tx.issuance_inflation_keys = Some(1);
        issuance_tx.issuance_asset_entropy = Some(asset_entropy);

        let (asset_id, reissuance_asset_id) = issuance_tx.issuance_ids();

        let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

        let mut inp_txout_sec = std::collections::HashMap::new();
        let mut pst = PartiallySignedTransaction::new_v2();

        // Issuance token input
        {
            let issuance_secrets = TxOutSecrets {
                asset_bf: AssetBlindingFactor::zero(),
                value_bf: ValueBlindingFactor::zero(),
                value: fee_utxo_tx_out.value.explicit().unwrap(),
                asset: lbtc_asset,
            };

            pst.inputs_mut()[0].blinded_issuance = Some(0x00);
            pst.add_input(issuance_tx);

            inp_txout_sec.insert(0, issuance_secrets);
        }

        // Passing Reissuance token to new tx_out
        {
            let mut output = Output::new_explicit(
                change_recipient.script_pubkey(),
                1,
                reissuance_asset_id,
                Some(blinding_key.public_key().into()),
            );
            output.blinder_index = Some(0);
            pst.add_output(output);
        }

        //  Defining the amount of token issuance
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            issue_amount,
            asset_id,
            None,
        ));

        // Change
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            total_input_fee - fee_amount,
            lbtc_asset,
            None,
        ));

        // Fee
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

        pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

        let tx = finalize_p2pk_transaction(
            pst.extract_tx()?,
            std::slice::from_ref(&fee_utxo_tx_out),
            &keypair,
            0,
            address_params,
            genesis_block_hash,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[fee_utxo_tx_out])?;
        Ok(IssueAssetResponse {
            tx,
            asset_id,
            reissuance_asset_id,
            asset_entropy,
        })
    }

    fn transfer_asset(
        keypair: &Keypair,
        asset_utxo_outpoint: OutPoint,
        fee_utxo_outpoint: OutPoint,
        to_address: &Address,
        send_amount: u64,
        fee_amount: u64,
        address_params: &'static AddressParams,
        lbtc_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        let asset_utxo_tx_out = fetch_utxo(asset_utxo_outpoint)?;
        let fee_utxo_tx_out = fetch_utxo(fee_utxo_outpoint)?;

        let total_input_asset = obtain_utxo_value(&asset_utxo_tx_out)?;
        if send_amount > total_input_asset {
            return Err(anyhow!("send amount exceeds asset input value"));
        }

        let total_input_fee = obtain_utxo_value(&fee_utxo_tx_out)?;
        if fee_amount > total_input_fee {
            return Err(anyhow!("fee exceeds fee input value"));
        }

        let explicit_asset_id = match asset_utxo_tx_out.asset {
            Asset::Explicit(id) => id,
            _ => return Err(anyhow!("asset utxo must be explicit (unblinded) asset")),
        };

        // Ensure the fee input is LBTC
        match fee_utxo_tx_out.asset {
            Asset::Explicit(id) if id == LIQUID_TESTNET_BITCOIN_ASSET => {}
            _ => return Err(anyhow!("fee utxo must be LBTC")),
        }

        let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(asset_utxo_outpoint));
        pst.add_input(Input::from_prevout(fee_utxo_outpoint));

        // Asset payment output
        pst.add_output(Output::new_explicit(
            to_address.script_pubkey(),
            send_amount,
            explicit_asset_id,
            None,
        ));

        // Asset change output
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
            lbtc_asset,
            None,
        ));

        // Fee output
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

        let tx = pst.extract_tx()?;

        let utxos = vec![asset_utxo_tx_out, fee_utxo_tx_out];
        let tx =
            finalize_p2pk_transaction(tx, &utxos, &keypair, 0, address_params, genesis_block_hash)?;
        let tx =
            finalize_p2pk_transaction(tx, &utxos, &keypair, 1, address_params, genesis_block_hash)?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
        Ok(tx)
    }

    fn split_native_three(
        keypair: &Keypair,
        utxo_outpoint: OutPoint,
        recipient_address: &Address,
        amount: u64,
        fee_amount: u64,
        address_params: &'static AddressParams,
        lbtc_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        let utxo_tx_out = fetch_utxo(utxo_outpoint)?;
        let total_input_amount = obtain_utxo_value(&utxo_tx_out)?;

        let first_amount = amount;
        let second_amount = first_amount;
        let third_amount = total_input_amount - first_amount - second_amount - fee_amount;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(utxo_outpoint));

        // First amount
        pst.add_output(Output::new_explicit(
            recipient_address.script_pubkey(),
            first_amount,
            lbtc_asset,
            None,
        ));

        // Second amount
        pst.add_output(Output::new_explicit(
            recipient_address.script_pubkey(),
            second_amount,
            lbtc_asset,
            None,
        ));

        // Change
        pst.add_output(Output::new_explicit(
            recipient_address.script_pubkey(),
            third_amount,
            lbtc_asset,
            None,
        ));

        // Fee
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

        let tx = finalize_p2pk_transaction(
            pst.extract_tx()?,
            std::slice::from_ref(&utxo_tx_out),
            &keypair,
            0,
            address_params,
            genesis_block_hash,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_tx_out])?;
        Ok(tx)
    }

    pub fn split_native(
        keypair: &Keypair,
        utxo_outpoint: OutPoint,
        recipient_address: &Address,
        amount: u64,
        fee_amount: u64,
        address_params: &'static AddressParams,
        lbtc_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        let utxo_tx_out = fetch_utxo(utxo_outpoint)?;
        let utxo_total_input_amount = obtain_utxo_value(&utxo_tx_out)?;

        let first_amount = amount;
        let second_amount = utxo_total_input_amount - first_amount - fee_amount;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(utxo_outpoint));

        // Amount to split
        pst.add_output(Output::new_explicit(
            recipient_address.script_pubkey(),
            first_amount,
            lbtc_asset,
            None,
        ));

        // Change
        pst.add_output(Output::new_explicit(
            recipient_address.script_pubkey(),
            second_amount,
            lbtc_asset,
            None,
        ));

        // Fee
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

        let tx = finalize_p2pk_transaction(
            pst.extract_tx()?,
            std::slice::from_ref(&utxo_tx_out),
            &keypair,
            0,
            address_params,
            genesis_block_hash,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_tx_out])?;
        Ok(tx)
    }

    pub fn transfer_native(
        keypair: &Keypair,
        utxo_outpoint: OutPoint,
        to_address: &Address,
        amount_to_send: u64,
        fee_amount: u64,
        address_params: &'static AddressParams,
        lbtc_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        let utxo_tx_out = fetch_utxo(utxo_outpoint)?;
        let utxo_total_amount = obtain_utxo_value(&utxo_tx_out)?;

        if amount_to_send + fee_amount > utxo_total_amount {
            return Err(anyhow!("amount + fee exceeds input value"));
        }

        let change_recipient = get_p2pk_address(&keypair.x_only_public_key().0, address_params)?;

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(utxo_outpoint));

        // Amount to send
        pst.add_output(Output::new_explicit(
            to_address.script_pubkey(),
            amount_to_send,
            lbtc_asset,
            None,
        ));

        // Change
        pst.add_output(Output::new_explicit(
            change_recipient.script_pubkey(),
            utxo_total_amount - amount_to_send - fee_amount,
            lbtc_asset,
            None,
        ));

        // Fee
        pst.add_output(Output::from_txout(TxOut::new_fee(fee_amount, lbtc_asset)));

        let tx = finalize_p2pk_transaction(
            pst.extract_tx()?,
            std::slice::from_ref(&utxo_tx_out),
            &keypair,
            0,
            address_params,
            genesis_block_hash,
        )?;

        tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &[utxo_tx_out])?;
        Ok(tx)
    }
}
