use anyhow::Result;
use clap::Subcommand;
use contracts::sdk::taproot_pubkey_gen::{TaprootPubkeyGen, get_random_seed};
use contracts::{OptionsArguments, finalize_options_transaction, get_options_program};
use std::str::FromStr;

use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::secp256k1_zkp::SECP256K1;
use simplicityhl::elements::{AddressParams, OutPoint};
use simplicityhl::simplicity::elements::AssetId;
use simplicityhl::simplicity::hex::DisplayHex;

use simplicityhl_core::{
    Encodable, LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, broadcast_tx,
    create_p2pk_signature, derive_public_blinder_key, fetch_utxo, finalize_p2pk_transaction,
};

use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;

/// Options contract utilities
/// In that version only the LBTC asset can be used as collateral
#[derive(Subcommand, Debug)]
pub enum Options {
    /// Creates a set of two UTXOs (option and grantor) for the options contract
    Create {
        /// First fee utxo used to issue the option reissuance token
        #[arg(long = "first-fee-utxo")]
        first_fee_utxo: OutPoint,
        /// Second fee utxo used to issue the grantor reissuance token
        #[arg(long = "second-fee-utxo")]
        second_fee_utxo: OutPoint,
        /// Start time (UNIX seconds)
        #[arg(long = "start-time")]
        start_time: u32,
        /// Expiry time (UNIX seconds)
        #[arg(long = "expiry-time")]
        expiry_time: u32,
        /// Collateral per contract
        #[arg(long = "collateral-per-contract")]
        collateral_per_contract: u64,
        /// Settlement per contract (in settlement asset units)
        #[arg(long = "settlement-per-contract")]
        settlement_per_contract: u64,
        /// Settlement asset id (hex, BE)
        #[arg(long = "settlement-asset-id-hex-be")]
        settlement_asset_id_hex_be: String,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// Fee amount in satoshis (LBTC)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Lock collateral on the options contract to get option and grantor tokens
    Fund {
        /// Option reissuance token UTXO
        #[arg(long = "option-asset-utxo")]
        option_asset_utxo: OutPoint,
        /// Grantor reissuance token UTXO
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// Collateral and fee UTXO
        #[arg(long = "collateral-and-fee-utxo")]
        collateral_and_fee_utxo: OutPoint,
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Collateral amount in satoshis (LBTC)
        #[arg(long = "collateral-amount")]
        collateral_amount: u64,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// Fee amount in satoshis (LBTC)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Exercise path: burn option tokens and settle against settlement asset
    Exercise {
        /// Collateral UTXO at the options address (LBTC)
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Option asset utxo
        #[arg(long = "option-asset-utxo")]
        option_asset_utxo: OutPoint,
        /// Settlement asset UTXO
        #[arg(long = "asset-utxo")]
        asset_utxo: OutPoint,
        /// Fee UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of option tokens to burn
        #[arg(long = "amount-to-burn")]
        amount_to_burn: u64,
        /// Fee amount in satoshis (LBTC) to pay (deducted from collateral input)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Settlement path: burn grantor tokens against settlement asset held by the covenant (contract)
    Settle {
        /// Settlement asset UTXO owned by the options contract
        #[arg(long = "settlement-asset-utxo")]
        settlement_asset_utxo: OutPoint,
        /// Grantor token UTXO consumed for burning
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// Fee UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of grantor tokens to burn
        #[arg(long = "grantor-token-amount-to-burn")]
        grantor_token_amount_to_burn: u64,
        /// Fee amount in satoshis (LBTC) to pay
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Expiry path: burn grantor tokens and withdraw collateral to P2PK (contract)
    Expire {
        /// Collateral UTXO owned by the options contract (LBTC)
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Grantor token UTXO consumed for burning
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// Fee UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of grantor tokens to burn
        #[arg(long = "grantor-token-amount-to-burn")]
        grantor_token_amount_to_burn: u64,
        /// Fee amount in satoshis (LBTC) to pay (deducted from collateral input)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Cancellation path: burn both tokens and withdraw collateral to P2PK (contract)
    Cancel {
        /// Collateral UTXO owned by the options contract (LBTC)
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Option token UTXO consumed for burning
        #[arg(long = "option-asset-utxo")]
        option_asset_utxo: OutPoint,
        /// Grantor token UTXO consumed for burning
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// Fee UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of both tokens to burn
        #[arg(long = "amount-to-burn")]
        amount_to_burn: u64,
        /// Fee amount in satoshis (LBTC) to pay (deducted from collateral input)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// This function is used to import the options arguments into the store
    /// Se the user can perform operations on the contract
    Import {
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Encoded options arguments
        #[arg(long = "encoded-options-arguments")]
        encoded_options_arguments: String,
    },
    Export {
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
    },
}

impl Options {
    /// Handle options CLI subcommand execution.
    ///
    /// # Errors
    /// Returns error if the subcommand operation fails.
    #[expect(clippy::too_many_lines)]
    pub async fn handle(&self) -> Result<()> {
        match self {
            Self::Import {
                option_taproot_pubkey_gen,
                encoded_options_arguments,
            } => Store::load()?.import_arguments(
                option_taproot_pubkey_gen,
                encoded_options_arguments,
                &AddressParams::LIQUID_TESTNET,
                &contracts::get_options_address,
            ),
            Self::Export {
                option_taproot_pubkey_gen,
            } => {
                println!(
                    "{}",
                    Store::load()?.export_arguments(option_taproot_pubkey_gen)?
                );
                Ok(())
            }
            Self::Create {
                first_fee_utxo,
                second_fee_utxo,
                start_time,
                expiry_time,
                collateral_per_contract,
                settlement_per_contract,
                settlement_asset_id_hex_be,
                account_index,
                fee_amount,
                broadcast,
            } => {
                let store = Store::load()?;
                let keypair = derive_keypair(*account_index);
                let blinder_keypair = derive_public_blinder_key();

                let first_tx_out = fetch_utxo(*first_fee_utxo).await?;
                let second_tx_out = fetch_utxo(*second_fee_utxo).await?;

                let issuance_asset_entropy = get_random_seed();

                let settlement_asset_id = AssetId::from_str(settlement_asset_id_hex_be)?;

                let option_arguments = OptionsArguments::new(
                    *start_time,
                    *expiry_time,
                    *collateral_per_contract,
                    *settlement_per_contract,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    settlement_asset_id,
                    issuance_asset_entropy,
                    *first_fee_utxo,
                    *second_fee_utxo,
                );

                let (pst, options_taproot_pubkey_gen) = contracts::sdk::build_option_creation(
                    &blinder_keypair.public_key(),
                    (*first_fee_utxo, first_tx_out.clone()),
                    (*second_fee_utxo, second_tx_out.clone()),
                    &option_arguments,
                    issuance_asset_entropy,
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![first_tx_out.clone(), second_tx_out.clone()];
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

                println!("options_taproot_pubkey_gen: {options_taproot_pubkey_gen}");

                store.import_arguments(
                    &options_taproot_pubkey_gen.to_string(),
                    &option_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&tx).await?);
                } else {
                    println!("{}", tx.serialize().to_lower_hex_string());
                }

                Ok(())
            }
            Self::Fund {
                option_asset_utxo,
                grantor_asset_utxo,
                collateral_and_fee_utxo,
                option_taproot_pubkey_gen,
                collateral_amount,
                account_index,
                fee_amount,
                broadcast,
            } => {
                let store = Store::load()?;
                let keypair = derive_keypair(*account_index);
                let blinder_keypair = derive_public_blinder_key();

                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let collateral_tx_out = fetch_utxo(*collateral_and_fee_utxo).await?;

                let option_tx_out_secrets =
                    option_tx_out.unblind(SECP256K1, blinder_keypair.secret_key())?;
                let grantor_tx_out_secrets =
                    grantor_tx_out.unblind(SECP256K1, blinder_keypair.secret_key())?;

                let (pst, option_branch) = contracts::sdk::build_option_funding(
                    &blinder_keypair.public_key(),
                    (
                        *option_asset_utxo,
                        option_tx_out.clone(),
                        option_tx_out_secrets,
                    ),
                    (
                        *grantor_asset_utxo,
                        grantor_tx_out.clone(),
                        grantor_tx_out_secrets,
                    ),
                    (*collateral_and_fee_utxo, collateral_tx_out.clone()),
                    None,
                    &option_arguments,
                    *collateral_amount,
                    *fee_amount,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![
                    option_tx_out.clone(),
                    grantor_tx_out.clone(),
                    collateral_tx_out.clone(),
                ];

                let tx = finalize_options_transaction(
                    tx,
                    &taproot_pubkey_gen.get_x_only_pubkey(),
                    &get_options_program(&option_arguments)?,
                    &utxos,
                    0,
                    option_branch,
                )?;

                let tx = finalize_options_transaction(
                    tx,
                    &taproot_pubkey_gen.get_x_only_pubkey(),
                    &get_options_program(&option_arguments)?,
                    &utxos,
                    1,
                    option_branch,
                )?;

                let x_only_public_key = keypair.x_only_public_key().0;
                let signature = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature,
                    2,
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
            Self::Exercise {
                collateral_utxo,
                option_asset_utxo,
                asset_utxo,
                fee_utxo,
                option_taproot_pubkey_gen,
                amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let keypair = derive_keypair(*account_index);

                let store = Store::load()?;
                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;
                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let asset_tx_out = fetch_utxo(*asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (pst, option_branch) = contracts::sdk::build_option_exercise(
                    (*collateral_utxo, collateral_tx_out.clone()),
                    (*option_asset_utxo, option_tx_out.clone()),
                    (*asset_utxo, asset_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    *amount_to_burn,
                    *fee_amount,
                    &option_arguments,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![
                    collateral_tx_out.clone(),
                    option_tx_out.clone(),
                    asset_tx_out.clone(),
                    fee_tx_out.clone(),
                ];

                let tx = finalize_options_transaction(
                    tx,
                    &taproot_pubkey_gen.get_x_only_pubkey(),
                    &get_options_program(&option_arguments)?,
                    &utxos,
                    0,
                    option_branch,
                )?;

                let x_only_public_key = keypair.x_only_public_key().0;

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

                let signature_2 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_2,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let signature_3 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    3,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_3,
                    3,
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
            Self::Settle {
                settlement_asset_utxo,
                grantor_asset_utxo,
                fee_utxo,
                option_taproot_pubkey_gen,
                grantor_token_amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;
                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let keypair = derive_keypair(*account_index);

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let settlement_tx_out = fetch_utxo(*settlement_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (pst, option_branch) = contracts::sdk::build_option_settlement(
                    (*settlement_asset_utxo, settlement_tx_out.clone()),
                    (*grantor_asset_utxo, grantor_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    *grantor_token_amount_to_burn,
                    *fee_amount,
                    &option_arguments,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![
                    settlement_tx_out.clone(),
                    grantor_tx_out.clone(),
                    fee_tx_out.clone(),
                ];

                let tx = finalize_options_transaction(
                    tx,
                    &taproot_pubkey_gen.get_x_only_pubkey(),
                    &get_options_program(&option_arguments)?,
                    &utxos,
                    0,
                    option_branch,
                )?;

                let x_only_public_key = keypair.x_only_public_key().0;

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

                let signature_2 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_2,
                    2,
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
            Self::Expire {
                collateral_utxo,
                grantor_asset_utxo,
                fee_utxo,
                option_taproot_pubkey_gen,
                grantor_token_amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;
                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let keypair = derive_keypair(*account_index);

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (pst, option_branch) = contracts::sdk::build_option_expiry(
                    (*collateral_utxo, collateral_tx_out.clone()),
                    (*grantor_asset_utxo, grantor_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    *grantor_token_amount_to_burn,
                    *fee_amount,
                    &option_arguments,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![
                    collateral_tx_out.clone(),
                    grantor_tx_out.clone(),
                    fee_tx_out.clone(),
                ];

                let tx = finalize_options_transaction(
                    tx,
                    &taproot_pubkey_gen.get_x_only_pubkey(),
                    &get_options_program(&option_arguments)?,
                    &utxos,
                    0,
                    option_branch,
                )?;

                let x_only_public_key = keypair.x_only_public_key().0;

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

                let signature_2 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_2,
                    2,
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
            Self::Cancel {
                collateral_utxo,
                option_asset_utxo,
                grantor_asset_utxo,
                fee_utxo,
                option_taproot_pubkey_gen,
                amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;
                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let keypair = derive_keypair(*account_index);

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;
                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (pst, option_branch) = contracts::sdk::build_option_cancellation(
                    (*collateral_utxo, collateral_tx_out.clone()),
                    (*option_asset_utxo, option_tx_out.clone()),
                    (*grantor_asset_utxo, grantor_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    &option_arguments,
                    *amount_to_burn,
                    *fee_amount,
                )?;

                let tx = pst.extract_tx()?;
                let utxos = vec![
                    collateral_tx_out.clone(),
                    option_tx_out.clone(),
                    grantor_tx_out.clone(),
                    fee_tx_out.clone(),
                ];

                let tx = finalize_options_transaction(
                    tx,
                    &taproot_pubkey_gen.get_x_only_pubkey(),
                    &get_options_program(&option_arguments)?,
                    &utxos,
                    0,
                    option_branch,
                )?;

                let x_only_public_key = keypair.x_only_public_key().0;

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

                let signature_2 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_2,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                let signature_3 = create_p2pk_signature(
                    &tx,
                    &utxos,
                    &keypair,
                    3,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &x_only_public_key,
                    &signature_3,
                    3,
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
        }
    }
}
