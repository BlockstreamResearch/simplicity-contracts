#![allow(clippy::similar_names)]

use std::str::FromStr;

use anyhow::Result;

use clap::Subcommand;

use contracts::options::{
    OptionsArguments, build_witness::OptionBranch, build_witness::blinding_factors_from_secrets,
    finalize_options_transaction, get_options_program,
};
use contracts::sdk::taproot_pubkey_gen::{TaprootPubkeyGen, get_random_seed};

use crate::explorer::{broadcast_tx, fetch_utxo};
use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;
use contracts::sdk::{DEFAULT_TARGET_BLOCKS, SyncFeeFetcher};
use simplicityhl::elements::OutPoint;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::secp256k1_zkp::SECP256K1;
use simplicityhl::simplicity::elements::AssetId;
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl_core::{
    Encodable, SimplicityNetwork, create_p2pk_signature, derive_public_blinder_key,
    finalize_p2pk_transaction,
};

/// Options contract utilities
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
        /// Collateral asset id (hex, BE)
        #[arg(long = "collateral-asset-id-hex-be")]
        collateral_asset_id_hex_be: String,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// Fee amount in satoshis (LBTC)
        #[arg(long = "fee-amount")]
        fee_amount: Option<u64>,
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
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Option taproot pubkey gen that in this CLI works as unique contract identifier
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Collateral amount in satoshis (LBTC)
        #[arg(long = "collateral-amount")]
        collateral_amount: u64,
        /// Account index that will pay for transaction fees and that owns a tokens to send
        #[arg(long = "account-index")]
        account_index: u32,
        /// Transaction id (hex) and output index (vout) of the LBTC UTXO used to pay fees
        #[arg(long = "fee-utxo")]
        fee_utxo: Option<OutPoint>,
        /// Fee amount in satoshis (LBTC)
        #[arg(long = "fee-amount")]
        fee_amount: Option<u64>,
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
        fee_amount: Option<u64>,
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
        fee_amount: Option<u64>,
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
        fee_amount: Option<u64>,
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
        fee_amount: Option<u64>,
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
    const NETWORK: SimplicityNetwork = SimplicityNetwork::LiquidTestnet;

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
                Self::NETWORK.address_params(),
                &contracts::options::get_options_address,
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
                collateral_asset_id_hex_be,
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
                let collateral_asset_id = AssetId::from_str(collateral_asset_id_hex_be)?;

                let option_arguments = OptionsArguments::new(
                    *start_time,
                    *expiry_time,
                    *collateral_per_contract,
                    *settlement_per_contract,
                    collateral_asset_id,
                    settlement_asset_id,
                    issuance_asset_entropy,
                    (*first_fee_utxo, false),
                    (*second_fee_utxo, false),
                );

                let (partial_pset, options_taproot_pubkey_gen) =
                    contracts::sdk::build_option_creation(
                        &blinder_keypair.public_key(),
                        (*first_fee_utxo, first_tx_out.clone()),
                        (*second_fee_utxo, second_tx_out.clone()),
                        &option_arguments,
                        issuance_asset_entropy,
                        Self::NETWORK.address_params(),
                    )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let tx = partial_pset.finalize(
                    Self::NETWORK,
                    |network: SimplicityNetwork, tx, utxos| {
                        let x_only_public_key = keypair.x_only_public_key().0;
                        let address_params = network.address_params();
                        let genesis_block_hash = network.genesis_block_hash();

                        let signature_0 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            0,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_0,
                            0,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_1 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            1,
                            address_params,
                            genesis_block_hash,
                        )?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )
                    },
                )?;

                println!("options_taproot_pubkey_gen: {options_taproot_pubkey_gen}");

                store.import_arguments(
                    &options_taproot_pubkey_gen.to_string(),
                    &option_arguments.to_hex()?,
                    Self::NETWORK.address_params(),
                    &contracts::options::get_options_address,
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
                collateral_utxo,
                option_taproot_pubkey_gen,
                collateral_amount,
                account_index,
                fee_utxo,
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
                    Self::NETWORK.address_params(),
                    &contracts::options::get_options_address,
                )?;

                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;

                let fee_utxo = if let Some(outpoint) = *fee_utxo {
                    let fee_tx_out = fetch_utxo(outpoint).await?;
                    Some((outpoint, fee_tx_out))
                } else {
                    None
                };

                let input_option_secrets =
                    option_tx_out.unblind(SECP256K1, blinder_keypair.secret_key())?;
                let input_grantor_secrets =
                    grantor_tx_out.unblind(SECP256K1, blinder_keypair.secret_key())?;

                let (partial_pset, expected_asset_amount) = contracts::sdk::build_option_funding(
                    blinder_keypair.public_key(),
                    (
                        *option_asset_utxo,
                        option_tx_out.clone(),
                        input_option_secrets,
                    ),
                    (
                        *grantor_asset_utxo,
                        grantor_tx_out.clone(),
                        input_grantor_secrets,
                    ),
                    (*collateral_utxo, collateral_tx_out.clone()),
                    fee_utxo.as_ref(),
                    &option_arguments,
                    *collateral_amount,
                )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let blinder_secret_key = blinder_keypair.secret_key();
                let tx = partial_pset.finalize(
                    Self::NETWORK,
                    |network: SimplicityNetwork, tx, utxos| {
                        let address_params = network.address_params();
                        let genesis_block_hash = network.genesis_block_hash();

                        // Unblind outputs from the finalized (blinded) transaction
                        let output_option_secrets = tx.output[0]
                            .unblind(SECP256K1, blinder_secret_key)
                            .map_err(|e| {
                                simplicityhl_core::ProgramError::WitnessSatisfaction(e.to_string())
                            })?;
                        let output_grantor_secrets = tx.output[1]
                            .unblind(SECP256K1, blinder_secret_key)
                            .map_err(|e| {
                                simplicityhl_core::ProgramError::WitnessSatisfaction(e.to_string())
                            })?;

                        // Build OptionBranch from blinding factors
                        let (input_option_abf, input_option_vbf) =
                            blinding_factors_from_secrets(&input_option_secrets);
                        let (input_grantor_abf, input_grantor_vbf) =
                            blinding_factors_from_secrets(&input_grantor_secrets);
                        let (output_option_abf, output_option_vbf) =
                            blinding_factors_from_secrets(&output_option_secrets);
                        let (output_grantor_abf, output_grantor_vbf) =
                            blinding_factors_from_secrets(&output_grantor_secrets);

                        let option_branch = OptionBranch::Funding {
                            expected_asset_amount,
                            input_option_abf,
                            input_option_vbf,
                            input_grantor_abf,
                            input_grantor_vbf,
                            output_option_abf,
                            output_option_vbf,
                            output_grantor_abf,
                            output_grantor_vbf,
                        };

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            address_params,
                            genesis_block_hash,
                        )?;

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            1,
                            &option_branch,
                            address_params,
                            genesis_block_hash,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;
                        let signature = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            2,
                            address_params,
                            genesis_block_hash,
                        )?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature,
                            2,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )
                    },
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
                    Self::NETWORK.address_params(),
                    &contracts::options::get_options_address,
                )?;

                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;
                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let asset_tx_out = fetch_utxo(*asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (partial_pset, option_branch) = contracts::sdk::build_option_exercise(
                    (*collateral_utxo, collateral_tx_out.clone()),
                    (*option_asset_utxo, option_tx_out.clone()),
                    (*asset_utxo, asset_tx_out.clone()),
                    Some((*fee_utxo, fee_tx_out.clone())),
                    *amount_to_burn,
                    &option_arguments,
                )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let tx = partial_pset.finalize(
                    Self::NETWORK,
                    |network: SimplicityNetwork, tx, utxos| {
                        let address_params = network.address_params();
                        let genesis_block_hash = network.genesis_block_hash();

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            address_params,
                            genesis_block_hash,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            1,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            2,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_3 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            3,
                            address_params,
                            genesis_block_hash,
                        )?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_3,
                            3,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )
                    },
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
                    Self::NETWORK.address_params(),
                    &contracts::options::get_options_address,
                )?;

                let settlement_tx_out = fetch_utxo(*settlement_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (partial_pset, option_branch) = contracts::sdk::build_option_settlement(
                    (*settlement_asset_utxo, settlement_tx_out.clone()),
                    (*grantor_asset_utxo, grantor_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    *grantor_token_amount_to_burn,
                    &option_arguments,
                )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let tx = partial_pset.finalize(
                    Self::NETWORK,
                    |network: SimplicityNetwork, tx, utxos| {
                        let address_params = network.address_params();
                        let genesis_block_hash = network.genesis_block_hash();

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            address_params,
                            genesis_block_hash,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            1,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            2,
                            address_params,
                            genesis_block_hash,
                        )?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )
                    },
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
                    Self::NETWORK.address_params(),
                    &contracts::options::get_options_address,
                )?;

                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (partial_pset, option_branch) = contracts::sdk::build_option_expiry(
                    (*collateral_utxo, collateral_tx_out.clone()),
                    (*grantor_asset_utxo, grantor_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    *grantor_token_amount_to_burn,
                    &option_arguments,
                )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let tx = partial_pset.finalize(
                    Self::NETWORK,
                    |network: SimplicityNetwork, tx, utxos| {
                        let address_params = network.address_params();
                        let genesis_block_hash = network.genesis_block_hash();

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            address_params,
                            genesis_block_hash,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            1,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            2,
                            address_params,
                            genesis_block_hash,
                        )?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )
                    },
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
                    Self::NETWORK.address_params(),
                    &contracts::options::get_options_address,
                )?;

                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;
                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let fee_tx_out = fetch_utxo(*fee_utxo).await?;

                let (partial_pset, option_branch) = contracts::sdk::build_option_cancellation(
                    (*collateral_utxo, collateral_tx_out.clone()),
                    (*option_asset_utxo, option_tx_out.clone()),
                    (*grantor_asset_utxo, grantor_tx_out.clone()),
                    (*fee_utxo, fee_tx_out.clone()),
                    &option_arguments,
                    *amount_to_burn,
                )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let tx = partial_pset.finalize(
                    Self::NETWORK,
                    |network: SimplicityNetwork, tx, utxos| {
                        let address_params = network.address_params();
                        let genesis_block_hash = network.genesis_block_hash();

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            address_params,
                            genesis_block_hash,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            1,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            2,
                            address_params,
                            genesis_block_hash,
                        )?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )?;

                        let signature_3 = create_p2pk_signature(
                            &tx,
                            utxos,
                            &keypair,
                            3,
                            address_params,
                            genesis_block_hash,
                        )?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_3,
                            3,
                            address_params,
                            genesis_block_hash,
                            TrackerLogLevel::None,
                        )
                    },
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
