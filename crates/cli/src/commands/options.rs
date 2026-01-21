#![allow(clippy::similar_names)]

use std::str::FromStr;

use anyhow::Result;

use clap::Subcommand;

use contracts::options::build_witness::OptionBranch;
use contracts::options::{OptionsArguments, finalize_options_transaction, get_options_program};
use contracts::sdk::taproot_pubkey_gen::{TaprootPubkeyGen, get_random_seed};
use contracts::sdk::{DEFAULT_TARGET_BLOCKS, SignerTrait, SyncFeeFetcher};

use simplicityhl::elements::OutPoint;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::schnorr::Keypair;
use simplicityhl::elements::secp256k1_zkp::SECP256K1;
use simplicityhl::simplicity::elements::AssetId;
use simplicityhl::simplicity::hex::DisplayHex;
use simplicityhl::tracker::TrackerLogLevel;

use crate::commands::NETWORK;
use crate::explorer::{broadcast_tx, fetch_utxo};
use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;
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
                NETWORK,
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
                        NETWORK,
                    )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let mut partial_pset = partial_pset.fee_rate(fee_rate);
                if let Some(fee_amount) = *fee_amount {
                    partial_pset = partial_pset.fee(fee_amount);
                }

                let tx =
                    partial_pset.finalize(NETWORK, |network: SimplicityNetwork, tx, utxos| {
                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_0 = create_p2pk_signature(&tx, utxos, &keypair, 0, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_0,
                            0,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_1 = create_p2pk_signature(&tx, utxos, &keypair, 1, network)?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            network,
                            TrackerLogLevel::None,
                        )
                    })?;

                println!("options_taproot_pubkey_gen: {options_taproot_pubkey_gen}");

                store.import_arguments(
                    &options_taproot_pubkey_gen.to_string(),
                    &option_arguments.to_hex()?,
                    NETWORK,
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
                fn spawn_funding_signer(
                    branch: OptionBranch,
                    taproot_pubkey_gen: TaprootPubkeyGen,
                    keypair: Keypair,
                    option_arguments: OptionsArguments,
                ) -> impl SignerTrait {
                    move |network: SimplicityNetwork, tx, utxos| {
                        let taproot_pubkey_gen = taproot_pubkey_gen.clone();
                        let keypair = keypair;

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &branch,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            1,
                            &branch,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;
                        let signature = create_p2pk_signature(&tx, utxos, &keypair, 2, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature,
                            2,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        if utxos.len() == 4 {
                            let signature =
                                create_p2pk_signature(&tx, utxos, &keypair, 3, network)?;
                            finalize_p2pk_transaction(
                                tx,
                                utxos,
                                &x_only_public_key,
                                &signature,
                                3,
                                network,
                                TrackerLogLevel::None,
                            )
                        } else {
                            Ok(tx)
                        }
                    }
                }

                let store = Store::load()?;
                let keypair = derive_keypair(*account_index);
                let blinder_keypair = derive_public_blinder_key();

                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    NETWORK,
                    &contracts::options::get_options_address,
                )?;

                let option_tx_out = fetch_utxo(*option_asset_utxo).await?;
                let grantor_tx_out = fetch_utxo(*grantor_asset_utxo).await?;
                let collateral_tx_out = fetch_utxo(*collateral_utxo).await?;

                let fee_utxo = if let Some(outpoint) = *fee_utxo {
                    let fee_tx_out = fetch_utxo(outpoint).await?;
                    Some(&(outpoint, fee_tx_out))
                } else {
                    None
                };

                let input_option_secrets =
                    option_tx_out.unblind(SECP256K1, blinder_keypair.secret_key())?;
                let input_grantor_secrets =
                    grantor_tx_out.unblind(SECP256K1, blinder_keypair.secret_key())?;

                let (partial_pset, expected_asset_amount) = contracts::sdk::build_option_funding(
                    &blinder_keypair,
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
                    fee_utxo,
                    &option_arguments,
                    *collateral_amount,
                )?;

                let fee_rate =
                    contracts::sdk::EsploraFeeFetcher::get_fee_rate(DEFAULT_TARGET_BLOCKS)?;
                let partial_pset = partial_pset.fee_rate(fee_rate);

                let mut utxos = vec![
                    option_tx_out.clone(),
                    grantor_tx_out.clone(),
                    collateral_tx_out.clone(),
                ];

                if let Some((_, fee_tx_out)) = fee_utxo {
                    utxos.push(fee_tx_out.clone());
                }

                let fee_amount = if let Some(fee_amount) = *fee_amount {
                    fee_amount
                } else {
                    // Create Draft pset for initial fee estimation
                    let draft_pset = partial_pset.create_draft_pset(NETWORK)?;
                    let draft_finalized_pset = contracts::sdk::PartialPset::finalize_pset_raw(
                        draft_pset,
                        partial_pset.get_inp_tx_out_sec(),
                        partial_pset.get_spent_tx_outs(),
                    )?;
                    let draft_tx = draft_finalized_pset.extract_tx()?;
                    let draft_branch = contracts::sdk::extract_funding_option_branch(
                        &blinder_keypair,
                        &partial_pset,
                        &draft_tx,
                        expected_asset_amount,
                    )?;
                    let draft_signer = spawn_funding_signer(
                        draft_branch,
                        taproot_pubkey_gen.clone(),
                        keypair,
                        option_arguments.clone(),
                    );
                    let signed_tx = contracts::sdk::PartialPset::sign_tx_raw(
                        draft_tx,
                        partial_pset.get_spent_tx_outs(),
                        NETWORK,
                        draft_signer,
                    )?;
                    contracts::sdk::PartialPset::calculate_fee_raw(&signed_tx, fee_rate)?
                };

                // Create Final pset with obtained fee estimation
                let pset = partial_pset.create_pset(fee_amount, NETWORK)?;
                let finalized_pset = contracts::sdk::PartialPset::finalize_pset_raw(
                    pset,
                    partial_pset.get_inp_tx_out_sec(),
                    partial_pset.get_spent_tx_outs(),
                )?;
                let tx = finalized_pset.extract_tx()?;
                let branch = contracts::sdk::extract_funding_option_branch(
                    &blinder_keypair,
                    &partial_pset,
                    &tx,
                    expected_asset_amount,
                )?;
                let signer = spawn_funding_signer(
                    branch,
                    taproot_pubkey_gen.clone(),
                    keypair,
                    option_arguments.clone(),
                );
                let signed_tx = contracts::sdk::PartialPset::sign_tx_raw(
                    tx,
                    partial_pset.get_spent_tx_outs(),
                    NETWORK,
                    signer,
                )?;

                if *broadcast {
                    println!("Broadcasted txid: {}", broadcast_tx(&signed_tx).await?);
                } else {
                    println!("{}", signed_tx.serialize().to_lower_hex_string());
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
                    NETWORK,
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

                let tx =
                    partial_pset.finalize(NETWORK, |network: SimplicityNetwork, tx, utxos| {
                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(&tx, utxos, &keypair, 1, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(&tx, utxos, &keypair, 2, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_3 = create_p2pk_signature(&tx, utxos, &keypair, 3, network)?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_3,
                            3,
                            network,
                            TrackerLogLevel::None,
                        )
                    })?;

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
                    NETWORK,
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

                let tx =
                    partial_pset.finalize(NETWORK, |network: SimplicityNetwork, tx, utxos| {
                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(&tx, utxos, &keypair, 1, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(&tx, utxos, &keypair, 2, network)?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            network,
                            TrackerLogLevel::None,
                        )
                    })?;

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
                    NETWORK,
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

                let tx =
                    partial_pset.finalize(NETWORK, |network: SimplicityNetwork, tx, utxos| {
                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(&tx, utxos, &keypair, 1, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(&tx, utxos, &keypair, 2, network)?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            network,
                            TrackerLogLevel::None,
                        )
                    })?;

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
                    NETWORK,
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

                let tx =
                    partial_pset.finalize(NETWORK, |network: SimplicityNetwork, tx, utxos| {
                        let tx = finalize_options_transaction(
                            tx,
                            &taproot_pubkey_gen.get_x_only_pubkey(),
                            &get_options_program(&option_arguments)?,
                            utxos,
                            0,
                            &option_branch,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let x_only_public_key = keypair.x_only_public_key().0;

                        let signature_1 = create_p2pk_signature(&tx, utxos, &keypair, 1, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_1,
                            1,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_2 = create_p2pk_signature(&tx, utxos, &keypair, 2, network)?;
                        let tx = finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_2,
                            2,
                            network,
                            TrackerLogLevel::None,
                        )?;

                        let signature_3 = create_p2pk_signature(&tx, utxos, &keypair, 3, network)?;
                        finalize_p2pk_transaction(
                            tx,
                            utxos,
                            &x_only_public_key,
                            &signature_3,
                            3,
                            network,
                            TrackerLogLevel::None,
                        )
                    })?;

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
