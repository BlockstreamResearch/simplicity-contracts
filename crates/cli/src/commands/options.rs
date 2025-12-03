use anyhow::Result;
use clap::Subcommand;
use contracts::OptionsArguments;

use simplicityhl_core::{
    Encodable, broadcast_tx, derive_public_blinder_key, get_new_asset_entropy,
};

use simplicityhl::simplicity::elements::AddressParams;
use simplicityhl::simplicity::elements::hex::ToHex;

use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;
use simplicityhl::elements::OutPoint;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::simplicity::hex::DisplayHex;

#[derive(Subcommand, Debug)]
pub enum Options {
    /// Compute Options address and `OPTION_SCRIPT_HASH` for creation program
    CreationOption {
        /// First fee utxo
        #[arg(long = "first-fee-utxo")]
        first_fee_utxo: OutPoint,
        /// Second fee utxo
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
    /// Fund Options using provided asset entropies (hex)
    FundingOption {
        /// Option asset utxo
        #[arg(long = "option-asset-utxo")]
        option_asset_utxo: OutPoint,
        /// Grantor asset utxo
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// Collateral and fee utxo
        #[arg(long = "collateral-and-fee-utxo")]
        collateral_and_fee_utxo: OutPoint,
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Collateral amount
        #[arg(long = "collateral-amount")]
        collateral_amount: u64,
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
    /// Exercise path: burn option tokens and settle against settlement asset
    ExerciseOption {
        /// Collateral UTXO at the options address (LBTC)
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Option asset utxo
        #[arg(long = "option-asset-utxo")]
        option_asset_utxo: OutPoint,
        /// Asset utxo
        #[arg(long = "asset-utxo")]
        asset_utxo: OutPoint,
        /// Fee utxo
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of option tokens to burn
        #[arg(long = "amount-to-burn")]
        amount_to_burn: u64,
        /// Fee in LBTC to pay (deducted from collateral input)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index for P2PK fee input (change + signing)
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Settlement path: burn grantor tokens against settlement asset held by the covenant (contract)
    SettlementOption {
        /// Settlement asset UTXO at the options address
        #[arg(long = "settlement-asset-utxo")]
        settlement_asset_utxo: OutPoint,
        /// Grantor token UTXO consumed for burning
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// LBTC UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of grantor tokens to burn
        #[arg(long = "grantor-token-amount-to-burn")]
        grantor_token_amount_to_burn: u64,
        /// Fee in LBTC to pay
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index for P2PK fee input (change + signing)
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Expiry path: burn grantor tokens and withdraw collateral to P2PK (contract)
    ExpiryOption {
        /// Collateral UTXO at the options address (LBTC)
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Grantor token UTXO consumed for burning
        #[arg(long = "grantor-asset-utxo")]
        grantor_asset_utxo: OutPoint,
        /// Fee UTXO used to pay fees (P2PK)
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of grantor tokens to burn
        #[arg(long = "grantor-token-amount-to-burn")]
        grantor_token_amount_to_burn: u64,
        /// Fee in LBTC to pay (deducted from collateral input)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Recipient account index to withdraw collateral to (P2PK)
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Cancellation path: burn both tokens and withdraw some collateral to P2PK (contract)
    CancellationOption {
        /// Collateral UTXO at the options address (LBTC)
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
        /// Option taproot pubkey gen
        #[arg(long = "option-taproot-pubkey-gen")]
        option_taproot_pubkey_gen: String,
        /// Amount of both tokens to burn
        #[arg(long = "amount-to-burn")]
        amount_to_burn: u64,
        /// Fee in LBTC to pay (deducted from collateral input)
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Recipient account index to withdraw collateral to (P2PK)
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    Import {
        /// Option taproot pubkey gen
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
            Options::Import {
                option_taproot_pubkey_gen,
                encoded_options_arguments,
            } => Store::load()?.import_arguments(
                option_taproot_pubkey_gen,
                encoded_options_arguments,
                &AddressParams::LIQUID_TESTNET,
                &contracts::get_options_address,
            ),
            Options::Export {
                option_taproot_pubkey_gen,
            } => {
                println!(
                    "{}",
                    Store::load()?.export_arguments(option_taproot_pubkey_gen)?
                );
                Ok(())
            }
            Options::CreationOption {
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
                let blinder_key = derive_public_blinder_key();

                let (
                    first_asset_entropy,
                    second_asset_entropy,
                    option_arguments,
                    options_taproot_pubkey_gen,
                    tx,
                ) = contracts_adapter::options::creation_option(
                    &keypair,
                    &blinder_key,
                    *first_fee_utxo,
                    *second_fee_utxo,
                    *start_time,
                    *expiry_time,
                    *collateral_per_contract,
                    *settlement_per_contract,
                    settlement_asset_id_hex_be,
                    *fee_amount,
                )
                .await?;

                store.import_arguments(
                    &options_taproot_pubkey_gen.to_string(),
                    &option_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                store.store.insert(
                    format!("first_entropy_{options_taproot_pubkey_gen}"),
                    get_new_asset_entropy(first_fee_utxo, first_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;
                store.store.insert(
                    format!("second_entropy_{options_taproot_pubkey_gen}"),
                    get_new_asset_entropy(second_fee_utxo, second_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx).await?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Options::FundingOption {
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
                let blinding_key = derive_public_blinder_key();

                let Some(first_entropy_hex) = store
                    .store
                    .get(format!("first_entropy_{option_taproot_pubkey_gen}"))?
                else {
                    anyhow::bail!("First entropy not found");
                };
                let Some(second_entropy_hex) = store
                    .store
                    .get(format!("second_entropy_{option_taproot_pubkey_gen}"))?
                else {
                    anyhow::bail!("Second entropy not found");
                };

                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let tx = contracts_adapter::options::funding_option(
                    option_asset_utxo,
                    grantor_asset_utxo,
                    collateral_and_fee_utxo,
                    option_taproot_pubkey_gen,
                    collateral_amount,
                    fee_amount,
                    &keypair,
                    blinding_key,
                    first_entropy_hex,
                    second_entropy_hex,
                    &option_arguments,
                )
                .await?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx).await?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
                Ok(())
            }
            Options::ExerciseOption {
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

                let tx = contracts_adapter::options::exercise_option(
                    collateral_utxo,
                    option_asset_utxo,
                    asset_utxo,
                    fee_utxo,
                    option_taproot_pubkey_gen,
                    amount_to_burn,
                    fee_amount,
                    &keypair,
                    &option_arguments,
                )
                .await?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx).await?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
                Ok(())
            }
            Options::SettlementOption {
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

                let tx = contracts_adapter::options::settlement_option(
                    settlement_asset_utxo,
                    grantor_asset_utxo,
                    fee_utxo,
                    option_taproot_pubkey_gen,
                    grantor_token_amount_to_burn,
                    fee_amount,
                    &option_arguments,
                    &keypair,
                )
                .await?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx).await?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
                Ok(())
            }
            Options::ExpiryOption {
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

                let tx = contracts_adapter::options::expiry_option(
                    collateral_utxo,
                    grantor_asset_utxo,
                    fee_utxo,
                    option_taproot_pubkey_gen,
                    grantor_token_amount_to_burn,
                    fee_amount,
                    &option_arguments,
                    &keypair,
                )
                .await?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx).await?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
                Ok(())
            }
            Options::CancellationOption {
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

                let tx = contracts_adapter::options::cancellation_option(
                    &keypair,
                    collateral_utxo,
                    option_asset_utxo,
                    grantor_asset_utxo,
                    fee_utxo,
                    option_taproot_pubkey_gen,
                    amount_to_burn,
                    fee_amount,
                    &option_arguments,
                )
                .await?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx).await?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }
                Ok(())
            }
        }
    }
}
