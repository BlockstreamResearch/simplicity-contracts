use anyhow::Result;
use clap::Subcommand;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::secp256k1_zkp::{PublicKey, SecretKey};
use simplicityhl::elements::OutPoint;
use simplicityhl::simplicity::hex::DisplayHex;

use simplicityhl_core::{
    broadcast_tx, derive_public_blinder_key, Encodable, TaprootPubkeyGen,
    LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS,
};

use crate::modules::keys::derive_secret_key_from_index;
use crate::modules::store::Store;
use crate::modules::utils::derive_keypair;
use contracts::MergeBranch;
use contracts::{oracle_msg, DCDArguments};
use contracts_adapter::dcd::{DcdInitParams, DcdInitResponse, COLLATERAL_ASSET_ID};
use simplicityhl::simplicity::elements::AddressParams;

/// DCD subcommands.
#[derive(Subcommand, Debug)]
pub enum Dcd {
    /// Import previously-encoded DCD arguments and bind to taproot pubkey gen
    Import {
        /// TaprootPubkeyGen string
        #[arg(long = "taproot-pubkey-gen")]
        taproot_pubkey_gen: String,
        /// Encoded DCD arguments (hex)
        #[arg(long = "encoded-dcd-arguments")]
        encoded_dcd_arguments: String,
    },
    /// Export stored DCD arguments (hex) by taproot pubkey gen
    Export {
        /// TaprootPubkeyGen string
        #[arg(long = "taproot-pubkey-gen")]
        taproot_pubkey_gen: String,
    },
    /// Produce oracle Schnorr signature for (settlement-height, price-at-current-block-height)
    OracleSignature {
        /// Price at current block height
        #[arg(long = "price-at-current-block-height")]
        price_at_current_block_height: u64,
        /// Settlement height
        #[arg(long = "settlement-height")]
        settlement_height: u32,
        /// Oracle account index to derive key from SEED_HEX
        #[arg(long = "oracle-account-index")]
        oracle_account_index: u32,
    },
    /// Merge 2 token UTXOs into 1
    Merge2Tokens {
        /// First token UTXO
        #[arg(long = "token-utxo-1")]
        token_utxo_1: OutPoint,
        /// Second token UTXO
        #[arg(long = "token-utxo-2")]
        token_utxo_2: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Merge 3 token UTXOs into 1
    Merge3Tokens {
        /// First token UTXO
        #[arg(long = "token-utxo-1")]
        token_utxo_1: OutPoint,
        /// Second token UTXO
        #[arg(long = "token-utxo-2")]
        token_utxo_2: OutPoint,
        /// Third token UTXO
        #[arg(long = "token-utxo-3")]
        token_utxo_3: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Merge 4 token UTXOs into 1
    Merge4Tokens {
        /// First token UTXO
        #[arg(long = "token-utxo-1")]
        token_utxo_1: OutPoint,
        /// Second token UTXO
        #[arg(long = "token-utxo-2")]
        token_utxo_2: OutPoint,
        /// Third token UTXO
        #[arg(long = "token-utxo-3")]
        token_utxo_3: OutPoint,
        /// Fourth token UTXO
        #[arg(long = "token-utxo-4")]
        token_utxo_4: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    Creation {
        /// First fee utxo
        #[arg(long = "first-fee-utxo")]
        first_fee_utxo: OutPoint,
        /// Second fee utxo
        #[arg(long = "second-fee-utxo")]
        second_fee_utxo: OutPoint,
        /// Third fee utxo
        #[arg(long = "third-fee-utxo")]
        third_fee_utxo: OutPoint,
        /// Taker funding start time
        #[arg(long = "taker-funding-start-time")]
        taker_funding_start_time: u32,
        /// Taker funding end time
        #[arg(long = "taker-funding-end-time")]
        taker_funding_end_time: u32,
        /// Contract expiry time
        #[arg(long = "contract-expiry-time")]
        contract_expiry_time: u32,
        /// Early termination end time
        #[arg(long = "early-termination-end-time")]
        early_termination_end_time: u32,
        /// Settlement height
        #[arg(long = "settlement-height")]
        settlement_height: u32,
        /// Principal collateral amount
        #[arg(long = "principal-collateral-amount")]
        principal_collateral_amount: u64,
        /// Incentive basis points
        #[arg(long = "incentive-basis-points")]
        incentive_basis_points: u64,
        /// Filler per principal collateral
        #[arg(long = "filler-per-principal-collateral")]
        filler_per_principal_collateral: u64,
        /// Strike price
        #[arg(long = "strike-price")]
        strike_price: u64,
        /// Settlement asset id
        #[arg(long = "settlement-asset-id")]
        settlement_asset_id: String,
        /// Oracle public key
        #[arg(long = "oracle-public-key")]
        oracle_public_key: PublicKey,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Maker funding path: deposit collateral and settlement assets, issue tokens
    MakerFundingPath {
        /// Filler token UTXO for issuance
        #[arg(long = "filler-token-utxo")]
        filler_token_utxo: OutPoint,
        /// Grantor collateral token UTXO
        #[arg(long = "grantor-collateral-token-utxo")]
        grantor_collateral_token_utxo: OutPoint,
        /// Grantor settlement token UTXO
        #[arg(long = "grantor-settlement-token-utxo")]
        grantor_settlement_token_utxo: OutPoint,
        /// Settlement asset UTXO
        #[arg(long = "settlement-asset-utxo")]
        settlement_asset_utxo: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Taker funding path: deposit collateral, receive filler tokens
    TakerFundingPath {
        /// Filler token UTXO from covenant
        #[arg(long = "filler-token-utxo")]
        filler_token_utxo: OutPoint,
        /// Collateral UTXO to deposit
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Collateral amount to deposit
        #[arg(long = "collateral-amount-to-deposit")]
        collateral_amount_to_deposit: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Taker early termination path: return filler tokens, get collateral back
    TakerEarlyTermination {
        /// Collateral UTXO at covenant
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Filler token UTXO to burn
        #[arg(long = "filler-token-utxo")]
        filler_token_utxo: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Filler token amount to return
        #[arg(long = "filler-token-amount-to-return")]
        filler_token_amount_to_return: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Maker collateral termination path: burn grantor collateral tokens, get collateral back
    MakerCollateralTermination {
        /// Collateral UTXO at covenant
        #[arg(long = "collateral-utxo")]
        collateral_utxo: OutPoint,
        /// Grantor collateral token UTXO to burn
        #[arg(long = "grantor-collateral-token-utxo")]
        grantor_collateral_token_utxo: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Grantor collateral token amount to burn
        #[arg(long = "grantor-collateral-amount-to-burn")]
        grantor_collateral_amount_to_burn: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Maker settlement termination path: burn grantor settlement tokens, get settlement asset back
    MakerSettlementTermination {
        /// Settlement asset UTXO at covenant
        #[arg(long = "settlement-asset-utxo")]
        settlement_asset_utxo: OutPoint,
        /// Grantor settlement token UTXO to burn
        #[arg(long = "grantor-settlement-token-utxo")]
        grantor_settlement_token_utxo: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Grantor settlement token amount to burn
        #[arg(long = "grantor-settlement-amount-to-burn")]
        grantor_settlement_amount_to_burn: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Maker settlement path: settle at maturity based on oracle price
    MakerSettlement {
        /// Asset UTXO at covenant (collateral or settlement depending on price)
        #[arg(long = "asset-utxo")]
        asset_utxo: OutPoint,
        /// Grantor collateral token UTXO to burn
        #[arg(long = "grantor-collateral-token-utxo")]
        grantor_collateral_token_utxo: OutPoint,
        /// Grantor settlement token UTXO to burn
        #[arg(long = "grantor-settlement-token-utxo")]
        grantor_settlement_token_utxo: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Price at current block height (from oracle)
        #[arg(long = "price-at-current-block-height")]
        price_at_current_block_height: u64,
        /// Oracle signature (hex)
        #[arg(long = "oracle-signature")]
        oracle_signature: PublicKey,
        /// Grantor token amount to burn
        #[arg(long = "grantor-amount-to-burn")]
        grantor_amount_to_burn: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
    /// Taker settlement path: settle at maturity based on oracle price
    TakerSettlement {
        /// Asset UTXO at covenant (collateral or settlement depending on price)
        #[arg(long = "asset-utxo")]
        asset_utxo: OutPoint,
        /// Filler token UTXO to burn
        #[arg(long = "filler-token-utxo")]
        filler_token_utxo: OutPoint,
        /// Fee UTXO
        #[arg(long = "fee-utxo")]
        fee_utxo: OutPoint,
        /// DCD taproot pubkey gen
        #[arg(long = "dcd-taproot-pubkey-gen")]
        dcd_taproot_pubkey_gen: String,
        /// Price at current block height (from oracle)
        #[arg(long = "price-at-current-block-height")]
        price_at_current_block_height: u64,
        /// Oracle signature (hex)
        #[arg(long = "oracle-signature")]
        oracle_signature: String,
        /// Filler token amount to burn
        #[arg(long = "filler-amount-to-burn")]
        filler_amount_to_burn: u64,
        /// Fee amount
        #[arg(long = "fee-amount")]
        fee_amount: u64,
        /// Account index
        #[arg(long = "account-index")]
        account_index: u32,
        /// When set, broadcast the built transaction via Esplora and print txid
        #[arg(long = "broadcast")]
        broadcast: bool,
    },
}

impl Dcd {
    #[allow(unused)]
    pub fn handle(&self) -> Result<()> {
        match self {
            Dcd::Import {
                taproot_pubkey_gen,
                encoded_dcd_arguments,
            } => Store::load()?.import_arguments(
                taproot_pubkey_gen,
                encoded_dcd_arguments,
                &simplicityhl::simplicity::elements::AddressParams::LIQUID_TESTNET,
                &contracts::get_dcd_address,
            ),
            Dcd::Export { taproot_pubkey_gen } => {
                println!("{}", Store::load()?.export_arguments(taproot_pubkey_gen)?);
                Ok(())
            }
            Dcd::OracleSignature {
                price_at_current_block_height,
                settlement_height,
                oracle_account_index,
            } => {
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*oracle_account_index),
                );
                let msg = secp256k1::Message::from_digest_slice(&oracle_msg(
                    *settlement_height,
                    *price_at_current_block_height,
                ))?;
                let sig = secp256k1::SECP256K1.sign_schnorr(&msg, &keypair);
                println!("{}", hex::encode(sig.serialize()));
                Ok(())
            }
            Dcd::Merge2Tokens {
                token_utxo_1,
                token_utxo_2,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let tx = contracts_adapter::dcd::DcdManager::merge_tokens(
                    &keypair,
                    &[*token_utxo_1, *token_utxo_2],
                    *fee_utxo,
                    *fee_amount,
                    MergeBranch::Two,
                    &taproot_pubkey_gen,
                    &dcd_arguments,
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
            Dcd::Merge3Tokens {
                token_utxo_1,
                token_utxo_2,
                token_utxo_3,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let tx = contracts_adapter::dcd::DcdManager::merge_tokens(
                    &keypair,
                    &[*token_utxo_1, *token_utxo_2, *token_utxo_3],
                    *fee_utxo,
                    *fee_amount,
                    MergeBranch::Three,
                    &taproot_pubkey_gen,
                    &dcd_arguments,
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
            Dcd::Merge4Tokens {
                token_utxo_1,
                token_utxo_2,
                token_utxo_3,
                token_utxo_4,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let tx = contracts_adapter::dcd::DcdManager::merge_tokens(
                    &keypair,
                    &[*token_utxo_1, *token_utxo_2, *token_utxo_3, *token_utxo_4],
                    *fee_utxo,
                    *fee_amount,
                    MergeBranch::Four,
                    &taproot_pubkey_gen,
                    &dcd_arguments,
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
            Dcd::Creation {
                first_fee_utxo,
                second_fee_utxo,
                third_fee_utxo,
                taker_funding_start_time,
                taker_funding_end_time,
                contract_expiry_time,
                early_termination_end_time,
                settlement_height,
                principal_collateral_amount,
                incentive_basis_points,
                filler_per_principal_collateral,
                strike_price,
                settlement_asset_id,
                oracle_public_key,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let blinding_key = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let DcdInitResponse {
                    tx,
                    filler_token_entropy: first_asset_entropy,
                    grantor_collateral_token_entropy: second_asset_entropy,
                    grantor_settlement_token_entropy: third_asset_entropy,
                    taproot_pubkey_gen: dcd_taproot_pubkey_gen,
                    dcd_args: dcd_arguments,
                } = contracts_adapter::dcd::DcdManager::maker_init(
                    &keypair,
                    &blinding_key,
                    &[*first_fee_utxo, *second_fee_utxo, *third_fee_utxo],
                    DcdInitParams {
                        taker_funding_start_time: *taker_funding_start_time,
                        taker_funding_end_time: *taker_funding_end_time,
                        contract_expiry_time: *contract_expiry_time,
                        early_termination_end_time: *early_termination_end_time,
                        settlement_height: *settlement_height,
                        principal_collateral_amount: *principal_collateral_amount,
                        incentive_basis_points: *incentive_basis_points,
                        filler_per_principal_collateral: *filler_per_principal_collateral,
                        strike_price: *strike_price,
                        collateral_asset_id: COLLATERAL_ASSET_ID.to_hex(),
                        settlement_asset_id: settlement_asset_id.clone(),
                        oracle_public_key: *oracle_public_key,
                    },
                    *fee_amount,
                    &AddressParams::LIQUID_TESTNET,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                println!("dcd_taproot_pubkey_gen: {}", dcd_taproot_pubkey_gen);

                store.import_arguments(
                    &dcd_taproot_pubkey_gen.to_string(),
                    &dcd_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                store.store.insert(
                    format!("first_entropy_{}", dcd_taproot_pubkey_gen),
                    first_asset_entropy.as_bytes(),
                )?;

                store.store.insert(
                    format!("second_entropy_{}", dcd_taproot_pubkey_gen),
                    second_asset_entropy.as_bytes(),
                )?;

                store.store.insert(
                    format!("third_entropy_{}", dcd_taproot_pubkey_gen),
                    third_asset_entropy.as_bytes(),
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                    false => println!("{}", tx.serialize().to_lower_hex_string()),
                }

                Ok(())
            }
            Dcd::MakerFundingPath {
                filler_token_utxo,
                grantor_collateral_token_utxo,
                grantor_settlement_token_utxo,
                settlement_asset_utxo,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = derive_keypair(*account_index);

                let blinding_key = derive_public_blinder_key();

                let Some(first_entropy_hex) = store
                    .store
                    .get(format!("first_entropy_{}", dcd_taproot_pubkey_gen))?
                else {
                    anyhow::bail!("First entropy not found");
                };
                let Some(second_entropy_hex) = store
                    .store
                    .get(format!("second_entropy_{}", dcd_taproot_pubkey_gen))?
                else {
                    anyhow::bail!("Second entropy not found");
                };
                let Some(third_entropy_hex) = store
                    .store
                    .get(format!("third_entropy_{}", dcd_taproot_pubkey_gen))?
                else {
                    anyhow::bail!("Third entropy not found");
                };

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::maker_funding(
                    &keypair,
                    &blinding_key,
                    (*filler_token_utxo, first_entropy_hex),
                    (*grantor_collateral_token_utxo, second_entropy_hex),
                    (*grantor_settlement_token_utxo, third_entropy_hex),
                    *settlement_asset_utxo,
                    *fee_utxo,
                    *fee_amount,
                    &taproot_pubkey_gen,
                    &dcd_arguments,
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
            Dcd::TakerFundingPath {
                filler_token_utxo,
                collateral_utxo,
                dcd_taproot_pubkey_gen,
                collateral_amount_to_deposit,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::taker_funding(
                    &keypair,
                    *filler_token_utxo,
                    *collateral_utxo,
                    *collateral_amount_to_deposit,
                    *fee_amount,
                    &taproot_pubkey_gen,
                    &dcd_arguments,
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
            Dcd::TakerEarlyTermination {
                collateral_utxo,
                filler_token_utxo,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                filler_token_amount_to_return,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::taker_early_termination(
                    &keypair,
                    *collateral_utxo,
                    *filler_token_utxo,
                    *fee_utxo,
                    *filler_token_amount_to_return,
                    *fee_amount,
                    &taproot_pubkey_gen,
                    &dcd_arguments,
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
            Dcd::MakerCollateralTermination {
                collateral_utxo,
                grantor_collateral_token_utxo,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                grantor_collateral_amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::maker_collateral_termination(
                    &keypair,
                    *collateral_utxo,
                    *grantor_collateral_token_utxo,
                    *fee_utxo,
                    *grantor_collateral_amount_to_burn,
                    *fee_amount,
                    &dcd_arguments,
                    &taproot_pubkey_gen,
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
            Dcd::MakerSettlementTermination {
                settlement_asset_utxo,
                grantor_settlement_token_utxo,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                grantor_settlement_amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::maker_settlement_termination(
                    &keypair,
                    *settlement_asset_utxo,
                    *grantor_settlement_token_utxo,
                    *fee_utxo,
                    *grantor_settlement_amount_to_burn,
                    *fee_amount,
                    &dcd_arguments,
                    &taproot_pubkey_gen,
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
            Dcd::MakerSettlement {
                asset_utxo,
                grantor_collateral_token_utxo,
                grantor_settlement_token_utxo,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                price_at_current_block_height,
                oracle_signature,
                grantor_amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::maker_settlement(
                    &keypair,
                    *asset_utxo,
                    *grantor_collateral_token_utxo,
                    *grantor_settlement_token_utxo,
                    *fee_utxo,
                    *price_at_current_block_height,
                    *grantor_amount_to_burn,
                    oracle_signature.to_hex(),
                    *fee_amount,
                    &dcd_arguments,
                    &taproot_pubkey_gen,
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
            Dcd::TakerSettlement {
                asset_utxo,
                filler_token_utxo,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                price_at_current_block_height,
                oracle_signature,
                filler_amount_to_burn,
                fee_amount,
                account_index,
                broadcast,
            } => {
                let store = Store::load()?;

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );
                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                let tx = contracts_adapter::dcd::DcdManager::taker_settlement(
                    &keypair,
                    *asset_utxo,
                    *filler_token_utxo,
                    *fee_utxo,
                    *price_at_current_block_height,
                    *filler_amount_to_burn,
                    *fee_amount,
                    oracle_signature,
                    &dcd_arguments,
                    &taproot_pubkey_gen,
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
        }
    }
}
