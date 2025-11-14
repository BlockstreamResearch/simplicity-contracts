use std::str::FromStr;

use crate::modules::keys::derive_secret_key_from_index;
use crate::modules::store::Store;

use anyhow::Result;
use clap::Subcommand;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::elements::hashes::sha256;
use simplicityhl::elements::hex::ToHex;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::secp256k1_zkp::{Secp256k1, SecretKey};
use simplicityhl::elements::{AssetId, OutPoint, Sequence, TxOut, TxOutSecrets};
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::hex::DisplayHex;

use simplicityhl_core::{
    Encodable, LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, TaprootPubkeyGen,
    broadcast_tx, fetch_utxo, finalize_p2pk_transaction, finalize_transaction,
    get_new_asset_entropy, get_p2pk_address, get_random_seed,
};

use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::{AddressParams, LockTime, Script, Transaction};

use contracts::{
    DCDArguments, DCDRatioArguments, build_dcd_witness, finalize_dcd_transaction_on_liquid_testnet,
    get_dcd_program, oracle_msg,
};
use contracts::{DcdBranch, MergeBranch, TokenBranch};

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
        oracle_public_key: String,
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
        oracle_signature: String,
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
            } => handle_merge_tokens(
                vec![*token_utxo_1, *token_utxo_2],
                *fee_utxo,
                dcd_taproot_pubkey_gen,
                *fee_amount,
                *account_index,
                *broadcast,
                MergeBranch::Two,
            ),
            Dcd::Merge3Tokens {
                token_utxo_1,
                token_utxo_2,
                token_utxo_3,
                fee_utxo,
                dcd_taproot_pubkey_gen,
                fee_amount,
                account_index,
                broadcast,
            } => handle_merge_tokens(
                vec![*token_utxo_1, *token_utxo_2, *token_utxo_3],
                *fee_utxo,
                dcd_taproot_pubkey_gen,
                *fee_amount,
                *account_index,
                *broadcast,
                MergeBranch::Three,
            ),
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
            } => handle_merge_tokens(
                vec![*token_utxo_1, *token_utxo_2, *token_utxo_3, *token_utxo_4],
                *fee_utxo,
                dcd_taproot_pubkey_gen,
                *fee_amount,
                *account_index,
                *broadcast,
                MergeBranch::Four,
            ),
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

                let first_utxo = fetch_utxo(*first_fee_utxo)?;
                let second_utxo = fetch_utxo(*second_fee_utxo)?;
                let third_utxo = fetch_utxo(*third_fee_utxo)?;

                let first_asset_entropy = get_random_seed();
                let second_asset_entropy = get_random_seed();
                let third_asset_entropy = get_random_seed();

                let mut first_issuance_tx = Input::from_prevout(*first_fee_utxo);
                first_issuance_tx.witness_utxo = Some(first_utxo.clone());
                first_issuance_tx.issuance_value_amount = None;
                first_issuance_tx.issuance_inflation_keys = Some(1);
                first_issuance_tx.issuance_asset_entropy = Some(first_asset_entropy);

                let mut second_issuance_tx = Input::from_prevout(*second_fee_utxo);
                second_issuance_tx.witness_utxo = Some(second_utxo.clone());
                second_issuance_tx.issuance_value_amount = None;
                second_issuance_tx.issuance_inflation_keys = Some(1);
                second_issuance_tx.issuance_asset_entropy = Some(second_asset_entropy);

                let mut third_issuance_tx = Input::from_prevout(*third_fee_utxo);
                third_issuance_tx.witness_utxo = Some(third_utxo.clone());
                third_issuance_tx.issuance_value_amount = None;
                third_issuance_tx.issuance_inflation_keys = Some(1);
                third_issuance_tx.issuance_asset_entropy = Some(third_asset_entropy);

                let (first_asset, first_reissuance_asset) = first_issuance_tx.issuance_ids();
                let (second_asset, second_reissuance_asset) = second_issuance_tx.issuance_ids();
                let (third_asset, third_reissuance_asset) = third_issuance_tx.issuance_ids();

                let ratio_args = DCDRatioArguments::build_from(
                    *principal_collateral_amount,
                    *incentive_basis_points,
                    *strike_price,
                    *filler_per_principal_collateral,
                )?;

                let dcd_arguments = DCDArguments {
                    taker_funding_start_time: *taker_funding_start_time,
                    taker_funding_end_time: *taker_funding_end_time,
                    contract_expiry_time: *contract_expiry_time,
                    early_termination_end_time: *early_termination_end_time,
                    settlement_height: *settlement_height,
                    strike_price: *strike_price,
                    incentive_basis_points: *incentive_basis_points,
                    fee_basis_points: 0,
                    collateral_asset_id_hex_le: LIQUID_TESTNET_BITCOIN_ASSET.to_string(),
                    settlement_asset_id_hex_le: settlement_asset_id.to_string(),
                    filler_token_asset_id_hex_le: first_asset.to_string(),
                    grantor_collateral_token_asset_id_hex_le: second_asset.to_string(),
                    grantor_settlement_token_asset_id_hex_le: third_asset.to_string(),
                    ratio_args: ratio_args.clone(),
                    oracle_public_key: oracle_public_key.clone(),
                };

                let dcd_taproot_pubkey_gen = TaprootPubkeyGen::from(
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                store.import_arguments(
                    &dcd_taproot_pubkey_gen.to_string(),
                    &dcd_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                store.store.insert(
                    format!("first_entropy_{}", dcd_taproot_pubkey_gen),
                    get_new_asset_entropy(first_fee_utxo, first_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                store.store.insert(
                    format!("second_entropy_{}", dcd_taproot_pubkey_gen),
                    get_new_asset_entropy(second_fee_utxo, second_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                store.store.insert(
                    format!("third_entropy_{}", dcd_taproot_pubkey_gen),
                    get_new_asset_entropy(third_fee_utxo, third_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                println!("dcd_taproot_pubkey_gen: {}", dcd_taproot_pubkey_gen);

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let total_input_fee = first_utxo.value.explicit().unwrap()
                    + second_utxo.value.explicit().unwrap()
                    + third_utxo.value.explicit().unwrap();

                let mut pst = PartiallySignedTransaction::new_v2();

                pst.add_input(first_issuance_tx);
                pst.add_input(second_issuance_tx);
                pst.add_input(third_issuance_tx);

                // Add first reissuance token
                let mut output = Output::new_explicit(
                    dcd_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    first_reissuance_asset,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);

                // Add second reissuance token
                let mut output = Output::new_explicit(
                    dcd_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    second_reissuance_asset,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(1);
                pst.add_output(output);

                // Add third reissuance token
                let mut output = Output::new_explicit(
                    dcd_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    third_reissuance_asset,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(2);
                pst.add_output(output);

                // Add L-BTC
                let output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                // Add fee
                let output = Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                let first_input_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: first_utxo.value.explicit().unwrap(),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };
                let second_input_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: second_utxo.value.explicit().unwrap(),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };
                let third_input_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: third_utxo.value.explicit().unwrap(),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };

                let mut inp_txout_sec = std::collections::HashMap::new();
                inp_txout_sec.insert(0, first_input_secrets);
                inp_txout_sec.insert(1, second_input_secrets);
                inp_txout_sec.insert(2, third_input_secrets);

                pst.inputs_mut()[0].blinded_issuance = Some(0x00);
                pst.inputs_mut()[1].blinded_issuance = Some(0x00);
                pst.inputs_mut()[2].blinded_issuance = Some(0x00);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

                let utxos = vec![first_utxo, second_utxo, third_utxo];
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
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let blinding_key = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let filler_utxo = fetch_utxo(*filler_token_utxo)?;
                let grantor_collateral_utxo = fetch_utxo(*grantor_collateral_token_utxo)?;
                let grantor_settlement_utxo = fetch_utxo(*grantor_settlement_token_utxo)?;
                let settlement_utxo = fetch_utxo(*settlement_asset_utxo)?;
                let fee_token_utxo = fetch_utxo(*fee_utxo)?;

                let total_input_fee = fee_token_utxo.value.explicit().unwrap();
                let total_input_asset = settlement_utxo.value.explicit().unwrap();

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
                let first_entropy_hex = hex::decode(first_entropy_hex)?;
                let second_entropy_hex = hex::decode(second_entropy_hex)?;
                let third_entropy_hex = hex::decode(third_entropy_hex)?;

                let mut first_asset_entropy_bytes: [u8; 32] = first_entropy_hex.try_into().unwrap();
                first_asset_entropy_bytes.reverse();
                let mut second_asset_entropy_bytes: [u8; 32] =
                    second_entropy_hex.try_into().unwrap();
                second_asset_entropy_bytes.reverse();
                let mut third_asset_entropy_bytes: [u8; 32] = third_entropy_hex.try_into().unwrap();
                third_asset_entropy_bytes.reverse();

                let first_asset_entropy =
                    sha256::Midstate::from_byte_array(first_asset_entropy_bytes);
                let second_asset_entropy =
                    sha256::Midstate::from_byte_array(second_asset_entropy_bytes);
                let third_asset_entropy =
                    sha256::Midstate::from_byte_array(third_asset_entropy_bytes);

                let blinding_sk = blinding_key.secret_key();

                let first_unblinded = filler_utxo.unblind(&Secp256k1::new(), blinding_sk)?;
                let second_unblinded =
                    grantor_collateral_utxo.unblind(&Secp256k1::new(), blinding_sk)?;
                let third_unblinded =
                    grantor_settlement_utxo.unblind(&Secp256k1::new(), blinding_sk)?;

                let first_token_abf = first_unblinded.asset_bf;
                let second_token_abf = second_unblinded.asset_bf;
                let third_token_abf = third_unblinded.asset_bf;

                let first_asset_id = AssetId::from_entropy(first_asset_entropy);
                let second_asset_id = AssetId::from_entropy(second_asset_entropy);
                let third_asset_id = AssetId::from_entropy(third_asset_entropy);

                let first_token_id =
                    AssetId::reissuance_token_from_entropy(first_asset_entropy, false);
                let second_token_id =
                    AssetId::reissuance_token_from_entropy(second_asset_entropy, false);
                let third_token_id =
                    AssetId::reissuance_token_from_entropy(third_asset_entropy, false);

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    filler_utxo.script_pubkey,
                    "Expected the taproot pubkey gen address to be the same as the filler token utxo script pubkey"
                );

                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    grantor_collateral_utxo.script_pubkey,
                    "Expected the taproot pubkey gen address to be the same as the grantor collateral token utxo script pubkey"
                );

                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    grantor_settlement_utxo.script_pubkey,
                    "Expected the taproot pubkey gen address to be the same as the grantor settlement token utxo script pubkey"
                );

                let settlement_asset_id =
                    AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();

                let mut first_reissuance_tx = Input::from_prevout(*filler_token_utxo);
                first_reissuance_tx.witness_utxo = Some(filler_utxo.clone());
                first_reissuance_tx.issuance_value_amount =
                    Some(dcd_arguments.ratio_args.filler_token_amount);
                first_reissuance_tx.issuance_inflation_keys = None;
                first_reissuance_tx.issuance_asset_entropy =
                    Some(first_asset_entropy.to_byte_array());

                let mut second_reissuance_tx = Input::from_prevout(*grantor_collateral_token_utxo);
                second_reissuance_tx.witness_utxo = Some(grantor_collateral_utxo.clone());
                second_reissuance_tx.issuance_value_amount =
                    Some(dcd_arguments.ratio_args.grantor_collateral_token_amount);
                second_reissuance_tx.issuance_inflation_keys = None;
                second_reissuance_tx.issuance_asset_entropy =
                    Some(second_asset_entropy.to_byte_array());

                let mut third_reissuance_tx = Input::from_prevout(*grantor_settlement_token_utxo);
                third_reissuance_tx.witness_utxo = Some(grantor_settlement_utxo.clone());
                third_reissuance_tx.issuance_value_amount =
                    Some(dcd_arguments.ratio_args.grantor_settlement_token_amount);
                third_reissuance_tx.issuance_inflation_keys = None;
                third_reissuance_tx.issuance_asset_entropy =
                    Some(third_asset_entropy.to_byte_array());

                pst.add_input(first_reissuance_tx);
                pst.add_input(second_reissuance_tx);
                pst.add_input(third_reissuance_tx);

                let mut asset_settlement_tx = Input::from_prevout(*settlement_asset_utxo);
                asset_settlement_tx.witness_utxo = Some(settlement_utxo.clone());
                pst.add_input(asset_settlement_tx);

                let mut fee_tx = Input::from_prevout(*fee_utxo);
                fee_tx.witness_utxo = Some(fee_token_utxo.clone());
                pst.add_input(fee_tx);

                let mut output = Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    first_token_id,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);

                let mut output = Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    second_token_id,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(1);
                pst.add_output(output);

                let mut output = Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    third_token_id,
                    Some(blinding_key.public_key().into()),
                );
                output.blinder_index = Some(2);
                pst.add_output(output);

                pst.add_output(Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    dcd_arguments.ratio_args.interest_collateral_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    dcd_arguments.ratio_args.total_asset_amount,
                    settlement_asset_id,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    dcd_arguments.ratio_args.filler_token_amount,
                    first_asset_id,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    dcd_arguments.ratio_args.grantor_collateral_token_amount,
                    second_asset_id,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    dcd_arguments.ratio_args.grantor_settlement_token_amount,
                    third_asset_id,
                    None,
                ));

                // Collateral change
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee
                        - fee_amount
                        - dcd_arguments.ratio_args.interest_collateral_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                // Asset change
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_asset - dcd_arguments.ratio_args.total_asset_amount,
                    settlement_asset_id,
                    None,
                ));

                // Fee
                pst.add_output(Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                {
                    let input = &mut pst.inputs_mut()[0];
                    input.blinded_issuance = Some(0x00);
                    input.issuance_blinding_nonce = Some(first_token_abf.into_inner());
                }
                {
                    let input = &mut pst.inputs_mut()[1];
                    input.blinded_issuance = Some(0x00);
                    input.issuance_blinding_nonce = Some(second_token_abf.into_inner());
                }
                {
                    let input = &mut pst.inputs_mut()[2];
                    input.blinded_issuance = Some(0x00);
                    input.issuance_blinding_nonce = Some(third_token_abf.into_inner());
                }

                let mut inp_tx_out_sec = std::collections::HashMap::new();
                inp_tx_out_sec.insert(0, first_unblinded);
                inp_tx_out_sec.insert(1, second_unblinded);
                inp_tx_out_sec.insert(2, third_unblinded);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_tx_out_sec)?;

                let utxos = vec![
                    filler_utxo,
                    grantor_collateral_utxo,
                    grantor_settlement_utxo,
                    settlement_utxo,
                    fee_token_utxo,
                ];
                let dcd_program = get_dcd_program(&dcd_arguments)?;

                let witness_values = build_dcd_witness(
                    TokenBranch::default(),
                    DcdBranch::MakerFunding {
                        principal_collateral_amount: dcd_arguments
                            .ratio_args
                            .principal_collateral_amount,
                        principal_asset_amount: dcd_arguments.ratio_args.principal_asset_amount,
                        interest_collateral_amount: dcd_arguments
                            .ratio_args
                            .interest_collateral_amount,
                        interest_asset_amount: dcd_arguments.ratio_args.interest_asset_amount,
                    },
                    MergeBranch::default(),
                );
                let tx = finalize_transaction(
                    pst.extract_tx()?,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values.clone(),
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_transaction(
                    tx,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    1,
                    witness_values.clone(),
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_transaction(
                    tx,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    2,
                    witness_values,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    3,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    4,
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

                let filler_utxo = fetch_utxo(*filler_token_utxo)?;
                let collateral_token_utxo = fetch_utxo(*collateral_utxo)?;

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    filler_utxo.script_pubkey,
                    "Expected the taproot pubkey gen address to be the same as the filler token utxo script pubkey"
                );

                let filler_asset_id = filler_utxo.asset.explicit().unwrap();

                let total_collateral = collateral_token_utxo.value.explicit().unwrap();
                let total_filler = filler_utxo.value.explicit().unwrap();

                anyhow::ensure!(
                    *collateral_amount_to_deposit <= total_collateral,
                    "collateral amount to deposit exceeds input value"
                );

                let total_input_fee = total_collateral - *collateral_amount_to_deposit;

                anyhow::ensure!(
                    *fee_amount <= total_input_fee,
                    "fee amount exceeds input value"
                );

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.global.tx_data.fallback_locktime =
                    Some(LockTime::from_time(dcd_arguments.taker_funding_start_time)?);

                pst.add_input(Input::from_prevout(*filler_token_utxo));
                pst.add_input(Input::from_prevout(*collateral_utxo));

                let filler_to_get = collateral_amount_to_deposit
                    / dcd_arguments.ratio_args.filler_per_principal_collateral;

                let is_filler_change_needed = total_filler != filler_to_get;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                if is_filler_change_needed {
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        total_filler - filler_to_get,
                        filler_asset_id,
                        None,
                    ));
                }

                pst.add_output(Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    *collateral_amount_to_deposit,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    filler_to_get,
                    filler_asset_id,
                    None,
                ));

                // LBTC change
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                let utxos = vec![filler_utxo, collateral_token_utxo];

                let witness_values = build_dcd_witness(
                    TokenBranch::default(),
                    DcdBranch::TakerFunding {
                        collateral_amount_to_deposit: *collateral_amount_to_deposit,
                        filler_token_amount_to_get: filler_to_get,
                        is_change_needed: is_filler_change_needed,
                    },
                    MergeBranch::default(),
                );

                let dcd_program = get_dcd_program(&dcd_arguments)?;

                let tx = finalize_transaction(
                    pst.extract_tx()?,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values,
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

                let collateral_txout = fetch_utxo(*collateral_utxo)?; // DCD input index 0
                let filler_txout = fetch_utxo(*filler_token_utxo)?; // P2PK input index 1
                let fee_txout = fetch_utxo(*fee_utxo)?; // P2PK input index 2

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                anyhow::ensure!(
                    taproot_pubkey_gen.address.script_pubkey() == collateral_txout.script_pubkey,
                    "collateral_utxo must be locked by DCD covenant"
                );

                let available_collateral = collateral_txout.value.explicit().unwrap();
                let filler_asset_id = filler_txout.asset.explicit().unwrap();
                let available_filler = filler_txout.value.explicit().unwrap();
                let total_fee_input = fee_txout.value.explicit().unwrap();

                anyhow::ensure!(
                    *filler_token_amount_to_return <= available_filler,
                    "filler tokens to return exceed available"
                );

                // collateral_to_get = filler_return * FILLER_PER_PRINCIPAL_COLLATERAL
                let collateral_per_principal =
                    dcd_arguments.ratio_args.filler_per_principal_collateral;
                let collateral_to_get =
                    filler_token_amount_to_return.saturating_mul(collateral_per_principal);

                anyhow::ensure!(
                    collateral_to_get <= available_collateral,
                    "required collateral exceeds available"
                );

                let is_change_needed = available_collateral != collateral_to_get;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();

                let mut in0 = Input::from_prevout(*collateral_utxo);
                in0.witness_utxo = Some(collateral_txout.clone());
                pst.add_input(in0);

                let mut in1 = Input::from_prevout(*filler_token_utxo);
                in1.witness_utxo = Some(filler_txout.clone());
                pst.add_input(in1);

                let mut in2 = Input::from_prevout(*fee_utxo);
                in2.witness_utxo = Some(fee_txout.clone());
                pst.add_input(in2);

                // Outputs per SIMF indices
                if is_change_needed {
                    // 0: collateral change back to covenant
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        available_collateral - collateral_to_get,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // return filler to covenant
                pst.add_output(Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    *filler_token_amount_to_return,
                    filler_asset_id,
                    None,
                ));

                // return collateral to user
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    collateral_to_get,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                if *filler_token_amount_to_return != available_filler {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        available_filler - filler_token_amount_to_return,
                        filler_asset_id,
                        None,
                    ));
                }

                // fee change
                anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_fee_input - *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                // fee
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                // Finalize
                let utxos = vec![collateral_txout, filler_txout, fee_txout];
                let dcd_program = get_dcd_program(&dcd_arguments)?;

                // Attach DCD witness to input 0 only
                let witness_values = build_dcd_witness(
                    TokenBranch::default(),
                    DcdBranch::TakerEarlyTermination {
                        is_change_needed,
                        index_to_spend: 0,
                        filler_token_amount_to_return: *filler_token_amount_to_return,
                        collateral_amount_to_get: collateral_to_get,
                    },
                    MergeBranch::default(),
                );

                let tx = finalize_transaction(
                    pst.extract_tx()?,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                // Sign P2PK inputs 1 and 2
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
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

                // Fetch UTXOs
                let collateral_txout = fetch_utxo(*collateral_utxo)?; // DCD input 0
                let grantor_coll_txout = fetch_utxo(*grantor_collateral_token_utxo)?; // P2PK input 1
                let fee_txout = fetch_utxo(*fee_utxo)?; // P2PK input 2

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                anyhow::ensure!(
                    taproot_pubkey_gen.address.script_pubkey() == collateral_txout.script_pubkey,
                    "collateral_utxo must be locked by DCD covenant"
                );

                let available_collateral = collateral_txout.value.explicit().unwrap();
                let grantor_coll_asset_id = grantor_coll_txout.asset.explicit().unwrap();
                let available_grantor_coll = grantor_coll_txout.value.explicit().unwrap();
                let total_fee_input = fee_txout.value.explicit().unwrap();

                anyhow::ensure!(
                    *grantor_collateral_amount_to_burn <= available_grantor_coll,
                    "grantor collateral burn amount exceeds available"
                );

                // amount_to_get = burn * GRANTOR_COLLATERAL_PER_DEPOSITED_COLLATERAL
                let grantor_coll_per_deposited =
                    dcd_arguments.ratio_args.interest_collateral_amount
                        / dcd_arguments.ratio_args.grantor_collateral_token_amount;
                let amount_to_get =
                    grantor_collateral_amount_to_burn.saturating_mul(grantor_coll_per_deposited);

                anyhow::ensure!(
                    amount_to_get <= available_collateral,
                    "required collateral exceeds available"
                );

                let is_change_needed = available_collateral != amount_to_get;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                // Build PST
                let mut pst = PartiallySignedTransaction::new_v2();

                let mut in0 = Input::from_prevout(*collateral_utxo);
                in0.witness_utxo = Some(collateral_txout.clone());
                pst.add_input(in0);

                let mut in1 = Input::from_prevout(*grantor_collateral_token_utxo);
                in1.witness_utxo = Some(grantor_coll_txout.clone());
                pst.add_input(in1);

                let mut in2 = Input::from_prevout(*fee_utxo);
                in2.witness_utxo = Some(fee_txout.clone());
                pst.add_input(in2);

                if is_change_needed {
                    // 0: collateral change back to covenant
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        available_collateral - amount_to_get,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // 1: burn grantor collateral token (OP_RETURN)
                pst.add_output(Output::new_explicit(
                    Script::new_op_return("burn".as_bytes()),
                    *grantor_collateral_amount_to_burn,
                    grantor_coll_asset_id,
                    None,
                ));

                // 2: return collateral to user
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    amount_to_get,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                if *grantor_collateral_amount_to_burn != available_grantor_coll {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        available_grantor_coll - grantor_collateral_amount_to_burn,
                        grantor_coll_asset_id,
                        None,
                    ));
                }

                // fee change + fee
                anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_fee_input - *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                // Finalize
                let utxos = vec![collateral_txout, grantor_coll_txout, fee_txout];
                let dcd_program = get_dcd_program(&dcd_arguments)?;

                let witness_values = build_dcd_witness(
                    TokenBranch::Maker,
                    DcdBranch::MakerTermination {
                        is_change_needed,
                        index_to_spend: 0,
                        grantor_token_amount_to_burn: *grantor_collateral_amount_to_burn,
                        amount_to_get,
                    },
                    MergeBranch::default(),
                );

                let tx = finalize_transaction(
                    pst.extract_tx()?,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values,
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
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
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

                // Fetch UTXOs
                let settlement_txout = fetch_utxo(*settlement_asset_utxo)?; // DCD input 0
                let grantor_settle_txout = fetch_utxo(*grantor_settlement_token_utxo)?; // P2PK input 1
                let fee_txout = fetch_utxo(*fee_utxo)?; // P2PK input 2

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                anyhow::ensure!(
                    taproot_pubkey_gen.address.script_pubkey() == settlement_txout.script_pubkey,
                    "settlement_asset_utxo must be locked by DCD covenant"
                );

                let available_settlement = settlement_txout.value.explicit().unwrap();
                let grantor_settle_asset_id = grantor_settle_txout.asset.explicit().unwrap();
                let available_grantor_settle = grantor_settle_txout.value.explicit().unwrap();
                let total_fee_input = fee_txout.value.explicit().unwrap();

                anyhow::ensure!(
                    *grantor_settlement_amount_to_burn <= available_grantor_settle,
                    "grantor settlement burn amount exceeds available"
                );

                // amount_to_get = burn * GRANTOR_SETTLEMENT_PER_DEPOSITED_ASSET
                let grantor_settle_per_deposited = dcd_arguments.ratio_args.total_asset_amount
                    / dcd_arguments.ratio_args.grantor_settlement_token_amount;
                let amount_to_get =
                    grantor_settlement_amount_to_burn.saturating_mul(grantor_settle_per_deposited);

                anyhow::ensure!(
                    amount_to_get <= available_settlement,
                    "required settlement exceeds available"
                );

                let is_change_needed = available_settlement != amount_to_get;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                // Build PST
                let mut pst = PartiallySignedTransaction::new_v2();

                let mut in0 = Input::from_prevout(*settlement_asset_utxo);
                in0.witness_utxo = Some(settlement_txout.clone());
                pst.add_input(in0);

                let mut in1 = Input::from_prevout(*grantor_settlement_token_utxo);
                in1.witness_utxo = Some(grantor_settle_txout.clone());
                pst.add_input(in1);

                let mut in2 = Input::from_prevout(*fee_utxo);
                in2.witness_utxo = Some(fee_txout.clone());
                pst.add_input(in2);

                if is_change_needed {
                    // 0: settlement change back to covenant
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        available_settlement - amount_to_get,
                        AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                        None,
                    ));
                }

                // 1: burn grantor settlement token (OP_RETURN)
                pst.add_output(Output::new_explicit(
                    Script::new_op_return("burn".as_bytes()),
                    *grantor_settlement_amount_to_burn,
                    grantor_settle_asset_id,
                    None,
                ));

                // 2: return settlement to user
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    amount_to_get,
                    AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                    None,
                ));

                if *grantor_settlement_amount_to_burn != available_grantor_settle {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        available_grantor_settle - grantor_settlement_amount_to_burn,
                        grantor_settle_asset_id,
                        None,
                    ));
                }

                // fee change + fee
                anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_fee_input - *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));
                pst.add_output(Output::from_txout(TxOut::new_fee(
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                )));

                // Finalize
                let utxos = vec![settlement_txout, grantor_settle_txout, fee_txout];
                let dcd_program = get_dcd_program(&dcd_arguments)?;

                let witness_values = build_dcd_witness(
                    TokenBranch::Taker,
                    DcdBranch::MakerTermination {
                        is_change_needed,
                        index_to_spend: 0,
                        grantor_token_amount_to_burn: *grantor_settlement_amount_to_burn,
                        amount_to_get,
                    },
                    MergeBranch::default(),
                );

                let tx = finalize_transaction(
                    pst.extract_tx()?,
                    &dcd_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values,
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
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
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

                // Fetch UTXOs
                let asset_txout = fetch_utxo(*asset_utxo)?; // DCD input 0
                let grantor_coll_txout = fetch_utxo(*grantor_collateral_token_utxo)?; // P2PK input 1
                let grantor_settle_txout = fetch_utxo(*grantor_settlement_token_utxo)?; // P2PK input 2
                let fee_txout = fetch_utxo(*fee_utxo)?; // P2PK input 3

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                anyhow::ensure!(
                    taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
                    "asset_utxo must be locked by DCD covenant"
                );

                let total_fee_input = fee_txout.value.explicit().unwrap();
                let available_onchain_asset = asset_txout.value.explicit().unwrap();

                let grantor_coll_asset_id = grantor_coll_txout.asset.explicit().unwrap();
                let grantor_settle_asset_id = grantor_settle_txout.asset.explicit().unwrap();
                let available_grantor_coll = grantor_coll_txout.value.explicit().unwrap();
                let available_grantor_settle = grantor_settle_txout.value.explicit().unwrap();

                anyhow::ensure!(
                    *grantor_amount_to_burn <= available_grantor_coll
                        && *grantor_amount_to_burn <= available_grantor_settle,
                    "grantor burn amount exceeds available"
                );

                // Compute amount_to_get based on price branch
                let settlement_height = dcd_arguments.settlement_height;
                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.global.tx_data.fallback_locktime =
                    Some(LockTime::from_height(settlement_height)?);

                // Inputs in order
                let mut in0 = Input::from_prevout(*asset_utxo);
                in0.witness_utxo = Some(asset_txout.clone());
                in0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
                pst.add_input(in0);

                let mut in1 = Input::from_prevout(*grantor_collateral_token_utxo);
                in1.witness_utxo = Some(grantor_coll_txout.clone());
                pst.add_input(in1);

                let mut in2 = Input::from_prevout(*grantor_settlement_token_utxo);
                in2.witness_utxo = Some(grantor_settle_txout.clone());
                pst.add_input(in2);

                let mut in3 = Input::from_prevout(*fee_utxo);
                in3.witness_utxo = Some(fee_txout.clone());
                pst.add_input(in3);

                // Decide branch and build outputs
                let price = *price_at_current_block_height;

                // Parse oracle signature
                let oracle_sig =
                    simplicityhl::simplicity::bitcoin::secp256k1::schnorr::Signature::from_slice(
                        &hex::decode(oracle_signature)?,
                    )?;

                // Maker gets ALT when price <= strike
                if price <= dcd_arguments.strike_price {
                    // amount_to_get = burn * GRANTOR_PER_SETTLEMENT_ASSET
                    let per_settlement_asset = dcd_arguments.ratio_args.total_asset_amount
                        / dcd_arguments.ratio_args.grantor_collateral_token_amount;
                    let amount_to_get = grantor_amount_to_burn.saturating_mul(per_settlement_asset);

                    anyhow::ensure!(
                        amount_to_get <= available_onchain_asset,
                        "required settlement exceeds available"
                    );

                    let is_change_needed = available_onchain_asset != amount_to_get;

                    if is_change_needed {
                        // 0: settlement change back to covenant
                        pst.add_output(Output::new_explicit(
                            taproot_pubkey_gen.address.script_pubkey(),
                            available_onchain_asset - amount_to_get,
                            AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                            None,
                        ));
                    }

                    // Burn grantor settlement token
                    pst.add_output(Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        *grantor_amount_to_burn,
                        grantor_settle_asset_id,
                        None,
                    ));
                    // Burn grantor collateral token
                    pst.add_output(Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        *grantor_amount_to_burn,
                        grantor_coll_asset_id,
                        None,
                    ));
                    // settlement to user
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        amount_to_get,
                        AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                        None,
                    ));

                    if *grantor_amount_to_burn != available_grantor_coll {
                        pst.add_output(Output::new_explicit(
                            change_recipient.script_pubkey(),
                            available_grantor_coll - grantor_amount_to_burn,
                            grantor_coll_asset_id,
                            None,
                        ));
                    }

                    if *grantor_amount_to_burn != available_grantor_settle {
                        pst.add_output(Output::new_explicit(
                            change_recipient.script_pubkey(),
                            available_grantor_settle - grantor_amount_to_burn,
                            grantor_settle_asset_id,
                            None,
                        ));
                    }

                    // fee change + fee
                    anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_fee_input - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                    pst.add_output(Output::from_txout(TxOut::new_fee(
                        *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                    )));

                    let utxos = vec![
                        asset_txout,
                        grantor_coll_txout,
                        grantor_settle_txout,
                        fee_txout,
                    ];
                    let dcd_program = get_dcd_program(&dcd_arguments)?;
                    let witness_values = build_dcd_witness(
                        TokenBranch::Maker,
                        DcdBranch::Settlement {
                            price_at_current_block_height: price,
                            oracle_sig: &oracle_sig,
                            index_to_spend: 0,
                            amount_to_burn: *grantor_amount_to_burn,
                            amount_to_get,
                            is_change_needed,
                        },
                        MergeBranch::default(),
                    );

                    let tx = finalize_transaction(
                        pst.extract_tx()?,
                        &dcd_program,
                        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                        &utxos,
                        0,
                        witness_values,
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
                    let tx = finalize_p2pk_transaction(
                        tx,
                        &utxos,
                        &keypair,
                        2,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;
                    let tx = finalize_p2pk_transaction(
                        tx,
                        &utxos,
                        &keypair,
                        3,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;

                    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
                    match broadcast {
                        true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                        false => println!("{}", tx.serialize().to_lower_hex_string()),
                    }
                } else {
                    // Maker gets LBTC (price > strike)
                    let per_settlement_collateral =
                        dcd_arguments.ratio_args.total_collateral_amount
                            / dcd_arguments.ratio_args.grantor_collateral_token_amount;
                    let amount_to_get =
                        grantor_amount_to_burn.saturating_mul(per_settlement_collateral);

                    anyhow::ensure!(
                        amount_to_get <= available_onchain_asset,
                        "required collateral exceeds available"
                    );

                    let is_change_needed = available_onchain_asset != amount_to_get;

                    if is_change_needed {
                        // 0: collateral change back to covenant
                        pst.add_output(Output::new_explicit(
                            taproot_pubkey_gen.address.script_pubkey(),
                            available_onchain_asset - amount_to_get,
                            LIQUID_TESTNET_BITCOIN_ASSET,
                            None,
                        ));
                    }

                    // Burn grantor collateral token
                    pst.add_output(Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        *grantor_amount_to_burn,
                        grantor_coll_asset_id,
                        None,
                    ));
                    // Burn grantor settlement token
                    pst.add_output(Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        *grantor_amount_to_burn,
                        grantor_settle_asset_id,
                        None,
                    ));
                    // collateral to user
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        amount_to_get,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));

                    if *grantor_amount_to_burn != available_grantor_coll {
                        pst.add_output(Output::new_explicit(
                            change_recipient.script_pubkey(),
                            available_grantor_coll - grantor_amount_to_burn,
                            grantor_coll_asset_id,
                            None,
                        ));
                    }

                    if *grantor_amount_to_burn != available_grantor_settle {
                        pst.add_output(Output::new_explicit(
                            change_recipient.script_pubkey(),
                            available_grantor_settle - grantor_amount_to_burn,
                            grantor_settle_asset_id,
                            None,
                        ));
                    }
                    // fee change + fee
                    anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_fee_input - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                    pst.add_output(Output::from_txout(TxOut::new_fee(
                        *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                    )));

                    let utxos = vec![
                        asset_txout,
                        grantor_coll_txout,
                        grantor_settle_txout,
                        fee_txout,
                    ];
                    let dcd_program = get_dcd_program(&dcd_arguments)?;
                    let witness_values = build_dcd_witness(
                        TokenBranch::Maker,
                        DcdBranch::Settlement {
                            price_at_current_block_height: price,
                            oracle_sig: &oracle_sig,
                            index_to_spend: 0,
                            amount_to_burn: *grantor_amount_to_burn,
                            amount_to_get,
                            is_change_needed,
                        },
                        MergeBranch::default(),
                    );

                    let tx = finalize_transaction(
                        pst.extract_tx()?,
                        &dcd_program,
                        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                        &utxos,
                        0,
                        witness_values,
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
                    let tx = finalize_p2pk_transaction(
                        tx,
                        &utxos,
                        &keypair,
                        2,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;
                    let tx = finalize_p2pk_transaction(
                        tx,
                        &utxos,
                        &keypair,
                        3,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;

                    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
                    match broadcast {
                        true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                        false => println!("{}", tx.serialize().to_lower_hex_string()),
                    }
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

                // Fetch UTXOs
                let asset_txout = fetch_utxo(*asset_utxo)?; // DCD input 0
                let filler_txout = fetch_utxo(*filler_token_utxo)?; // P2PK input 1
                let fee_txout = fetch_utxo(*fee_utxo)?; // P2PK input 2

                let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;
                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    dcd_taproot_pubkey_gen,
                    &dcd_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_dcd_address,
                )?;

                anyhow::ensure!(
                    taproot_pubkey_gen.address.script_pubkey() == asset_txout.script_pubkey,
                    "asset_utxo must be locked by DCD covenant"
                );

                let total_fee_input = fee_txout.value.explicit().unwrap();
                let available_onchain_asset = asset_txout.value.explicit().unwrap();
                let filler_asset_id = filler_txout.asset.explicit().unwrap();
                let available_filler = filler_txout.value.explicit().unwrap();

                anyhow::ensure!(
                    *filler_amount_to_burn <= available_filler,
                    "filler burn amount exceeds available"
                );

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();
                pst.global.tx_data.fallback_locktime =
                    Some(LockTime::from_height(dcd_arguments.settlement_height)?);

                // Inputs
                let mut in0 = Input::from_prevout(*asset_utxo);
                in0.witness_utxo = Some(asset_txout.clone());
                in0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
                pst.add_input(in0);

                let mut in1 = Input::from_prevout(*filler_token_utxo);
                in1.witness_utxo = Some(filler_txout.clone());
                pst.add_input(in1);

                let mut in2 = Input::from_prevout(*fee_utxo);
                in2.witness_utxo = Some(fee_txout.clone());
                pst.add_input(in2);

                let price = *price_at_current_block_height;
                let oracle_sig =
                    simplicityhl::simplicity::bitcoin::secp256k1::schnorr::Signature::from_slice(
                        &hex::decode(oracle_signature)?,
                    )?;

                if price <= dcd_arguments.strike_price {
                    // Taker receives LBTC: amount_to_get = burn * FILLER_PER_SETTLEMENT_COLLATERAL
                    let per_settlement_collateral =
                        dcd_arguments.ratio_args.total_collateral_amount
                            / dcd_arguments.ratio_args.filler_token_amount;
                    let amount_to_get =
                        filler_amount_to_burn.saturating_mul(per_settlement_collateral);

                    anyhow::ensure!(
                        amount_to_get <= available_onchain_asset,
                        "required collateral exceeds available"
                    );

                    let is_change_needed = available_onchain_asset != amount_to_get;

                    if is_change_needed {
                        // 0: collateral change back to covenant
                        pst.add_output(Output::new_explicit(
                            taproot_pubkey_gen.address.script_pubkey(),
                            available_onchain_asset - amount_to_get,
                            LIQUID_TESTNET_BITCOIN_ASSET,
                            None,
                        ));
                    }

                    // Burn filler token
                    pst.add_output(Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        *filler_amount_to_burn,
                        filler_asset_id,
                        None,
                    ));

                    // collateral to user
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        amount_to_get,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));

                    if *filler_amount_to_burn != available_filler {
                        pst.add_output(Output::new_explicit(
                            change_recipient.script_pubkey(),
                            available_filler - filler_amount_to_burn,
                            filler_asset_id,
                            None,
                        ));
                    }

                    anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_fee_input - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                    pst.add_output(Output::from_txout(TxOut::new_fee(
                        *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                    )));

                    let utxos = vec![asset_txout, filler_txout, fee_txout];
                    let dcd_program = get_dcd_program(&dcd_arguments)?;
                    let witness_values = build_dcd_witness(
                        TokenBranch::Taker,
                        DcdBranch::Settlement {
                            price_at_current_block_height: price,
                            oracle_sig: &oracle_sig,
                            index_to_spend: 0,
                            amount_to_burn: *filler_amount_to_burn,
                            amount_to_get,
                            is_change_needed,
                        },
                        MergeBranch::default(),
                    );

                    let tx = finalize_transaction(
                        pst.extract_tx()?,
                        &dcd_program,
                        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                        &utxos,
                        0,
                        witness_values,
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
                    let tx = finalize_p2pk_transaction(
                        tx,
                        &utxos,
                        &keypair,
                        2,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;

                    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
                    match broadcast {
                        true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                        false => println!("{}", tx.serialize().to_lower_hex_string()),
                    }
                } else {
                    // Taker receives SETTLEMENT: amount_to_get = burn * FILLER_PER_SETTLEMENT_ASSET
                    let per_settlement_asset = dcd_arguments.ratio_args.total_asset_amount
                        / dcd_arguments.ratio_args.filler_token_amount;
                    let amount_to_get = filler_amount_to_burn.saturating_mul(per_settlement_asset);

                    anyhow::ensure!(
                        amount_to_get <= available_onchain_asset,
                        "required settlement exceeds available"
                    );

                    let is_change_needed = available_onchain_asset != amount_to_get;

                    if is_change_needed {
                        // 0: settlement change back to covenant
                        pst.add_output(Output::new_explicit(
                            taproot_pubkey_gen.address.script_pubkey(),
                            available_onchain_asset - amount_to_get,
                            AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                            None,
                        ));
                    }

                    // Burn filler token
                    pst.add_output(Output::new_explicit(
                        Script::new_op_return("burn".as_bytes()),
                        *filler_amount_to_burn,
                        filler_asset_id,
                        None,
                    ));

                    // settlement to user
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        amount_to_get,
                        AssetId::from_str(&dcd_arguments.settlement_asset_id_hex_le)?,
                        None,
                    ));

                    if *filler_amount_to_burn != available_filler {
                        pst.add_output(Output::new_explicit(
                            change_recipient.script_pubkey(),
                            available_filler - filler_amount_to_burn,
                            filler_asset_id,
                            None,
                        ));
                    }

                    anyhow::ensure!(*fee_amount <= total_fee_input, "fee exceeds input value");
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_fee_input - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                    pst.add_output(Output::from_txout(TxOut::new_fee(
                        *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                    )));

                    let utxos = vec![asset_txout, filler_txout, fee_txout];
                    let dcd_program = get_dcd_program(&dcd_arguments)?;
                    let witness_values = build_dcd_witness(
                        TokenBranch::Taker,
                        DcdBranch::Settlement {
                            price_at_current_block_height: price,
                            oracle_sig: &oracle_sig,
                            index_to_spend: 0,
                            amount_to_burn: *filler_amount_to_burn,
                            amount_to_get,
                            is_change_needed,
                        },
                        MergeBranch::default(),
                    );

                    let tx = finalize_transaction(
                        pst.extract_tx()?,
                        &dcd_program,
                        &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                        &utxos,
                        0,
                        witness_values,
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
                    let tx = finalize_p2pk_transaction(
                        tx,
                        &utxos,
                        &keypair,
                        2,
                        &AddressParams::LIQUID_TESTNET,
                        *LIQUID_TESTNET_GENESIS,
                    )?;

                    tx.verify_tx_amt_proofs(secp256k1::SECP256K1, &utxos)?;
                    match broadcast {
                        true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
                        false => println!("{}", tx.serialize().to_lower_hex_string()),
                    }
                }

                Ok(())
            }
        }
    }
}

fn handle_merge_tokens(
    token_utxos: Vec<OutPoint>,
    fee_utxo: OutPoint,
    dcd_taproot_pubkey_gen: &str,
    fee_amount: u64,
    account_index: u32,
    broadcast_flag: bool,
    merge_branch: MergeBranch,
) -> Result<()> {
    let store = Store::load()?;
    let dcd_arguments: DCDArguments = store.get_arguments(dcd_taproot_pubkey_gen)?;

    let keypair = secp256k1::Keypair::from_secret_key(
        secp256k1::SECP256K1,
        &derive_secret_key_from_index(account_index),
    );

    // Fetch all token UTXOs
    let mut token_txouts = vec![];
    for utxo in &token_utxos {
        token_txouts.push(fetch_utxo(*utxo)?);
    }

    // Fetch fee UTXO
    let fee_txout = fetch_utxo(fee_utxo)?;

    // Get token asset ID from first UTXO
    let token_asset_id = token_txouts[0]
        .asset
        .explicit()
        .ok_or_else(|| anyhow::anyhow!("Expected explicit asset for token"))?;

    // Calculate total token amount
    let mut total_token_amount = 0u64;
    for txout in &token_txouts {
        total_token_amount += txout
            .value
            .explicit()
            .ok_or_else(|| anyhow::anyhow!("Expected explicit value for token"))?;
    }

    let total_fee_amount = fee_txout
        .value
        .explicit()
        .ok_or_else(|| anyhow::anyhow!("Expected explicit value for fee"))?;

    // Build PST
    let mut pst = PartiallySignedTransaction::from_tx(Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    });

    // Add token inputs
    for (i, utxo) in token_utxos.iter().enumerate() {
        let mut input = Input::from_prevout(*utxo);
        input.witness_utxo = Some(token_txouts[i].clone());
        pst.add_input(input);
    }

    // Add fee input
    let mut fee_input = Input::from_prevout(fee_utxo);
    fee_input.witness_utxo = Some(fee_txout.clone());
    pst.add_input(fee_input);

    // Get DCD address from arguments
    let dcd_program = get_dcd_program(&dcd_arguments)?;
    let dcd_pubkey = simplicityhl_core::TaprootPubkeyGen::build_from_str(
        dcd_taproot_pubkey_gen,
        &dcd_arguments,
        &AddressParams::LIQUID_TESTNET,
        &contracts::get_dcd_address,
    )?
    .pubkey
    .to_x_only_pubkey();

    let dcd_address =
        contracts::get_dcd_address(&dcd_pubkey, &dcd_arguments, &AddressParams::LIQUID_TESTNET)?;

    // Output 1: Merged tokens back to covenant
    pst.add_output(Output::new_explicit(
        dcd_address.script_pubkey(),
        total_token_amount,
        token_asset_id,
        None,
    ));

    // Output 2: Change
    let change_address = simplicityhl_core::get_p2pk_address(
        &keypair.x_only_public_key().0,
        &AddressParams::LIQUID_TESTNET,
    )?;

    pst.add_output(Output::new_explicit(
        change_address.script_pubkey(),
        total_fee_amount - fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    // Output 3: Fee
    pst.add_output(Output::new_explicit(
        Script::new(),
        fee_amount,
        LIQUID_TESTNET_BITCOIN_ASSET,
        None,
    ));

    let mut tx = pst.extract_tx()?;

    // Collect all UTXOs for finalization
    let mut all_utxos = token_txouts.clone();
    all_utxos.push(fee_txout);

    // Finalize each token input with DCD program
    for i in 0..token_utxos.len() {
        tx = finalize_dcd_transaction_on_liquid_testnet(
            tx,
            &dcd_program,
            &dcd_pubkey,
            &all_utxos,
            i as u32,
            TokenBranch::default(),
            DcdBranch::Merge,
            merge_branch,
        )?;
    }

    // Finalize fee input with P2PK
    tx = finalize_p2pk_transaction(
        tx,
        &all_utxos,
        &keypair,
        token_utxos.len(),
        &AddressParams::LIQUID_TESTNET,
        *LIQUID_TESTNET_GENESIS,
    )?;

    match broadcast_flag {
        true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
        false => println!("{}", tx.serialize().to_lower_hex_string()),
    }

    Ok(())
}
