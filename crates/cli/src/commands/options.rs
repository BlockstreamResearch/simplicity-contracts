use crate::modules::keys::derive_secret_key_from_index;
use crate::modules::store::Store;

use anyhow::Result;
use clap::Subcommand;
use contracts::build_witness::TokenBranch;
use contracts::{OptionsArguments, finalize_options_funding_path_transaction, get_options_program};

use std::str::FromStr;

use simplicityhl::simplicity::bitcoin::secp256k1::SecretKey;
use simplicityhl_core::{
    Encodable, LIQUID_TESTNET_BITCOIN_ASSET, LIQUID_TESTNET_GENESIS, TaprootPubkeyGen,
    broadcast_tx, fetch_utxo, finalize_p2pk_transaction, finalize_transaction,
    get_new_asset_entropy, get_p2pk_address, get_random_seed,
};

use simplicityhl::simplicity::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use simplicityhl::simplicity::elements::hex::ToHex;
use simplicityhl::simplicity::elements::pset::{Input, Output, PartiallySignedTransaction};
use simplicityhl::simplicity::elements::secp256k1_zkp::Secp256k1;
use simplicityhl::simplicity::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::simplicity::elements::{
    AddressParams, AssetId, LockTime, Script, Sequence, Transaction, TxOutSecrets,
};
use simplicityhl::simplicity::hashes::sha256;

use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::serialize::Serialize;
use simplicityhl::elements::{OutPoint, confidential};
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::hex::DisplayHex;

#[derive(Subcommand, Debug)]
pub enum Options {
    /// Compute Options address and OPTION_SCRIPT_HASH for creation program
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
    /// Exercise path: burn option tokens and settle against target asset
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
    pub fn handle(&self) -> Result<()> {
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let blinder_key = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &SecretKey::from_slice(&[1; 32])?,
                );

                let first_utxo = fetch_utxo(*first_fee_utxo)?;
                let second_utxo = fetch_utxo(*second_fee_utxo)?;

                let first_asset_entropy = get_random_seed();
                let second_asset_entropy = get_random_seed();

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

                let (first_asset, first_reissuance_asset) = first_issuance_tx.issuance_ids();
                let (second_asset, second_reissuance_asset) = second_issuance_tx.issuance_ids();

                let option_arguments = OptionsArguments {
                    start_time: *start_time,
                    expiry_time: *expiry_time,
                    collateral_per_contract: *collateral_per_contract,
                    settlement_per_contract: *settlement_per_contract,
                    collateral_asset_id_hex_le: LIQUID_TESTNET_BITCOIN_ASSET.to_string(),
                    settlement_asset_id_hex_le: settlement_asset_id_hex_be.clone(),
                    option_token_asset_id_hex_le: first_asset.to_string(),
                    grantor_token_asset_id_hex_le: second_asset.to_string(),
                };

                let options_taproot_pubkey_gen = TaprootPubkeyGen::from(
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                store.import_arguments(
                    &options_taproot_pubkey_gen.to_string(),
                    &option_arguments.to_hex()?,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                store.store.insert(
                    format!("first_entropy_{}", options_taproot_pubkey_gen),
                    get_new_asset_entropy(first_fee_utxo, first_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;
                store.store.insert(
                    format!("second_entropy_{}", options_taproot_pubkey_gen),
                    get_new_asset_entropy(second_fee_utxo, second_asset_entropy)
                        .to_hex()
                        .as_bytes(),
                )?;

                println!("options_taproot_pubkey_gen: {}", options_taproot_pubkey_gen);

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let total_input_fee =
                    first_utxo.value.explicit().unwrap() + second_utxo.value.explicit().unwrap();

                let mut pst = PartiallySignedTransaction::from_tx(Transaction {
                    version: 2,
                    lock_time: LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                });

                pst.add_input(first_issuance_tx);
                pst.add_input(second_issuance_tx);

                // Add first token (use account blinding pubkey so we can unblind later)
                let mut output = Output::new_explicit(
                    options_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    first_reissuance_asset,
                    Some(blinder_key.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);
                // Add second token
                let mut output = Output::new_explicit(
                    options_taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    second_reissuance_asset,
                    Some(blinder_key.public_key().into()),
                );
                output.blinder_index = Some(1);
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

                // Provide correct input secrets for blinding for BOTH issuance inputs.
                // For explicit inputs, the blinding factors are zero and values/assets are explicit.
                let first_input_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: first_utxo
                        .value
                        .explicit()
                        .expect("expected explicit value for first issuance input"),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };
                let second_input_secrets = TxOutSecrets {
                    asset_bf: AssetBlindingFactor::zero(),
                    value_bf: ValueBlindingFactor::zero(),
                    value: second_utxo
                        .value
                        .explicit()
                        .expect("expected explicit value for second issuance input"),
                    asset: LIQUID_TESTNET_BITCOIN_ASSET,
                };

                let mut inp_txout_sec = std::collections::HashMap::new();
                inp_txout_sec.insert(0, first_input_secrets);
                inp_txout_sec.insert(1, second_input_secrets);

                let input = &mut pst.inputs_mut()[0];
                input.blinded_issuance = Some(0x00);

                let input = &mut pst.inputs_mut()[1];
                input.blinded_issuance = Some(0x00);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_txout_sec)?;

                let utxos = vec![first_utxo, second_utxo];
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

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let option_utxo = fetch_utxo(*option_asset_utxo)?;
                let grantor_utxo = fetch_utxo(*grantor_asset_utxo)?;
                let collateral_utxo = fetch_utxo(*collateral_and_fee_utxo)?;

                let total_input_fee = collateral_utxo.value.explicit().unwrap();

                let Some(first_entropy_hex) = store
                    .store
                    .get(format!("first_entropy_{}", option_taproot_pubkey_gen))?
                else {
                    anyhow::bail!("First entropy not found");
                };
                let Some(second_entropy_hex) = store
                    .store
                    .get(format!("second_entropy_{}", option_taproot_pubkey_gen))?
                else {
                    anyhow::bail!("Second entropy not found");
                };
                let first_entropy_hex = hex::decode(first_entropy_hex)?;
                let second_entropy_hex = hex::decode(second_entropy_hex)?;

                let mut first_asset_entropy_bytes: [u8; 32] = first_entropy_hex.try_into().unwrap();
                first_asset_entropy_bytes.reverse();

                let mut second_asset_entropy_bytes: [u8; 32] =
                    second_entropy_hex.try_into().unwrap();
                second_asset_entropy_bytes.reverse();

                let first_asset_entropy =
                    sha256::Midstate::from_byte_array(first_asset_entropy_bytes);
                let second_asset_entropy =
                    sha256::Midstate::from_byte_array(second_asset_entropy_bytes);

                let blinding_sk = SecretKey::from_slice(&[1; 32])?;

                let first_unblinded = option_utxo.unblind(&Secp256k1::new(), blinding_sk)?;
                let second_unblinded = grantor_utxo.unblind(&Secp256k1::new(), blinding_sk)?;

                // Auto-unblind token UTXOs to obtain ABFs for reissuance nonce
                let first_token_abf = first_unblinded.asset_bf;
                let second_token_abf = second_unblinded.asset_bf;

                let first_asset_id = AssetId::from_entropy(first_asset_entropy);
                let first_token_id =
                    AssetId::reissuance_token_from_entropy(first_asset_entropy, false);

                let second_asset_id = AssetId::from_entropy(second_asset_entropy);
                let second_token_id =
                    AssetId::reissuance_token_from_entropy(second_asset_entropy, false);

                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let option_token_amount =
                    collateral_amount / option_arguments.collateral_per_contract;
                let expected_asset_amount =
                    option_token_amount.saturating_mul(option_arguments.settlement_per_contract);

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    option_utxo.script_pubkey,
                    "Expected the taproot pubkey gen address to be the same as the option utxo script pubkey"
                );

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                let mut pst = PartiallySignedTransaction::new_v2();

                let mut first_reissuance_tx = Input::from_prevout(*option_asset_utxo);
                first_reissuance_tx.witness_utxo = Some(option_utxo.clone());
                first_reissuance_tx.issuance_value_amount = Some(option_token_amount);
                first_reissuance_tx.issuance_inflation_keys = None;
                first_reissuance_tx.issuance_asset_entropy =
                    Some(first_asset_entropy.to_byte_array());

                let mut second_reissuance_tx = Input::from_prevout(*grantor_asset_utxo);
                second_reissuance_tx.witness_utxo = Some(grantor_utxo.clone());
                second_reissuance_tx.issuance_value_amount = Some(option_token_amount);
                second_reissuance_tx.issuance_inflation_keys = None;
                second_reissuance_tx.issuance_asset_entropy =
                    Some(second_asset_entropy.to_byte_array());

                let mut collateral_tx = Input::from_prevout(*collateral_and_fee_utxo);
                collateral_tx.witness_utxo = Some(collateral_utxo.clone());

                pst.add_input(first_reissuance_tx);
                pst.add_input(second_reissuance_tx);
                pst.add_input(collateral_tx);

                // Add first token (move reissuance token forward)
                let mut output = Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    first_token_id,
                    Some(keypair.public_key().into()),
                );
                output.blinder_index = Some(0);
                pst.add_output(output);

                // Add second token (move reissuance token forward)
                let mut output = Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    1,
                    second_token_id,
                    Some(keypair.public_key().into()),
                );
                output.blinder_index = Some(1);
                pst.add_output(output);

                // Add collateral
                let output = Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    *collateral_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                );
                pst.add_output(output);

                // Add first asset
                let output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    option_token_amount,
                    first_asset_id,
                    None,
                );
                pst.add_output(output);

                // Add second asset
                let output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    option_token_amount,
                    second_asset_id,
                    None,
                );
                pst.add_output(output);

                // Add change
                let output = Output::new_explicit(
                    change_recipient.script_pubkey(),
                    total_input_fee - fee_amount - collateral_amount,
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

                let mut inp_tx_out_sec = std::collections::HashMap::new();
                inp_tx_out_sec.insert(0, first_unblinded);
                inp_tx_out_sec.insert(1, second_unblinded);

                pst.blind_last(&mut thread_rng(), &Secp256k1::new(), &inp_tx_out_sec)?;

                let utxos = vec![option_utxo, grantor_utxo, collateral_utxo];
                let options_program = get_options_program(&option_arguments)?;

                let tx = finalize_options_funding_path_transaction(
                    pst.extract_tx()?,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &options_program,
                    &utxos,
                    0,
                    expected_asset_amount,
                    TokenBranch::OptionToken,
                )?;
                let tx = finalize_options_funding_path_transaction(
                    tx,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &options_program,
                    &utxos,
                    1,
                    expected_asset_amount,
                    TokenBranch::GrantorToken,
                )?;

                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
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
                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let store = Store::load()?;
                let option_arguments: OptionsArguments =
                    store.get_arguments(option_taproot_pubkey_gen)?;

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                // Fetch and validate covenant LBTC UTXO
                let cov_utxo = fetch_utxo(*collateral_utxo)?;
                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    cov_utxo.script_pubkey,
                    "Expected collateral UTXO script to match options address"
                );

                let option_utxo = fetch_utxo(*option_asset_utxo)?;
                let asset_utxo_out = fetch_utxo(*asset_utxo)?;
                let fee_utxo_out = fetch_utxo(*fee_utxo)?;

                let total_input_fee = fee_utxo_out.value.explicit().unwrap();

                let total_collateral = cov_utxo.value.explicit().unwrap();
                let collateral_amount_to_get =
                    (*amount_to_burn).saturating_mul(option_arguments.collateral_per_contract);
                let asset_amount_to_pay =
                    (*amount_to_burn).saturating_mul(option_arguments.settlement_per_contract);

                anyhow::ensure!(
                    collateral_amount_to_get <= total_collateral,
                    "fee + collateral exceeds input value"
                );

                let total_asset_amount = asset_utxo_out.value.explicit().unwrap();
                let total_option_token_amount = option_utxo.value.explicit().unwrap();

                anyhow::ensure!(
                    asset_amount_to_pay <= total_asset_amount,
                    "asset_amount exceeds asset utxo value"
                );
                anyhow::ensure!(
                    option_arguments.settlement_asset_id_hex_le
                        == asset_utxo_out.asset.explicit().unwrap().to_string(),
                    "settlement asset id mismatch"
                );

                // Asset ids
                let option_token_id =
                    AssetId::from_str(&option_arguments.option_token_asset_id_hex_le)?;
                let settlement_asset_id =
                    AssetId::from_str(&option_arguments.settlement_asset_id_hex_le)?;

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                // Build PST
                let mut pst = PartiallySignedTransaction::new_v2();
                pst.global.tx_data.fallback_locktime =
                    Some(LockTime::from_time(option_arguments.start_time)?);

                pst.add_input(Input::from_prevout(*collateral_utxo));
                pst.inputs_mut()[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

                pst.add_input(Input::from_prevout(*option_asset_utxo));
                pst.inputs_mut()[1].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

                pst.add_input(Input::from_prevout(*asset_utxo));
                pst.inputs_mut()[2].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

                pst.add_input(Input::from_prevout(*fee_utxo));
                pst.inputs_mut()[3].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

                // Compute which changes are needed
                let is_collateral_change_needed = total_collateral != collateral_amount_to_get;
                let is_option_token_change_needed = total_option_token_amount != *amount_to_burn;
                let is_asset_change_needed = total_asset_amount != asset_amount_to_pay;
                let is_lbtc_change_needed = total_input_fee != *fee_amount;

                // Conditionally add outputs in the order expected by the covenant
                if is_collateral_change_needed {
                    // change (collateral) back to covenant at index 0 when change is needed
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        total_collateral - collateral_amount_to_get,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // burn option tokens (index 0 if no change; index 1 if change exists)
                pst.add_output(Output::new_explicit(
                    Script::new_op_return(b"burn"),
                    *amount_to_burn,
                    option_token_id,
                    None,
                ));

                // settlement payment to covenant (immediately after burn)
                pst.add_output(Output::new_explicit(
                    taproot_pubkey_gen.address.script_pubkey(),
                    asset_amount_to_pay,
                    settlement_asset_id,
                    None,
                ));

                // option token change (only if needed)
                if is_option_token_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_option_token_amount - amount_to_burn,
                        option_token_id,
                        None,
                    ));
                }

                // asset change (only if needed)
                if is_asset_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_asset_amount - asset_amount_to_pay,
                        settlement_asset_id,
                        None,
                    ));
                }

                // LBTC change (only if needed)
                if is_lbtc_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_input_fee - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // collateral amount to user
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    collateral_amount_to_get,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                // fee output
                pst.add_output(Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                let utxos = vec![cov_utxo, option_utxo, asset_utxo_out, fee_utxo_out];
                let options_program = get_options_program(&option_arguments)?;

                let witness_values = contracts::build_witness::build_option_witness(
                    TokenBranch::OptionToken,
                    contracts::build_witness::OptionBranch::Exercise {
                        is_change_needed: is_collateral_change_needed,
                        index_to_spend: 0,
                        amount_to_burn: *amount_to_burn,
                        collateral_amount_to_get,
                        asset_amount: asset_amount_to_pay,
                    },
                );
                let tx = finalize_transaction(
                    pst.extract_tx()?,
                    &options_program,
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

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let target_utxo = fetch_utxo(*settlement_asset_utxo)?;
                let grantor_utxo = fetch_utxo(*grantor_asset_utxo)?;
                let fee_lbtc_utxo = fetch_utxo(*fee_utxo)?;

                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    target_utxo.script_pubkey,
                    "Expected settlement asset UTXO script to match options address"
                );

                // Asset ids
                let grantor_token_id =
                    AssetId::from_str(&option_arguments.grantor_token_asset_id_hex_le)?;
                let target_asset_id =
                    AssetId::from_str(&option_arguments.settlement_asset_id_hex_le)?;

                // Validate assets
                anyhow::ensure!(
                    matches!(target_utxo.asset, confidential::Asset::Explicit(id) if id == target_asset_id),
                    "settlement-asset-utxo must be the settlement asset"
                );
                anyhow::ensure!(
                    matches!(fee_lbtc_utxo.asset, confidential::Asset::Explicit(id) if id == LIQUID_TESTNET_BITCOIN_ASSET),
                    "fee-utxo must be LBTC"
                );

                let available_target_asset = target_utxo.value.explicit().unwrap();
                let total_input_fee = fee_lbtc_utxo.value.explicit().unwrap();
                let total_grantor_token_amount = grantor_utxo.value.explicit().unwrap();

                let asset_amount = (*grantor_token_amount_to_burn)
                    .saturating_mul(option_arguments.settlement_per_contract);
                anyhow::ensure!(
                    asset_amount <= available_target_asset,
                    "asset_amount exceeds available target asset"
                );
                anyhow::ensure!(
                    *fee_amount <= total_input_fee,
                    "fee exceeds fee input value"
                );

                let change_recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                // Build PST
                let mut pst = PartiallySignedTransaction::new_v2();
                pst.global.tx_data.fallback_locktime =
                    Some(LockTime::from_time(option_arguments.start_time)?);
                pst.add_input(Input::from_prevout(*settlement_asset_utxo));
                pst.add_input(Input::from_prevout(*grantor_asset_utxo));
                pst.add_input(Input::from_prevout(*fee_utxo));

                // Compute change needs
                let is_target_change_needed = available_target_asset != asset_amount;
                let is_grantor_change_needed =
                    total_grantor_token_amount != *grantor_token_amount_to_burn;
                let is_lbtc_change_needed = total_input_fee != *fee_amount;

                // change (target asset) back to covenant if needed
                if is_target_change_needed {
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        available_target_asset - asset_amount,
                        target_asset_id,
                        None,
                    ));
                }

                // burn grantor tokens
                pst.add_output(Output::new_explicit(
                    Script::new_op_return(b"burn"),
                    *grantor_token_amount_to_burn,
                    grantor_token_id,
                    None,
                ));

                // settlement asset to user (target asset)
                pst.add_output(Output::new_explicit(
                    change_recipient.script_pubkey(),
                    asset_amount,
                    target_asset_id,
                    None,
                ));

                // grantor token change (remaining) if any
                if is_grantor_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_grantor_token_amount - *grantor_token_amount_to_burn,
                        grantor_token_id,
                        None,
                    ));
                }

                // LBTC change if any
                if is_lbtc_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_recipient.script_pubkey(),
                        total_input_fee - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // fee
                pst.add_output(Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                let mut tx = pst.extract_tx()?;
                tx.input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[1].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[2].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;

                let utxos = vec![target_utxo, grantor_utxo, fee_lbtc_utxo];
                let options_program = get_options_program(&option_arguments)?;

                let witness_values = contracts::build_witness::build_option_witness(
                    TokenBranch::GrantorToken,
                    contracts::build_witness::OptionBranch::Exercise {
                        is_change_needed: is_target_change_needed,
                        index_to_spend: 0,
                        amount_to_burn: *grantor_token_amount_to_burn,
                        collateral_amount_to_get: 0,
                        asset_amount,
                    },
                );
                let tx = finalize_transaction(
                    tx,
                    &options_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                // sign grantor token input
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                // sign fee input
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let cov_utxo = fetch_utxo(*collateral_utxo)?;
                let grantor_utxo = fetch_utxo(*grantor_asset_utxo)?;
                let fee_utxo_out = fetch_utxo(*fee_utxo)?;
                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    cov_utxo.script_pubkey,
                    "Expected collateral UTXO script to match options address"
                );

                let total_fee = fee_utxo_out.value.explicit().unwrap();

                let total_collateral = cov_utxo.value.explicit().unwrap();
                let collateral_amount = (*grantor_token_amount_to_burn)
                    .saturating_mul(option_arguments.collateral_per_contract);
                anyhow::ensure!(
                    collateral_amount <= total_collateral,
                    "collateral exceeds input value"
                );

                let total_grantor_token_amount = grantor_utxo.value.explicit().unwrap();

                // Asset id for grantor token
                let grantor_token_id =
                    AssetId::from_str(&option_arguments.grantor_token_asset_id_hex_le)?;

                let change_address = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                // Build PST
                let mut pst = PartiallySignedTransaction::new_v2();
                pst.global.tx_data.fallback_locktime =
                    Some(LockTime::from_time(option_arguments.start_time)?);
                pst.add_input(Input::from_prevout(*collateral_utxo));
                pst.add_input(Input::from_prevout(*grantor_asset_utxo));
                pst.add_input(Input::from_prevout(*fee_utxo));

                // Compute change needs
                let is_collateral_change_needed = total_collateral != collateral_amount;
                let is_grantor_change_needed =
                    total_grantor_token_amount != *grantor_token_amount_to_burn;
                let is_lbtc_change_needed = total_fee != *fee_amount;

                // change (collateral) back to covenant if needed
                if is_collateral_change_needed {
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        total_collateral - collateral_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // burn grantor tokens
                pst.add_output(Output::new_explicit(
                    Script::new_op_return(b"burn"),
                    *grantor_token_amount_to_burn,
                    grantor_token_id,
                    None,
                ));

                // withdraw collateral to recipient
                pst.add_output(Output::new_explicit(
                    change_address.script_pubkey(),
                    collateral_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                // grantor token change if any
                if is_grantor_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_address.script_pubkey(),
                        total_grantor_token_amount - *grantor_token_amount_to_burn,
                        grantor_token_id,
                        None,
                    ));
                }

                // LBTC change if any
                if is_lbtc_change_needed {
                    pst.add_output(Output::new_explicit(
                        change_address.script_pubkey(),
                        total_fee - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // fee
                pst.add_output(Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                let mut tx = pst.extract_tx()?;
                tx.input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[1].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[2].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;

                let utxos = vec![cov_utxo, grantor_utxo, fee_utxo_out];
                let witness_values = contracts::build_witness::build_option_witness(
                    TokenBranch::GrantorToken,
                    contracts::build_witness::OptionBranch::Expiry {
                        is_change_needed: is_collateral_change_needed,
                        index_to_spend: 0,
                        grantor_token_amount_to_burn: *grantor_token_amount_to_burn,
                        collateral_amount_to_withdraw: collateral_amount,
                    },
                );
                let options_program = get_options_program(&option_arguments)?;
                let tx = finalize_transaction(
                    tx,
                    &options_program,
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

                match broadcast {
                    true => println!("Broadcasted txid: {}", broadcast_tx(&tx)?),
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

                let keypair = secp256k1::Keypair::from_secret_key(
                    secp256k1::SECP256K1,
                    &derive_secret_key_from_index(*account_index),
                );

                let taproot_pubkey_gen = TaprootPubkeyGen::build_from_str(
                    option_taproot_pubkey_gen,
                    &option_arguments,
                    &AddressParams::LIQUID_TESTNET,
                    &contracts::get_options_address,
                )?;

                let cov_utxo = fetch_utxo(*collateral_utxo)?;
                let option_utxo = fetch_utxo(*option_asset_utxo)?;
                let grantor_utxo = fetch_utxo(*grantor_asset_utxo)?;
                let fee_utxo_out = fetch_utxo(*fee_utxo)?;
                assert_eq!(
                    taproot_pubkey_gen.address.script_pubkey(),
                    cov_utxo.script_pubkey,
                    "Expected collateral UTXO script to match options address"
                );

                let total_fee = fee_utxo_out.value.explicit().unwrap();

                let total_collateral = cov_utxo.value.explicit().unwrap();
                let collateral_amount_to_withdraw =
                    (*amount_to_burn).saturating_mul(option_arguments.collateral_per_contract);
                anyhow::ensure!(
                    collateral_amount_to_withdraw <= total_collateral,
                    "collateral exceeds input value"
                );

                // Asset ids
                let option_token_id =
                    AssetId::from_str(&option_arguments.option_token_asset_id_hex_le)?;
                let grantor_token_id =
                    AssetId::from_str(&option_arguments.grantor_token_asset_id_hex_le)?;

                let total_option_token_amount = option_utxo.value.explicit().unwrap();
                let total_grantor_token_amount = grantor_utxo.value.explicit().unwrap();

                let recipient = get_p2pk_address(
                    &keypair.x_only_public_key().0,
                    &AddressParams::LIQUID_TESTNET,
                )?;

                // Build PST
                let mut pst = PartiallySignedTransaction::new_v2();
                pst.add_input(Input::from_prevout(*collateral_utxo));
                pst.add_input(Input::from_prevout(*option_asset_utxo));
                pst.add_input(Input::from_prevout(*grantor_asset_utxo));
                pst.add_input(Input::from_prevout(*fee_utxo));

                // Compute change needs
                let is_collateral_change_needed = total_collateral != collateral_amount_to_withdraw;
                let is_option_change_needed = total_option_token_amount != *amount_to_burn;
                let is_grantor_change_needed = total_grantor_token_amount != *amount_to_burn;
                let is_lbtc_change_needed = total_fee != *fee_amount;

                // change (collateral) back to covenant if needed
                if is_collateral_change_needed {
                    pst.add_output(Output::new_explicit(
                        taproot_pubkey_gen.address.script_pubkey(),
                        total_collateral - collateral_amount_to_withdraw,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // burn option tokens
                pst.add_output(Output::new_explicit(
                    Script::new_op_return(b"burn"),
                    *amount_to_burn,
                    option_token_id,
                    None,
                ));

                // burn grantor tokens
                pst.add_output(Output::new_explicit(
                    Script::new_op_return(b"burn"),
                    *amount_to_burn,
                    grantor_token_id,
                    None,
                ));

                // withdraw collateral to recipient
                pst.add_output(Output::new_explicit(
                    recipient.script_pubkey(),
                    collateral_amount_to_withdraw,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                // token changes if any
                if is_option_change_needed {
                    pst.add_output(Output::new_explicit(
                        recipient.script_pubkey(),
                        total_option_token_amount - *amount_to_burn,
                        option_token_id,
                        None,
                    ));
                }
                if is_grantor_change_needed {
                    pst.add_output(Output::new_explicit(
                        recipient.script_pubkey(),
                        total_grantor_token_amount - *amount_to_burn,
                        grantor_token_id,
                        None,
                    ));
                }

                // LBTC change if any
                if is_lbtc_change_needed {
                    pst.add_output(Output::new_explicit(
                        recipient.script_pubkey(),
                        total_fee - *fee_amount,
                        LIQUID_TESTNET_BITCOIN_ASSET,
                        None,
                    ));
                }

                // fee
                pst.add_output(Output::new_explicit(
                    Script::new(),
                    *fee_amount,
                    LIQUID_TESTNET_BITCOIN_ASSET,
                    None,
                ));

                let mut tx = pst.extract_tx()?;
                tx.input[0].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[1].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[2].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;
                tx.input[3].sequence = Sequence::ENABLE_LOCKTIME_NO_RBF;

                let utxos = vec![cov_utxo, option_utxo, grantor_utxo, fee_utxo_out];
                let options_program = get_options_program(&option_arguments)?;

                let witness_values = contracts::build_witness::build_option_witness(
                    TokenBranch::OptionToken,
                    contracts::build_witness::OptionBranch::Cancellation {
                        is_change_needed: is_collateral_change_needed,
                        index_to_spend: 0,
                        amount_to_burn: *amount_to_burn,
                        collateral_amount_to_withdraw,
                    },
                );
                let tx = finalize_transaction(
                    tx,
                    &options_program,
                    &taproot_pubkey_gen.pubkey.to_x_only_pubkey(),
                    &utxos,
                    0,
                    witness_values,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                // sign option token input
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    1,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                // sign grantor token input
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    2,
                    &AddressParams::LIQUID_TESTNET,
                    *LIQUID_TESTNET_GENESIS,
                )?;

                // sign fee input
                let tx = finalize_p2pk_transaction(
                    tx,
                    &utxos,
                    &keypair,
                    3,
                    &AddressParams::LIQUID_TESTNET,
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
