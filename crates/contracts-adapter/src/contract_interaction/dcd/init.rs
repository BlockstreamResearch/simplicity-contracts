use crate::dcd::common::convert_asset_entropy;
use crate::dcd::types::{
    FillerTokenEntropyHex, GrantorCollateralAssetEntropyHex, GrantorSettlementAssetEntropyHex,
};
use contracts::{DCDArguments, MergeBranch};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::{AddressParams, AssetId, OutPoint, Transaction};
use simplicityhl::{elements, simplicity};
use simplicityhl_core::{AssetIdHex, TaprootPubkeyGen};

pub struct DcdManager;

#[derive(Debug)]
pub struct DcdInitParams {
    pub taker_funding_start_time: u32,
    pub taker_funding_end_time: u32,
    pub contract_expiry_time: u32,
    pub early_termination_end_time: u32,
    pub settlement_height: u32,
    pub principal_collateral_amount: u64,
    pub incentive_basis_points: u64,
    pub filler_per_principal_collateral: u64,
    pub strike_price: u64,
    pub collateral_asset_id: AssetIdHex,
    pub settlement_asset_id: AssetIdHex,
    pub oracle_public_key: secp256k1::PublicKey,
}

#[derive(Debug)]
pub struct DcdInitResponse {
    pub tx: Transaction,
    pub filler_token_entropy: FillerTokenEntropyHex,
    pub grantor_collateral_token_entropy: GrantorCollateralAssetEntropyHex,
    pub grantor_settlement_token_entropy: GrantorSettlementAssetEntropyHex,
    pub taproot_pubkey_gen: TaprootPubkeyGen,
    pub dcd_args: DCDArguments,
}

impl DcdManager {
    #[allow(clippy::too_many_arguments)]
    pub fn maker_init(
        keypair: &secp256k1::Keypair,
        blinder_key: &secp256k1::Keypair,
        input_utxos: &[OutPoint; 3],
        dcd_init_params: DcdInitParams,
        fee_amount: u64,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<DcdInitResponse> {
        crate::dcd::handlers::maker_init::handle(
            keypair,
            blinder_key,
            input_utxos,
            dcd_init_params,
            fee_amount,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn maker_funding(
        keypair: &secp256k1::Keypair,
        blinding_key: &secp256k1::Keypair,
        filler_token_info: (OutPoint, impl AsRef<[u8]>),
        grantor_collateral_token_info: (OutPoint, impl AsRef<[u8]>),
        grantor_settlement_token_info: (OutPoint, impl AsRef<[u8]>),
        settlement_asset_info: OutPoint,
        fee_utxo: OutPoint,
        fee_amount: u64,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        dcd_arguments: &DCDArguments,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        let filler_token_info = (
            filler_token_info.0,
            convert_asset_entropy(filler_token_info.1)?,
        );
        let grantor_collateral_token_info = (
            grantor_collateral_token_info.0,
            convert_asset_entropy(grantor_collateral_token_info.1)?,
        );
        let grantor_settlement_token_info = (
            grantor_settlement_token_info.0,
            convert_asset_entropy(grantor_settlement_token_info.1)?,
        );
        crate::dcd::handlers::maker_funding::handle(
            keypair,
            blinding_key,
            filler_token_info,
            grantor_collateral_token_info,
            grantor_settlement_token_info,
            settlement_asset_info,
            fee_utxo,
            fee_amount,
            dcd_taproot_pubkey_gen,
            dcd_arguments,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn taker_funding(
        keypair: &secp256k1::Keypair,
        filler_token_utxo: OutPoint,
        collateral_token_utxo: OutPoint,
        fee_amount: u64,
        collateral_amount_to_deposit: u64,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        dcd_arguments: &DCDArguments,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::taker_funding::handle(
            keypair,
            filler_token_utxo,
            collateral_token_utxo,
            fee_amount,
            collateral_amount_to_deposit,
            dcd_taproot_pubkey_gen,
            dcd_arguments,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn taker_early_termination(
        keypair: &secp256k1::Keypair,
        filler_token_utxo: OutPoint,
        collateral_token_utxo: OutPoint,
        fee_utxo: OutPoint,
        fee_amount: u64,
        filler_token_amount_to_return: u64,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        dcd_arguments: &DCDArguments,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::taker_termination_early::handle(
            keypair,
            filler_token_utxo,
            collateral_token_utxo,
            fee_utxo,
            fee_amount,
            filler_token_amount_to_return,
            dcd_taproot_pubkey_gen,
            dcd_arguments,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn maker_collateral_termination(
        keypair: &secp256k1::Keypair,
        collateral_token_utxo: OutPoint,
        grantor_collateral_token_utxo: OutPoint,
        fee_utxo: OutPoint,
        fee_amount: u64,
        grantor_collateral_amount_to_burn: u64,
        dcd_arguments: &DCDArguments,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::maker_termination_collateral::handle(
            keypair,
            collateral_token_utxo,
            grantor_collateral_token_utxo,
            fee_utxo,
            fee_amount,
            grantor_collateral_amount_to_burn,
            dcd_arguments,
            dcd_taproot_pubkey_gen,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn maker_settlement_termination(
        keypair: &secp256k1::Keypair,
        settlement_asset_utxo: OutPoint,
        grantor_settlement_token_utxo: OutPoint,
        fee_utxo: OutPoint,
        fee_amount: u64,
        grantor_settlement_amount_to_burn: u64,
        dcd_arguments: &DCDArguments,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::maker_termination_settlement::handle(
            keypair,
            settlement_asset_utxo,
            grantor_settlement_token_utxo,
            fee_utxo,
            fee_amount,
            grantor_settlement_amount_to_burn,
            dcd_arguments,
            dcd_taproot_pubkey_gen,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn maker_settlement(
        keypair: &secp256k1::Keypair,
        asset_utxo: OutPoint,
        grantor_collateral_token_utxo: OutPoint,
        grantor_settlement_token_utxo: OutPoint,
        fee_utxo: OutPoint,
        fee_amount: u64,
        price_at_current_block_height: u64,
        oracle_signature: String,
        grantor_amount_to_burn: u64,
        dcd_arguments: &DCDArguments,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::maker_settlement::handle(
            keypair,
            asset_utxo,
            grantor_collateral_token_utxo,
            grantor_settlement_token_utxo,
            fee_utxo,
            fee_amount,
            price_at_current_block_height,
            oracle_signature,
            grantor_amount_to_burn,
            dcd_arguments,
            dcd_taproot_pubkey_gen,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn taker_settlement(
        keypair: &secp256k1::Keypair,
        asset_utxo: OutPoint,
        filler_token_utxo: OutPoint,
        fee_utxo: OutPoint,
        fee_amount: u64,
        price_at_current_block_height: u64,
        filler_amount_to_burn: u64,
        oracle_signature: &str,
        dcd_arguments: &DCDArguments,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::taker_settlement::handle(
            keypair,
            asset_utxo,
            filler_token_utxo,
            fee_utxo,
            fee_amount,
            price_at_current_block_height,
            filler_amount_to_burn,
            oracle_signature,
            dcd_arguments,
            dcd_taproot_pubkey_gen,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn merge_tokens(
        keypair: &secp256k1::Keypair,
        token_utxos: &[OutPoint],
        fee_utxo: OutPoint,
        fee_amount: u64,
        merge_branch: MergeBranch,
        dcd_taproot_pubkey_gen: &TaprootPubkeyGen,
        dcd_arguments: &DCDArguments,
        address_params: &'static AddressParams,
        change_asset: AssetId,
        genesis_block_hash: simplicity::elements::BlockHash,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::merge_tokens::handle(
            keypair,
            token_utxos,
            fee_utxo,
            fee_amount,
            merge_branch,
            dcd_taproot_pubkey_gen,
            dcd_arguments,
            address_params,
            change_asset,
            genesis_block_hash,
        )
    }
}
