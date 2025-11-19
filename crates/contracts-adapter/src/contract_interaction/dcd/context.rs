use crate::dcd::DcdInitParams;
use contracts::{DCDArguments, MergeBranch};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::{AddressParams, AssetId, OutPoint};
use simplicityhl::simplicity;
use simplicityhl_core::TaprootPubkeyGen;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct CreationContext {
    pub keypair: secp256k1::Keypair,
    pub blinding_key: secp256k1::Keypair,
}

#[derive(Debug, Clone)]
pub struct CommonContext {
    pub keypair: secp256k1::Keypair,
}

#[derive(Debug, Clone)]
pub struct MakerFundingContext<T1, T2, T3> {
    pub filler_token_info: (OutPoint, T1),
    pub grantor_collateral_token_info: (OutPoint, T2),
    pub grantor_settlement_token_info: (OutPoint, T3),
    pub settlement_asset_utxo: OutPoint,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
}

#[derive(Debug, Clone)]
pub struct MakerInitContext {
    pub input_utxos: [OutPoint; 3],
    pub dcd_init_params: DcdInitParams,
    pub fee_amount: u64,
}

#[derive(Debug, Clone)]
pub struct MakerSettlementContext {
    pub asset_utxo: OutPoint,
    pub grantor_collateral_token_utxo: OutPoint,
    pub grantor_settlement_token_utxo: OutPoint,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
    pub price_at_current_block_height: u64,
    pub oracle_signature: String,
    pub grantor_amount_to_burn: u64,
}

#[derive(Debug, Clone)]
pub struct MakerTerminationCollateralContext {
    pub collateral_token_utxo: OutPoint,
    pub grantor_collateral_token_utxo: OutPoint,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
    pub grantor_collateral_amount_to_burn: u64,
}

#[derive(Debug, Clone)]
pub struct MakerTerminationSettlementContext {
    pub settlement_asset_utxo: OutPoint,
    pub grantor_settlement_token_utxo: OutPoint,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
    pub grantor_settlement_amount_to_burn: u64,
}

#[derive(Debug, Clone)]
pub struct MergeTokensContext {
    pub token_utxos: Vec<OutPoint>,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
    pub merge_branch: MergeBranch,
}

#[derive(Debug, Clone)]
pub struct TakerFundingContext {
    pub filler_token_utxo: OutPoint,
    pub collateral_token_utxo: OutPoint,
    pub fee_amount: u64,
    pub collateral_amount_to_deposit: u64,
}

#[derive(Debug, Clone)]
pub struct TakerTerminationEarlyContext {
    pub filler_token_utxo: OutPoint,
    pub collateral_token_utxo: OutPoint,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
    pub filler_token_amount_to_return: u64,
}

#[derive(Debug, Clone)]
pub struct TakerSettlementContext {
    pub asset_utxo: OutPoint,
    pub filler_token_utxo: OutPoint,
    pub fee_utxo: OutPoint,
    pub fee_amount: u64,
    pub price_at_current_block_height: u64,
    pub filler_amount_to_burn: u64,
    pub oracle_signature: String,
}

#[derive(Debug, Clone)]
pub struct DcdContractContext {
    pub dcd_taproot_pubkey_gen: TaprootPubkeyGen,
    pub dcd_arguments: DCDArguments,
    pub base_contract_context: BaseContractContext,
}

#[derive(Debug, Clone)]
pub struct BaseContractContext {
    pub address_params: &'static AddressParams,
    pub lbtc_asset: AssetId,
    pub genesis_block_hash: simplicity::elements::BlockHash,
}
