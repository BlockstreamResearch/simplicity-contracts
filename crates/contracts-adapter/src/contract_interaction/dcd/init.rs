use crate::dcd::common::convert_asset_entropy;
use crate::dcd::context::{CreationContext, DcdContractContext, MakerFundingContext};
use crate::dcd::handlers::maker_funding::InnerMakerFundingContext;
use crate::dcd::types::{
    FillerTokenEntropyHex, GrantorCollateralAssetEntropyHex, GrantorSettlementAssetEntropyHex,
};
use crate::dcd::{
    BaseContractContext, CommonContext, MakerInitContext, MakerSettlementContext,
    MakerTerminationCollateralContext, MakerTerminationSettlementContext, MergeTokensContext,
    TakerFundingContext, TakerSettlementContext, TakerTerminationEarlyContext,
};
use contracts::DCDArguments;
use simplicityhl::elements::Transaction;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl_core::{AssetIdHex, TaprootPubkeyGen};
use std::fmt::Debug;

pub struct DcdManager;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct DcdInitResponse {
    pub tx: Transaction,
    pub filler_token_entropy: FillerTokenEntropyHex,
    pub grantor_collateral_token_entropy: GrantorCollateralAssetEntropyHex,
    pub grantor_settlement_token_entropy: GrantorSettlementAssetEntropyHex,
    pub taproot_pubkey_gen: TaprootPubkeyGen,
    pub dcd_args: DCDArguments,
}

impl DcdManager {
    pub fn maker_init(
        creation_context: &CreationContext,
        maker_init_context: MakerInitContext,
        base_contract_context: &BaseContractContext,
    ) -> anyhow::Result<DcdInitResponse> {
        crate::dcd::handlers::maker_init::handle(
            creation_context,
            maker_init_context,
            base_contract_context,
        )
    }
    pub fn maker_funding<
        T1: AsRef<[u8]> + Debug,
        T2: AsRef<[u8]> + Debug,
        T3: AsRef<[u8]> + Debug,
    >(
        creation_context: &CreationContext,
        maker_funding_context: MakerFundingContext<T1, T2, T3>,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        let MakerFundingContext {
            filler_token_info,
            grantor_collateral_token_info,
            grantor_settlement_token_info,
            settlement_asset_utxo,
            fee_utxo,
            fee_amount,
        } = maker_funding_context;

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
        let inner_context = InnerMakerFundingContext {
            filler_reissue_token_info: filler_token_info,
            grantor_collateral_reissue_token_info: grantor_collateral_token_info,
            grantor_settlement_reissue_token_info: grantor_settlement_token_info,
            settlement_asset_utxo,
            fee_utxo,
            fee_amount,
        };
        crate::dcd::handlers::maker_funding::handle(
            creation_context,
            &inner_context,
            dcd_contract_context,
        )
    }
    pub fn taker_funding(
        common_context: &CommonContext,
        taker_funding_context: TakerFundingContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::taker_funding::handle(
            common_context,
            taker_funding_context,
            dcd_contract_context,
        )
    }
    pub fn taker_early_termination(
        common_context: &CommonContext,
        taker_termination_early_context: TakerTerminationEarlyContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::taker_termination_early::handle(
            common_context,
            taker_termination_early_context,
            dcd_contract_context,
        )
    }
    pub fn maker_collateral_termination(
        common_context: &CommonContext,
        maker_termination_context: MakerTerminationCollateralContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::maker_termination_collateral::handle(
            common_context,
            maker_termination_context,
            dcd_contract_context,
        )
    }
    pub fn maker_settlement_termination(
        common_context: &CommonContext,
        maker_settlement_context: MakerTerminationSettlementContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::maker_termination_settlement::handle(
            common_context,
            maker_settlement_context,
            dcd_contract_context,
        )
    }
    pub fn maker_settlement(
        common_context: &CommonContext,
        maker_settlement_context: MakerSettlementContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::maker_settlement::handle(
            common_context,
            maker_settlement_context,
            dcd_contract_context,
        )
    }
    pub fn taker_settlement(
        common_context: &CommonContext,
        taker_settlement_context: TakerSettlementContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::taker_settlement::handle(
            common_context,
            taker_settlement_context,
            dcd_contract_context,
        )
    }
    pub fn merge_tokens(
        common_context: &CommonContext,
        merge_tokens_context: MergeTokensContext,
        dcd_contract_context: &DcdContractContext,
    ) -> anyhow::Result<Transaction> {
        crate::dcd::handlers::merge_tokens::handle(
            common_context,
            merge_tokens_context,
            dcd_contract_context,
        )
    }
}
