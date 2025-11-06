use std::collections::HashMap;
use std::str::FromStr;

use hex::FromHex;

use anyhow::{Result, anyhow, ensure};

use simplicityhl::num::U256;
use simplicityhl::{
    Arguments, simplicity::bitcoin::XOnlyPublicKey, str::WitnessName, value::UIntValue,
};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
pub struct DCDArguments {
    // Time parameters
    pub taker_funding_start_time: u32,
    pub taker_funding_end_time: u32,
    pub contract_expiry_time: u32,
    pub early_termination_end_time: u32,
    pub settlement_height: u32,

    // Pricing parameters
    pub strike_price: u64,
    pub incentive_basis_points: u64,

    // Asset IDs (hex LE strings)
    pub collateral_asset_id_hex_le: String,
    pub settlement_asset_id_hex_le: String,
    pub filler_token_asset_id_hex_le: String,
    pub grantor_collateral_token_asset_id_hex_le: String,
    pub grantor_settlement_token_asset_id_hex_le: String,

    // Ratio/denominator parameters
    pub ratio_args: DCDRatioArguments,

    // Oracle
    pub oracle_public_key: String,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Default)]
pub struct DCDRatioArguments {
    pub principal_collateral_amount: u64,
    pub interest_collateral_amount: u64,
    pub total_collateral_amount: u64,
    pub principal_asset_amount: u64,
    pub interest_asset_amount: u64,
    pub total_asset_amount: u64,
    pub filler_token_amount: u64,
    pub grantor_collateral_token_amount: u64,
    pub grantor_settlement_token_amount: u64,
    pub filler_per_settlement_collateral: u64,
    pub filler_per_settlement_asset: u64,
    pub filler_per_principal_collateral: u64,
    pub grantor_settlement_per_deposited_asset: u64,
    pub grantor_collateral_per_deposited_collateral: u64,
    pub grantor_per_settlement_collateral: u64,
    pub grantor_per_settlement_asset: u64,
}

pub const MAX_BASIS_POINTS: u64 = 10000;

impl DCDRatioArguments {
    pub fn build_from(
        principal_collateral_amount: u64,
        incentive_basis_points: u64,
        strike_price: u64,
        filler_per_principal_collateral: u64,
    ) -> Result<Self> {
        // interest_collateral_amount = (principal_collateral_amount * incentive_basis_points) / MAX_BASIS_POINTS
        let ic_num: u128 = (principal_collateral_amount as u128)
            .checked_mul(incentive_basis_points as u128)
            .ok_or_else(|| {
                anyhow!("overflow while computing interest_collateral_amount numerator")
            })?;
        ensure!(
            ic_num.is_multiple_of(MAX_BASIS_POINTS as u128),
            "principal_collateral_amount * incentive_basis_points must be divisible by MAX_BASIS_POINTS ({}), remainder {}",
            MAX_BASIS_POINTS,
            ic_num % (MAX_BASIS_POINTS as u128)
        );
        let interest_collateral_amount: u64 = (ic_num / (MAX_BASIS_POINTS as u128))
            .try_into()
            .map_err(|_| anyhow!("interest_collateral_amount exceeds u64"))?;

        let total_collateral_amount = principal_collateral_amount
            .checked_add(interest_collateral_amount)
            .ok_or_else(|| anyhow!("overflow while computing total_collateral_amount"))?;

        // principal_asset_amount = principal_collateral_amount * strike_price
        let principal_asset_amount = principal_collateral_amount
            .checked_mul(strike_price)
            .ok_or_else(|| anyhow!("overflow while computing principal_asset_amount"))?;

        // interest_asset_amount = (principal_asset_amount * incentive_basis_points) / MAX_BASIS_POINTS
        let ia_num: u128 = (principal_asset_amount as u128)
            .checked_mul(incentive_basis_points as u128)
            .ok_or_else(|| anyhow!("overflow while computing interest_asset_amount numerator"))?;
        ensure!(
            ia_num.is_multiple_of(MAX_BASIS_POINTS as u128),
            "principal_asset_amount * incentive_basis_points must be divisible by MAX_BASIS_POINTS ({}), remainder {}",
            MAX_BASIS_POINTS,
            ia_num % (MAX_BASIS_POINTS as u128)
        );
        let interest_asset_amount: u64 = (ia_num / (MAX_BASIS_POINTS as u128))
            .try_into()
            .map_err(|_| anyhow!("interest_asset_amount exceeds u64"))?;

        let total_asset_amount = principal_asset_amount
            .checked_add(interest_asset_amount)
            .ok_or_else(|| anyhow!("overflow while computing total_asset_amount"))?;

        // filler_token_amount = principal_collateral_amount / filler_per_principal_collateral
        ensure!(
            filler_per_principal_collateral != 0,
            "filler_per_principal_collateral must be non-zero"
        );
        ensure!(
            principal_collateral_amount.is_multiple_of(filler_per_principal_collateral),
            "principal_collateral_amount must be divisible by filler_per_principal_collateral, remainder {}",
            principal_collateral_amount % filler_per_principal_collateral
        );
        let filler_token_amount = principal_collateral_amount / filler_per_principal_collateral;
        ensure!(
            filler_token_amount != 0,
            "filler_token_amount computed to zero; would cause division by zero later"
        );

        let grantor_collateral_token_amount = filler_token_amount;
        let grantor_settlement_token_amount = filler_token_amount;

        // filler_per_settlement_* divisions by filler_token_amount
        ensure!(
            total_collateral_amount % filler_token_amount == 0,
            "total_collateral_amount must be divisible by filler_token_amount, remainder {}",
            total_collateral_amount % filler_token_amount
        );
        let filler_per_settlement_collateral = total_collateral_amount / filler_token_amount;

        ensure!(
            total_asset_amount % filler_token_amount == 0,
            "total_asset_amount must be divisible by filler_token_amount, remainder {}",
            total_asset_amount % filler_token_amount
        );
        let filler_per_settlement_asset = total_asset_amount / filler_token_amount;

        // grantor_* per deposited/settlement divisions by grantor_*_token_amount (same as filler_token_amount)
        ensure!(
            total_asset_amount % grantor_settlement_token_amount == 0,
            "total_asset_amount must be divisible by grantor_settlement_token_amount, remainder {}",
            total_asset_amount % grantor_settlement_token_amount
        );
        let grantor_settlement_per_deposited_asset =
            total_asset_amount / grantor_settlement_token_amount;

        ensure!(
            interest_collateral_amount.is_multiple_of(grantor_collateral_token_amount),
            "interest_collateral_amount must be divisible by grantor_collateral_token_amount, remainder {}",
            interest_collateral_amount % grantor_collateral_token_amount
        );
        let grantor_collateral_per_deposited_collateral =
            interest_collateral_amount / grantor_collateral_token_amount;

        ensure!(
            total_collateral_amount % grantor_settlement_token_amount == 0,
            "total_collateral_amount must be divisible by grantor_settlement_token_amount, remainder {}",
            total_collateral_amount % grantor_settlement_token_amount
        );
        let grantor_per_settlement_collateral =
            total_collateral_amount / grantor_settlement_token_amount;

        ensure!(
            total_asset_amount % grantor_settlement_token_amount == 0,
            "total_asset_amount must be divisible by grantor_settlement_token_amount, remainder {}",
            total_asset_amount % grantor_settlement_token_amount
        );
        let grantor_per_settlement_asset = total_asset_amount / grantor_settlement_token_amount;

        Ok(Self {
            principal_collateral_amount,
            interest_collateral_amount,
            total_collateral_amount,
            principal_asset_amount,
            interest_asset_amount,
            total_asset_amount,
            filler_token_amount,
            grantor_collateral_token_amount,
            grantor_settlement_token_amount,
            filler_per_settlement_collateral,
            filler_per_settlement_asset,
            filler_per_principal_collateral,
            grantor_settlement_per_deposited_asset,
            grantor_collateral_per_deposited_collateral,
            grantor_per_settlement_collateral,
            grantor_per_settlement_asset,
        })
    }
}

impl Default for DCDArguments {
    fn default() -> Self {
        Self {
            taker_funding_start_time: 0,
            taker_funding_end_time: 0,
            contract_expiry_time: 0,
            early_termination_end_time: 0,
            settlement_height: 0,
            strike_price: 0,
            incentive_basis_points: 0,
            collateral_asset_id_hex_le: "00".repeat(32),
            settlement_asset_id_hex_le: "00".repeat(32),
            filler_token_asset_id_hex_le: "00".repeat(32),
            grantor_collateral_token_asset_id_hex_le: "00".repeat(32),
            grantor_settlement_token_asset_id_hex_le: "00".repeat(32),
            ratio_args: DCDRatioArguments::default(),
            oracle_public_key: String::new(),
        }
    }
}

impl DCDArguments {
    pub fn build_arguments(&self) -> Arguments {
        let collateral_asset = u256_from_le_hex(&self.collateral_asset_id_hex_le);
        let settlement_asset = u256_from_le_hex(&self.settlement_asset_id_hex_le);
        let filler_token_asset = u256_from_le_hex(&self.filler_token_asset_id_hex_le);
        let grantor_collateral_token_asset =
            u256_from_le_hex(&self.grantor_collateral_token_asset_id_hex_le);
        let grantor_settlement_token_asset =
            u256_from_le_hex(&self.grantor_settlement_token_asset_id_hex_le);

        let oracle_bytes = XOnlyPublicKey::from_str(self.oracle_public_key.as_str())
            .unwrap()
            .serialize();

        Arguments::from(HashMap::from([
            // Times
            (
                WitnessName::from_str_unchecked("TAKER_FUNDING_START_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.taker_funding_start_time)),
            ),
            (
                WitnessName::from_str_unchecked("TAKER_FUNDING_END_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.taker_funding_end_time)),
            ),
            (
                WitnessName::from_str_unchecked("CONTRACT_EXPIRY_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.contract_expiry_time)),
            ),
            (
                WitnessName::from_str_unchecked("EARLY_TERMINATION_END_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.early_termination_end_time)),
            ),
            (
                WitnessName::from_str_unchecked("SETTLEMENT_HEIGHT"),
                simplicityhl::Value::from(UIntValue::U32(self.settlement_height)),
            ),
            // Pricing
            (
                WitnessName::from_str_unchecked("STRIKE_PRICE"),
                simplicityhl::Value::from(UIntValue::U64(self.strike_price)),
            ),
            (
                WitnessName::from_str_unchecked("INCENTIVE_BASIS_POINTS"),
                simplicityhl::Value::from(UIntValue::U64(self.incentive_basis_points)),
            ),
            // Assets
            (
                WitnessName::from_str_unchecked("COLLATERAL_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(collateral_asset)),
            ),
            (
                WitnessName::from_str_unchecked("SETTLEMENT_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(settlement_asset)),
            ),
            (
                WitnessName::from_str_unchecked("FILLER_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(filler_token_asset)),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_COLLATERAL_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(grantor_collateral_token_asset)),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_SETTLEMENT_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(grantor_settlement_token_asset)),
            ),
            // Ratios
            (
                WitnessName::from_str_unchecked("FILLER_PER_SETTLEMENT_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.filler_per_settlement_collateral,
                )),
            ),
            (
                WitnessName::from_str_unchecked("FILLER_PER_SETTLEMENT_ASSET"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.filler_per_settlement_asset,
                )),
            ),
            (
                WitnessName::from_str_unchecked("FILLER_PER_PRINCIPAL_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.filler_per_principal_collateral,
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_SETTLEMENT_PER_DEPOSITED_ASSET"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_settlement_per_deposited_asset,
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_COLLATERAL_PER_DEPOSITED_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_collateral_per_deposited_collateral,
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_PER_SETTLEMENT_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_per_settlement_collateral,
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_PER_SETTLEMENT_ASSET"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_per_settlement_asset,
                )),
            ),
            // Oracle
            (
                WitnessName::from_str_unchecked("ORACLE_PK"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(oracle_bytes))),
            ),
        ]))
    }
}

impl simplicityhl_core::Encodable for DCDArguments {}

fn u256_from_le_hex(hex_le: &str) -> U256 {
    let mut bytes = <[u8; 32]>::from_hex(hex_le).expect("expected 32 bytes hex");
    bytes.reverse();
    U256::from_byte_array(bytes)
}
