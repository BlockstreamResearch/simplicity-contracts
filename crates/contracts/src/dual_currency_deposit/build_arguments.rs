use std::collections::HashMap;
use std::str::FromStr;

use hex::FromHex;

use simplicityhl::num::U256;
use simplicityhl::{
    Arguments, simplicity::bitcoin::XOnlyPublicKey, str::WitnessName, value::UIntValue,
};

use crate::error::DCDRatioError;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct DCDArguments {
    // Time parameters
    taker_funding_start_time: u32,
    taker_funding_end_time: u32,
    contract_expiry_time: u32,
    early_termination_end_time: u32,
    settlement_height: u32,

    // Pricing parameters
    strike_price: u64,
    incentive_basis_points: u64,

    // Asset IDs (hex LE strings)
    collateral_asset_id_hex_le: String,
    settlement_asset_id_hex_le: String,
    filler_token_asset_id_hex_le: String,
    grantor_collateral_token_asset_id_hex_le: String,
    grantor_settlement_token_asset_id_hex_le: String,

    // Fee parameters
    fee_basis_points: u64,
    fee_script_hash_hex_le: String,

    // Ratio/denominator parameters
    ratio_args: DCDRatioArguments,

    // Oracle
    oracle_public_key: String,
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct DCDRatioArguments {
    principal_collateral_amount: u64,
    interest_collateral_amount: u64,
    total_collateral_amount: u64,
    principal_asset_amount: u64,
    interest_asset_amount: u64,
    total_asset_amount: u64,
    filler_token_amount: u64,
    grantor_collateral_token_amount: u64,
    grantor_settlement_token_amount: u64,
    filler_per_settlement_collateral: u64,
    filler_per_settlement_asset: u64,
    filler_per_principal_collateral: u64,
    grantor_settlement_per_deposited_asset: u64,
    grantor_collateral_per_deposited_collateral: u64,
    grantor_per_settlement_collateral: u64,
    grantor_per_settlement_asset: u64,
}

impl DCDRatioArguments {
    /// Returns the principal collateral amount.
    #[must_use]
    pub const fn principal_collateral_amount(&self) -> u64 {
        self.principal_collateral_amount
    }

    /// Returns the interest collateral amount.
    #[must_use]
    pub const fn interest_collateral_amount(&self) -> u64 {
        self.interest_collateral_amount
    }

    /// Returns the total collateral amount.
    #[must_use]
    pub const fn total_collateral_amount(&self) -> u64 {
        self.total_collateral_amount
    }

    /// Returns the principal asset amount.
    #[must_use]
    pub const fn principal_asset_amount(&self) -> u64 {
        self.principal_asset_amount
    }

    /// Returns the interest asset amount.
    #[must_use]
    pub const fn interest_asset_amount(&self) -> u64 {
        self.interest_asset_amount
    }

    /// Returns the total asset amount.
    #[must_use]
    pub const fn total_asset_amount(&self) -> u64 {
        self.total_asset_amount
    }

    /// Returns the filler token amount.
    #[must_use]
    pub const fn filler_token_amount(&self) -> u64 {
        self.filler_token_amount
    }

    /// Returns the grantor collateral token amount.
    #[must_use]
    pub const fn grantor_collateral_token_amount(&self) -> u64 {
        self.grantor_collateral_token_amount
    }

    /// Returns the grantor settlement token amount.
    #[must_use]
    pub const fn grantor_settlement_token_amount(&self) -> u64 {
        self.grantor_settlement_token_amount
    }

    /// Returns the filler per settlement collateral ratio.
    #[must_use]
    pub const fn filler_per_settlement_collateral(&self) -> u64 {
        self.filler_per_settlement_collateral
    }

    /// Returns the filler per settlement asset ratio.
    #[must_use]
    pub const fn filler_per_settlement_asset(&self) -> u64 {
        self.filler_per_settlement_asset
    }

    /// Returns the filler per principal collateral ratio.
    #[must_use]
    pub const fn filler_per_principal_collateral(&self) -> u64 {
        self.filler_per_principal_collateral
    }

    /// Returns the grantor settlement per deposited asset ratio.
    #[must_use]
    pub const fn grantor_settlement_per_deposited_asset(&self) -> u64 {
        self.grantor_settlement_per_deposited_asset
    }

    /// Returns the grantor collateral per deposited collateral ratio.
    #[must_use]
    pub const fn grantor_collateral_per_deposited_collateral(&self) -> u64 {
        self.grantor_collateral_per_deposited_collateral
    }

    /// Returns the grantor per settlement collateral ratio.
    #[must_use]
    pub const fn grantor_per_settlement_collateral(&self) -> u64 {
        self.grantor_per_settlement_collateral
    }

    /// Returns the grantor per settlement asset ratio.
    #[must_use]
    pub const fn grantor_per_settlement_asset(&self) -> u64 {
        self.grantor_per_settlement_asset
    }
}

pub const MAX_BASIS_POINTS: u64 = 10000;

impl DCDRatioArguments {
    /// Build ratio arguments from contract parameters.
    ///
    /// # Errors
    /// Returns error if arithmetic overflow occurs or divisibility requirements aren't met.
    #[expect(clippy::too_many_lines)]
    pub fn build_from(
        principal_collateral_amount: u64,
        incentive_basis_points: u64,
        strike_price: u64,
        filler_per_principal_collateral: u64,
    ) -> Result<Self, DCDRatioError> {
        // interest_collateral_amount = (principal_collateral_amount * incentive_basis_points) / MAX_BASIS_POINTS
        let interest_collateral_amount: u128 = u128::from(principal_collateral_amount)
            .checked_mul(u128::from(incentive_basis_points))
            .ok_or_else(|| DCDRatioError::Overflow {
                operation: "principal_collateral_amount * incentive_basis_points".to_string(),
            })?;

        let remainder = interest_collateral_amount % u128::from(MAX_BASIS_POINTS);
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "principal_collateral_amount * incentive_basis_points".to_string(),
                divisor: "MAX_BASIS_POINTS".to_string(),
                #[allow(clippy::cast_possible_truncation)]
                remainder: remainder as u64,
            });
        }
        let interest_collateral_amount: u64 = (interest_collateral_amount
            / u128::from(MAX_BASIS_POINTS))
        .try_into()
        .map_err(|_| DCDRatioError::U64Overflow {
            value_name: "interest_collateral_amount".to_string(),
        })?;

        let total_collateral_amount = principal_collateral_amount
            .checked_add(interest_collateral_amount)
            .ok_or_else(|| DCDRatioError::Overflow {
                operation: "principal_collateral_amount + interest_collateral_amount".to_string(),
            })?;

        // principal_asset_amount = principal_collateral_amount * strike_price
        let principal_asset_amount = principal_collateral_amount
            .checked_mul(strike_price)
            .ok_or_else(|| DCDRatioError::Overflow {
                operation: "principal_collateral_amount * strike_price".to_string(),
            })?;

        // interest_asset_amount = (principal_asset_amount * incentive_basis_points) / MAX_BASIS_POINTS
        let interest_asset_amount: u128 = u128::from(principal_asset_amount)
            .checked_mul(u128::from(incentive_basis_points))
            .ok_or_else(|| DCDRatioError::Overflow {
                operation: "principal_asset_amount * incentive_basis_points".to_string(),
            })?;

        let remainder = interest_asset_amount % u128::from(MAX_BASIS_POINTS);
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "principal_asset_amount * incentive_basis_points".to_string(),
                divisor: "MAX_BASIS_POINTS".to_string(),
                #[allow(clippy::cast_possible_truncation)]
                remainder: remainder as u64,
            });
        }
        let interest_asset_amount: u64 = (interest_asset_amount / u128::from(MAX_BASIS_POINTS))
            .try_into()
            .map_err(|_| DCDRatioError::U64Overflow {
                value_name: "interest_asset_amount".to_string(),
            })?;

        let total_asset_amount = principal_asset_amount
            .checked_add(interest_asset_amount)
            .ok_or_else(|| DCDRatioError::Overflow {
                operation: "principal_asset_amount + interest_asset_amount".to_string(),
            })?;

        // filler_token_amount = principal_collateral_amount / filler_per_principal_collateral
        if filler_per_principal_collateral == 0 {
            return Err(DCDRatioError::ZeroValue {
                value_name: "filler_per_principal_collateral".to_string(),
            });
        }
        let remainder = principal_collateral_amount % filler_per_principal_collateral;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "principal_collateral_amount".to_string(),
                divisor: "filler_per_principal_collateral".to_string(),
                remainder,
            });
        }
        let filler_token_amount = principal_collateral_amount / filler_per_principal_collateral;
        if filler_token_amount == 0 {
            return Err(DCDRatioError::ZeroValue {
                value_name: "filler_token_amount".to_string(),
            });
        }

        let grantor_collateral_token_amount = filler_token_amount;
        let grantor_settlement_token_amount = filler_token_amount;

        // filler_per_settlement_* divisions by filler_token_amount
        let remainder = total_collateral_amount % filler_token_amount;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "total_collateral_amount".to_string(),
                divisor: "filler_token_amount".to_string(),
                remainder,
            });
        }
        let filler_per_settlement_collateral = total_collateral_amount / filler_token_amount;

        let remainder = total_asset_amount % filler_token_amount;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "total_asset_amount".to_string(),
                divisor: "filler_token_amount".to_string(),
                remainder,
            });
        }
        let filler_per_settlement_asset = total_asset_amount / filler_token_amount;

        // grantor_* per deposited/settlement divisions by grantor_*_token_amount (same as filler_token_amount)
        let remainder = total_asset_amount % grantor_settlement_token_amount;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "total_asset_amount".to_string(),
                divisor: "grantor_settlement_token_amount".to_string(),
                remainder,
            });
        }
        let grantor_settlement_per_deposited_asset =
            total_asset_amount / grantor_settlement_token_amount;

        let remainder = interest_collateral_amount % grantor_collateral_token_amount;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "interest_collateral_amount".to_string(),
                divisor: "grantor_collateral_token_amount".to_string(),
                remainder,
            });
        }
        let grantor_collateral_per_deposited_collateral =
            interest_collateral_amount / grantor_collateral_token_amount;

        let remainder = total_collateral_amount % grantor_settlement_token_amount;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "total_collateral_amount".to_string(),
                divisor: "grantor_settlement_token_amount".to_string(),
                remainder,
            });
        }
        let grantor_per_settlement_collateral =
            total_collateral_amount / grantor_settlement_token_amount;

        let remainder = total_asset_amount % grantor_settlement_token_amount;
        if remainder != 0 {
            return Err(DCDRatioError::NotDivisible {
                dividend: "total_asset_amount".to_string(),
                divisor: "grantor_settlement_token_amount".to_string(),
                remainder,
            });
        }
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
            fee_basis_points: 0,
            collateral_asset_id_hex_le: "00".repeat(32),
            settlement_asset_id_hex_le: "00".repeat(32),
            filler_token_asset_id_hex_le: "00".repeat(32),
            grantor_collateral_token_asset_id_hex_le: "00".repeat(32),
            grantor_settlement_token_asset_id_hex_le: "00".repeat(32),
            fee_script_hash_hex_le: "00".repeat(32),
            ratio_args: DCDRatioArguments::default(),
            oracle_public_key: String::new(),
        }
    }
}

impl DCDArguments {
    /// Create new DCD arguments.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        taker_funding_start_time: u32,
        taker_funding_end_time: u32,
        contract_expiry_time: u32,
        early_termination_end_time: u32,
        settlement_height: u32,
        strike_price: u64,
        incentive_basis_points: u64,
        fee_basis_points: u64,
        collateral_asset_id_hex_le: String,
        settlement_asset_id_hex_le: String,
        filler_token_asset_id_hex_le: String,
        grantor_collateral_token_asset_id_hex_le: String,
        grantor_settlement_token_asset_id_hex_le: String,
        ratio_args: DCDRatioArguments,
        oracle_public_key: String,
        fee_script_hash_hex_le: String,
    ) -> Self {
        Self {
            taker_funding_start_time,
            taker_funding_end_time,
            contract_expiry_time,
            early_termination_end_time,
            settlement_height,
            strike_price,
            incentive_basis_points,
            collateral_asset_id_hex_le,
            settlement_asset_id_hex_le,
            filler_token_asset_id_hex_le,
            grantor_collateral_token_asset_id_hex_le,
            grantor_settlement_token_asset_id_hex_le,
            fee_basis_points,
            fee_script_hash_hex_le,
            ratio_args,
            oracle_public_key,
        }
    }

    /// Returns the taker funding start time.
    #[must_use]
    pub const fn taker_funding_start_time(&self) -> u32 {
        self.taker_funding_start_time
    }

    /// Returns the early termination end time.
    #[must_use]
    pub const fn early_termination_end_time(&self) -> u32 {
        self.early_termination_end_time
    }

    /// Convert to Simplicity program arguments.
    ///
    /// # Panics
    /// Panics if asset IDs or public key cannot be parsed.
    #[must_use]
    #[expect(clippy::too_many_lines)]
    pub fn build_arguments(&self) -> Arguments {
        let collateral_asset = u256_from_le_hex(&self.collateral_asset_id_hex_le);
        let settlement_asset = u256_from_le_hex(&self.settlement_asset_id_hex_le);
        let filler_token_asset = u256_from_le_hex(&self.filler_token_asset_id_hex_le);
        let grantor_collateral_token_asset =
            u256_from_le_hex(&self.grantor_collateral_token_asset_id_hex_le);
        let grantor_settlement_token_asset =
            u256_from_le_hex(&self.grantor_settlement_token_asset_id_hex_le);
        let fee_script_hash = u256_from_le_hex(&self.fee_script_hash_hex_le);

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
            (
                WitnessName::from_str_unchecked("FEE_BASIS_POINTS"),
                simplicityhl::Value::from(UIntValue::U64(self.fee_basis_points)),
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
                    self.ratio_args.filler_per_settlement_collateral(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("FILLER_PER_SETTLEMENT_ASSET"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.filler_per_settlement_asset(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("FILLER_PER_PRINCIPAL_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.filler_per_principal_collateral(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_SETTLEMENT_PER_DEPOSITED_ASSET"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_settlement_per_deposited_asset(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_COLLATERAL_PER_DEPOSITED_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args
                        .grantor_collateral_per_deposited_collateral(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_PER_SETTLEMENT_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_per_settlement_collateral(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_PER_SETTLEMENT_ASSET"),
                simplicityhl::Value::from(UIntValue::U64(
                    self.ratio_args.grantor_per_settlement_asset(),
                )),
            ),
            (
                WitnessName::from_str_unchecked("FEE_SCRIPT_HASH"),
                simplicityhl::Value::from(UIntValue::U256(fee_script_hash)),
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
