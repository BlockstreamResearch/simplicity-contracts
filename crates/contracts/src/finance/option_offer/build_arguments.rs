#![allow(clippy::missing_errors_doc)]

use crate::arguments_helpers::{extract_u32, extract_u64, extract_u256_bytes};
use crate::error::FromArgumentsError;
use serde_json::Value;
use simplicityhl::elements::AssetId;
use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};
use std::collections::HashMap;
use wallet_abi::WalletAbiError;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct OptionOfferArguments {
    /// Asset ID of collateral (the asset user deposits)
    collateral_asset_id: [u8; 32],
    /// Asset ID of premium (the second asset user deposits, linked to collateral)
    premium_asset_id: [u8; 32],
    /// Asset ID of settlement asset (the asset counterparty pays with)
    settlement_asset_id: [u8; 32],
    /// Settlement rate: `settlement_amount` = `COLLATERAL_PER_CONTRACT` * `collateral_amount`
    collateral_per_contract: u64,
    /// Premium rate: `premium_amount` = `PREMIUM_PER_COLLATERAL` * `collateral_amount`
    premium_per_collateral: u64,
    /// Unix timestamp after which user can reclaim collateral and premium
    expiry_time: u32,
    /// User's x-only public key for signature verification (32 bytes)
    user_pubkey: [u8; 32],
}

impl OptionOfferArguments {
    /// Create new option offer arguments.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        collateral_asset_id: AssetId,
        premium_asset_id: AssetId,
        settlement_asset_id: AssetId,
        collateral_per_contract: u64,
        premium_per_collateral: u64,
        expiry_time: u32,
        user_pubkey: [u8; 32],
    ) -> Self {
        Self {
            collateral_asset_id: collateral_asset_id.into_inner().0,
            premium_asset_id: premium_asset_id.into_inner().0,
            settlement_asset_id: settlement_asset_id.into_inner().0,
            collateral_per_contract,
            premium_per_collateral,
            expiry_time,
            user_pubkey,
        }
    }

    /// Build arguments for contract instantiation.
    #[must_use]
    pub fn build_arguments(&self) -> Arguments {
        Arguments::from(HashMap::from([
            (
                WitnessName::from_str_unchecked("COLLATERAL_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.collateral_asset_id,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("PREMIUM_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.premium_asset_id,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("SETTLEMENT_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.settlement_asset_id,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("COLLATERAL_PER_CONTRACT"),
                simplicityhl::Value::from(UIntValue::U64(self.collateral_per_contract)),
            ),
            (
                WitnessName::from_str_unchecked("PREMIUM_PER_COLLATERAL"),
                simplicityhl::Value::from(UIntValue::U64(self.premium_per_collateral)),
            ),
            (
                WitnessName::from_str_unchecked("EXPIRY_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.expiry_time)),
            ),
            (
                WitnessName::from_str_unchecked("USER_PUBKEY"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(self.user_pubkey))),
            ),
        ]))
    }

    pub fn to_json(&self) -> Result<Value, WalletAbiError> {
        serde_json::to_value(self.build_arguments()).map_err(WalletAbiError::from)
    }

    /// Returns the collateral per contract amount.
    #[must_use]
    pub const fn collateral_per_contract(&self) -> u64 {
        self.collateral_per_contract
    }

    /// Returns the premium per collateral amount.
    #[must_use]
    pub const fn premium_per_collateral(&self) -> u64 {
        self.premium_per_collateral
    }

    /// Returns the expiry time.
    #[must_use]
    pub const fn expiry_time(&self) -> u32 {
        self.expiry_time
    }

    /// Returns the user's public key.
    #[must_use]
    pub const fn user_pubkey(&self) -> [u8; 32] {
        self.user_pubkey
    }

    /// Returns the collateral asset ID.
    ///
    /// # Panics
    ///
    /// Panics if the collateral asset ID bytes are invalid.
    #[must_use]
    pub fn get_collateral_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.collateral_asset_id).unwrap()
    }

    /// Returns the premium asset ID.
    ///
    /// # Panics
    ///
    /// Panics if the premium asset ID bytes are invalid.
    #[must_use]
    pub fn get_premium_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.premium_asset_id).unwrap()
    }

    /// Returns the settlement asset ID.
    ///
    /// # Panics
    ///
    /// Panics if the settlement asset ID bytes are invalid.
    #[must_use]
    pub fn get_settlement_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.settlement_asset_id).unwrap()
    }

    /// Build struct from Simplicity Arguments.
    ///
    /// # Errors
    ///
    /// Returns error if any required witness is missing, has wrong type, or has invalid value.
    pub fn from_arguments(args: &Arguments) -> Result<Self, FromArgumentsError> {
        let collateral_asset_id = extract_u256_bytes(args, "COLLATERAL_ASSET_ID")?;
        let premium_asset_id = extract_u256_bytes(args, "PREMIUM_ASSET_ID")?;
        let settlement_asset_id = extract_u256_bytes(args, "SETTLEMENT_ASSET_ID")?;
        let collateral_per_contract = extract_u64(args, "COLLATERAL_PER_CONTRACT")?;
        let premium_per_collateral = extract_u64(args, "PREMIUM_PER_COLLATERAL")?;
        let expiry_time = extract_u32(args, "EXPIRY_TIME")?;
        let user_pubkey = extract_u256_bytes(args, "USER_PUBKEY")?;

        Ok(Self {
            collateral_asset_id,
            premium_asset_id,
            settlement_asset_id,
            collateral_per_contract,
            premium_per_collateral,
            expiry_time,
            user_pubkey,
        })
    }
}

impl wallet_abi::Encodable for OptionOfferArguments {}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_abi::Encodable;

    #[test]
    fn test_serialize_deserialize_default() -> anyhow::Result<()> {
        let args = OptionOfferArguments::default();

        let serialized = args.encode()?;
        let deserialized = OptionOfferArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }

    #[test]
    fn test_serialize_deserialize_full() -> anyhow::Result<()> {
        let args = OptionOfferArguments::new(
            AssetId::from_slice(&[1u8; 32])?,
            AssetId::from_slice(&[2u8; 32])?,
            AssetId::from_slice(&[3u8; 32])?,
            1000,
            100,
            1_700_000_000,
            [4u8; 32],
        );

        let serialized = args.encode()?;
        let deserialized = OptionOfferArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }

    #[test]
    fn test_arguments_roundtrip_default() -> anyhow::Result<()> {
        let original = OptionOfferArguments::default();
        let arguments = original.build_arguments();

        let recovered = OptionOfferArguments::from_arguments(&arguments)?;

        assert_eq!(original, recovered);

        Ok(())
    }

    #[test]
    fn test_arguments_roundtrip_full() -> anyhow::Result<()> {
        let original = OptionOfferArguments::new(
            AssetId::from_slice(&[1u8; 32])?,
            AssetId::from_slice(&[2u8; 32])?,
            AssetId::from_slice(&[3u8; 32])?,
            1000,
            100,
            1_700_000_000,
            [4u8; 32],
        );
        let arguments = original.build_arguments();

        let recovered = OptionOfferArguments::from_arguments(&arguments)?;

        assert_eq!(original, recovered);

        Ok(())
    }
}
