use std::collections::HashMap;

use simplicityhl::elements::AssetId;
use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct SwapWithChangeArguments {
    /// Asset ID of collateral (the asset user deposits)
    pub collateral_asset_id: [u8; 32],
    /// Asset ID of settlement asset (the asset counterparty pays with)
    pub settlement_asset_id: [u8; 32],
    /// Settlement rate: `settlement_amount` = `COLLATERAL_PER_CONTRACT` * `collateral_amount`
    pub collateral_per_contract: u64,
    /// Unix timestamp after which user can reclaim collateral
    pub expiry_time: u32,
    /// User's x-only public key for signature verification (32 bytes)
    pub user_pubkey: [u8; 32],
}

impl SwapWithChangeArguments {
    /// Create new swap with change arguments.
    #[must_use]
    pub const fn new(
        collateral_asset_id: [u8; 32],
        settlement_asset_id: [u8; 32],
        collateral_per_contract: u64,
        expiry_time: u32,
        user_pubkey: [u8; 32],
    ) -> Self {
        Self {
            collateral_asset_id,
            settlement_asset_id,
            collateral_per_contract,
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
                WitnessName::from_str_unchecked("EXPIRY_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.expiry_time)),
            ),
            (
                WitnessName::from_str_unchecked("USER_PUBKEY"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(self.user_pubkey))),
            ),
        ]))
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

    /// Returns the settlement asset ID.
    ///
    /// # Panics
    ///
    /// Panics if the settlement asset ID bytes are invalid.
    #[must_use]
    pub fn get_settlement_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.settlement_asset_id).unwrap()
    }
}

impl simplicityhl_core::Encodable for SwapWithChangeArguments {}

#[cfg(test)]
mod tests {
    use super::*;
    use simplicityhl_core::Encodable;

    #[test]
    fn test_serialize_deserialize_default() -> anyhow::Result<()> {
        let args = SwapWithChangeArguments::default();

        let serialized = args.encode()?;
        let deserialized = SwapWithChangeArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }

    #[test]
    fn test_serialize_deserialize_full() -> anyhow::Result<()> {
        let args = SwapWithChangeArguments {
            collateral_asset_id: [1u8; 32],
            settlement_asset_id: [2u8; 32],
            collateral_per_contract: 1000,
            expiry_time: 1_700_000_000,
            user_pubkey: [3u8; 32],
        };

        let serialized = args.encode()?;
        let deserialized = SwapWithChangeArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }
}
