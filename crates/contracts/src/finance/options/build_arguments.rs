use std::collections::HashMap;

use simplicityhl::elements::AssetId;
use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct OptionsArguments {
    start_time: u32,
    expiry_time: u32,
    collateral_per_contract: u64,
    settlement_per_contract: u64,
    collateral_asset_id: [u8; 32],
    settlement_asset_id: [u8; 32],
    issuance_asset_entropy: [u8; 32],
    option_token_asset: [u8; 32],
    option_reissuance_token_asset: [u8; 32],
    grantor_token_asset: [u8; 32],
    grantor_reissuance_token_asset: [u8; 32],
}

impl OptionsArguments {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        start_time: u32,
        expiry_time: u32,
        collateral_per_contract: u64,
        settlement_per_contract: u64,
        collateral_asset_id: AssetId,
        settlement_asset_id: AssetId,
        issuance_asset_entropy: [u8; 32],
        option_token_asset: AssetId,
        option_reissuance_token_asset: AssetId,
        grantor_token_asset: AssetId,
        grantor_reissuance_token_asset: AssetId,
    ) -> Self {
        Self {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id: collateral_asset_id.into_inner().0,
            settlement_asset_id: settlement_asset_id.into_inner().0,
            issuance_asset_entropy,
            option_token_asset: option_token_asset.into_inner().0,
            option_reissuance_token_asset: option_reissuance_token_asset.into_inner().0,
            grantor_token_asset: grantor_token_asset.into_inner().0,
            grantor_reissuance_token_asset: grantor_reissuance_token_asset.into_inner().0,
        }
    }

    #[must_use]
    pub const fn start_time(&self) -> u32 {
        self.start_time
    }

    #[must_use]
    pub const fn expiry_time(&self) -> u32 {
        self.expiry_time
    }

    #[must_use]
    pub const fn collateral_per_contract(&self) -> u64 {
        self.collateral_per_contract
    }

    #[must_use]
    pub const fn settlement_per_contract(&self) -> u64 {
        self.settlement_per_contract
    }

    #[must_use]
    pub const fn issuance_asset_entropy(&self) -> [u8; 32] {
        self.issuance_asset_entropy
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn option_token(&self) -> AssetId {
        AssetId::from_slice(&self.option_token_asset)
            .expect("option_token_asset must be a valid 32-byte asset id")
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn option_reissuance_token(&self) -> AssetId {
        AssetId::from_slice(&self.option_reissuance_token_asset)
            .expect("option_reissuance_token_asset must be a valid 32-byte asset id")
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn grantor_token(&self) -> AssetId {
        AssetId::from_slice(&self.grantor_token_asset)
            .expect("grantor_token_asset must be a valid 32-byte asset id")
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn grantor_reissuance_token(&self) -> AssetId {
        AssetId::from_slice(&self.grantor_reissuance_token_asset)
            .expect("grantor_reissuance_token_asset must be a valid 32-byte asset id")
    }

    #[must_use]
    pub fn get_option_token_ids(&self) -> (AssetId, AssetId) {
        (self.option_token(), self.option_reissuance_token())
    }

    #[must_use]
    pub fn get_grantor_token_ids(&self) -> (AssetId, AssetId) {
        (self.grantor_token(), self.grantor_reissuance_token())
    }

    #[must_use]
    pub fn build_option_arguments(&self) -> Arguments {
        Arguments::from(HashMap::from([
            (
                WitnessName::from_str_unchecked("START_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.start_time)),
            ),
            (
                WitnessName::from_str_unchecked("EXPIRY_TIME"),
                simplicityhl::Value::from(UIntValue::U32(self.expiry_time)),
            ),
            (
                WitnessName::from_str_unchecked("COLLATERAL_PER_CONTRACT"),
                simplicityhl::Value::from(UIntValue::U64(self.collateral_per_contract)),
            ),
            (
                WitnessName::from_str_unchecked("SETTLEMENT_PER_CONTRACT"),
                simplicityhl::Value::from(UIntValue::U64(self.settlement_per_contract)),
            ),
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
                WitnessName::from_str_unchecked("OPTION_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.option_token_asset,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("OPTION_REISSUANCE_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.option_reissuance_token_asset,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.grantor_token_asset,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_REISSUANCE_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.grantor_reissuance_token_asset,
                ))),
            ),
        ]))
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn get_settlement_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.settlement_asset_id)
            .expect("settlement_asset_id must be a valid 32-byte asset id")
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn get_collateral_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.collateral_asset_id)
            .expect("collateral_asset_id must be a valid 32-byte asset id")
    }
}

impl wallet_abi::Encodable for OptionsArguments {}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_abi::Encodable;

    const NETWORK: ::wallet_abi::Network = ::wallet_abi::Network::TestnetLiquid;

    #[test]
    fn test_serialize_deserialize_default() -> anyhow::Result<()> {
        let args = OptionsArguments::default();
        let serialized = args.encode()?;
        let deserialized = OptionsArguments::decode(&serialized)?;
        assert_eq!(args, deserialized);
        Ok(())
    }

    #[test]
    fn test_serialize_deserialize_full() -> anyhow::Result<()> {
        let option_token_asset = AssetId::from_slice(&[4; 32])?;
        let option_reissuance_token_asset = AssetId::from_slice(&[5; 32])?;
        let grantor_token_asset = AssetId::from_slice(&[6; 32])?;
        let grantor_reissuance_token_asset = AssetId::from_slice(&[7; 32])?;

        let args = OptionsArguments::new(
            10,
            50,
            100,
            1000,
            *NETWORK.policy_asset(),
            *NETWORK.policy_asset(),
            [3u8; 32],
            option_token_asset,
            option_reissuance_token_asset,
            grantor_token_asset,
            grantor_reissuance_token_asset,
        );

        let serialized = args.encode()?;
        let deserialized = OptionsArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }
}
