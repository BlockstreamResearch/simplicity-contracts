use std::collections::HashMap;

use simplicityhl::elements::hashes::{Hash, sha256};
use simplicityhl::elements::{AssetId, ContractHash, OutPoint};
use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct OptionsArguments {
    pub start_time: u32,
    pub expiry_time: u32,
    pub collateral_per_contract: u64,
    pub settlement_per_contract: u64,
    pub collateral_asset_id: [u8; 32],
    pub settlement_asset_id: [u8; 32],
    pub option_token_entropy: [u8; 32],
    pub grantor_token_entropy: [u8; 32],
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
        option_creation_outpoint: OutPoint,
        grantor_creation_outpoint: OutPoint,
    ) -> Self {
        Self {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id: collateral_asset_id.into_inner().0,
            settlement_asset_id: settlement_asset_id.into_inner().0,
            option_token_entropy: AssetId::generate_asset_entropy(
                option_creation_outpoint,
                ContractHash::from_byte_array(issuance_asset_entropy),
            )
            .0,
            grantor_token_entropy: AssetId::generate_asset_entropy(
                grantor_creation_outpoint,
                ContractHash::from_byte_array(issuance_asset_entropy),
            )
            .0,
        }
    }

    #[must_use]
    pub fn build_option_arguments(&self) -> Arguments {
        let (option_asset_id, _) = self.get_option_token_ids();
        let (grantor_asset_id, _) = self.get_grantor_token_ids();

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
                    option_asset_id.into_inner().0,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    grantor_asset_id.into_inner().0,
                ))),
            ),
        ]))
    }

    /// Returns the grantor token ID and reissuance asset ID.
    #[must_use]
    pub fn get_grantor_token_ids(&self) -> (AssetId, AssetId) {
        let grantor_asset_entropy = sha256::Midstate::from_byte_array(self.grantor_token_entropy);

        (
            AssetId::from_entropy(grantor_asset_entropy),
            AssetId::reissuance_token_from_entropy(grantor_asset_entropy, false),
        )
    }

    /// Returns the option token ID and reissuance asset ID.
    #[must_use]
    pub fn get_option_token_ids(&self) -> (AssetId, AssetId) {
        let option_asset_entropy = sha256::Midstate::from_byte_array(self.option_token_entropy);

        (
            AssetId::from_entropy(option_asset_entropy),
            AssetId::reissuance_token_from_entropy(option_asset_entropy, false),
        )
    }

    /// Returns the settlement asset ID.
    ///
    /// # Panics
    ///
    /// Panics if the settlement asset ID bytes are invalid. This should never
    /// happen since the field is a fixed 32-byte array.
    #[must_use]
    pub fn get_settlement_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.settlement_asset_id).unwrap()
    }

    /// Returns the collateral asset ID.
    ///
    /// # Panics
    ///
    /// Panics if the collateral asset ID bytes are invalid. This should never
    /// happen since the field is a fixed 32-byte array.
    #[must_use]
    pub fn get_collateral_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.collateral_asset_id).unwrap()
    }
}

impl simplicityhl_core::Encodable for OptionsArguments {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::taproot_pubkey_gen::get_random_seed;
    use simplicityhl_core::Encodable;

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
        let args = OptionsArguments {
            start_time: 10,
            expiry_time: 50,
            collateral_per_contract: 100,
            settlement_per_contract: 1000,
            collateral_asset_id: AssetId::LIQUID_BTC.into_inner().0,
            settlement_asset_id: AssetId::LIQUID_BTC.into_inner().0,
            option_token_entropy: get_random_seed(),
            grantor_token_entropy: get_random_seed(),
        };

        let serialized = args.encode()?;
        let deserialized = OptionsArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }
}
