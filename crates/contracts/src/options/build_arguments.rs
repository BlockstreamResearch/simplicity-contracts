use std::collections::HashMap;

use hex::FromHex;

use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
pub struct OptionsArguments {
    pub start_time: u32,
    pub expiry_time: u32,
    pub contract_size: u64,
    pub asset_strike_price: u64,
    pub grantor_token_strike_price: u64,
    pub lbtc_asset_id_hex_le: String,
    pub collateral_asset_id_hex_le: String,
    pub target_asset_id_hex_le: String,
    pub option_token_asset_id_hex_le: String,
    pub grantor_token_asset_id_hex_le: String,
    pub reissuance_option_token_asset_id_hex_le: String,
    pub reissuance_grantor_token_asset_id_hex_le: String,
}

impl Default for OptionsArguments {
    fn default() -> Self {
        Self {
            start_time: 0,
            expiry_time: 0,
            contract_size: 0,
            asset_strike_price: 0,
            grantor_token_strike_price: 0,
            collateral_asset_id_hex_le: "00".repeat(32),
            lbtc_asset_id_hex_le: "00".repeat(32),
            option_token_asset_id_hex_le: "00".repeat(32),
            grantor_token_asset_id_hex_le: "00".repeat(32),
            reissuance_option_token_asset_id_hex_le: "00".repeat(32),
            reissuance_grantor_token_asset_id_hex_le: "00".repeat(32),
            target_asset_id_hex_le: "00".repeat(32),
        }
    }
}

impl OptionsArguments {
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
                WitnessName::from_str_unchecked("CONTRACT_SIZE"),
                simplicityhl::Value::from(UIntValue::U64(self.contract_size)),
            ),
            (
                WitnessName::from_str_unchecked("ASSET_STRIKE_PRICE"),
                simplicityhl::Value::from(UIntValue::U64(self.asset_strike_price)),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_TOKEN_STRIKE_PRICE"),
                simplicityhl::Value::from(UIntValue::U64(self.grantor_token_strike_price)),
            ),
            (
                WitnessName::from_str_unchecked("LBTC_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.lbtc_asset_id_hex_le,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("COLLATERAL_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.collateral_asset_id_hex_le,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("TARGET_ASSET_ID"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.target_asset_id_hex_le,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("OPTION_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.option_token_asset_id_hex_le,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.grantor_token_asset_id_hex_le,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("REISSUANCE_OPTION_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.reissuance_option_token_asset_id_hex_le,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("REISSUANCE_GRANTOR_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(u256_from_le_hex(
                    &self.reissuance_grantor_token_asset_id_hex_le,
                ))),
            ),
        ]))
    }
}

impl simplicityhl_core::Encodable for OptionsArguments {}

fn u256_from_le_hex(hex_le: &str) -> U256 {
    let mut bytes = <[u8; 32]>::from_hex(hex_le).expect("expected 32 bytes hex");
    bytes.reverse();
    U256::from_byte_array(bytes)
}

#[cfg(test)]
mod tests {
    use simplicityhl::simplicity::elements;
    use simplicityhl_core::{Encodable, LIQUID_TESTNET_TEST_ASSET_ID_STR};

    use super::*;

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
            contract_size: 100,
            asset_strike_price: 1000,
            grantor_token_strike_price: 1000,
            lbtc_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            collateral_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            target_asset_id_hex_le: LIQUID_TESTNET_TEST_ASSET_ID_STR.to_string(),
            option_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            reissuance_option_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            grantor_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
            reissuance_grantor_token_asset_id_hex_le: elements::AssetId::LIQUID_BTC.to_string(),
        };

        let serialized = args.encode()?;
        let deserialized = OptionsArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);
        Ok(())
    }
}
