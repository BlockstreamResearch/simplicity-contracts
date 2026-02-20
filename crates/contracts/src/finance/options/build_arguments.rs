use std::collections::HashMap;

use crate::error::FromArgumentsError;
use crate::utils::arguments_helpers::{extract_u32, extract_u64, extract_u256_bytes};

use simplicityhl::elements::AssetId;
use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};
use wallet_abi::schema::values::{RuntimeSimfValue, SimfArguments};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct OptionsArguments {
    /// Unix timestamp (seconds) when exercise/settlement becomes valid.
    start_time: u32,
    /// Unix timestamp (seconds) when expiry path becomes valid.
    expiry_time: u32,
    /// Collateral units locked per option contract.
    collateral_per_contract: u64,
    /// Settlement units paid per option contract.
    settlement_per_contract: u64,
    /// Collateral asset ID committed in covenant parameters.
    collateral_asset_id: [u8; 32],
    /// Settlement asset ID committed in covenant parameters.
    settlement_asset_id: [u8; 32],
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
    ) -> Self {
        Self {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id: collateral_asset_id.into_inner().0,
            settlement_asset_id: settlement_asset_id.into_inner().0,
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
    fn build_arguments(&self) -> Arguments {
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
        ]))
    }

    #[must_use]
    pub fn build_simf_arguments(&self) -> SimfArguments {
        let runtime_arguments: HashMap<String, RuntimeSimfValue> = HashMap::from([
            (
                "OPTION_TOKEN_ASSET".to_string(),
                RuntimeSimfValue::NewIssuanceAsset { input_index: 0 },
            ),
            (
                "OPTION_REISSUANCE_TOKEN_ASSET".to_string(),
                RuntimeSimfValue::NewIssuanceToken { input_index: 0 },
            ),
            (
                "GRANTOR_TOKEN_ASSET".to_string(),
                RuntimeSimfValue::NewIssuanceAsset { input_index: 1 },
            ),
            (
                "GRANTOR_REISSUANCE_TOKEN_ASSET".to_string(),
                RuntimeSimfValue::NewIssuanceToken { input_index: 1 },
            ),
        ]);

        SimfArguments {
            resolved: self.build_arguments(),
            runtime_arguments,
        }
    }

    /// Build struct from Simplicity arguments.
    ///
    /// # Errors
    ///
    /// Returns error if any required parameter is missing or has wrong type.
    pub fn from_arguments(args: &Arguments) -> Result<Self, FromArgumentsError> {
        let start_time_name = WitnessName::from_str_unchecked("START_TIME");
        let expiry_time_name = WitnessName::from_str_unchecked("EXPIRY_TIME");
        let collateral_per_contract_name =
            WitnessName::from_str_unchecked("COLLATERAL_PER_CONTRACT");
        let settlement_per_contract_name =
            WitnessName::from_str_unchecked("SETTLEMENT_PER_CONTRACT");
        let collateral_asset_id_name = WitnessName::from_str_unchecked("COLLATERAL_ASSET_ID");
        let settlement_asset_id_name = WitnessName::from_str_unchecked("SETTLEMENT_ASSET_ID");

        let start_time = extract_u32(args, &start_time_name)?;
        let expiry_time = extract_u32(args, &expiry_time_name)?;
        let collateral_per_contract = extract_u64(args, &collateral_per_contract_name)?;
        let settlement_per_contract = extract_u64(args, &settlement_per_contract_name)?;
        let collateral_asset_id = extract_u256_bytes(args, &collateral_asset_id_name)?;
        let settlement_asset_id = extract_u256_bytes(args, &settlement_asset_id_name)?;

        Ok(Self {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id,
            settlement_asset_id,
        })
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn settlement_asset_id(&self) -> AssetId {
        AssetId::from_slice(&self.settlement_asset_id)
            .expect("settlement_asset_id must be a valid 32-byte asset id")
    }

    #[must_use]
    /// # Panics
    ///
    /// Panics if internal bytes are not a valid `AssetId`.
    pub fn collateral_asset_id(&self) -> AssetId {
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

    fn make_full_args() -> anyhow::Result<OptionsArguments> {
        Ok(OptionsArguments::new(
            10,
            50,
            100,
            1000,
            *NETWORK.policy_asset(),
            AssetId::from_slice(&[2; 32])?,
        ))
    }

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
        let args = make_full_args()?;
        let serialized = args.encode()?;
        let deserialized = OptionsArguments::decode(&serialized)?;
        assert_eq!(args, deserialized);
        assert_eq!(deserialized.start_time(), 10);
        assert_eq!(deserialized.expiry_time(), 50);
        assert_eq!(deserialized.collateral_per_contract(), 100);
        assert_eq!(deserialized.settlement_per_contract(), 1000);
        assert_eq!(deserialized.collateral_asset_id(), *NETWORK.policy_asset());
        assert_eq!(
            deserialized.settlement_asset_id(),
            AssetId::from_slice(&[2; 32])?
        );
        Ok(())
    }

    #[test]
    fn test_arguments_roundtrip_default() -> anyhow::Result<()> {
        let original = OptionsArguments::default();
        let recovered = OptionsArguments::from_arguments(&original.build_arguments())?;
        assert_eq!(original, recovered);
        Ok(())
    }

    #[test]
    fn test_arguments_roundtrip_full() -> anyhow::Result<()> {
        let original = make_full_args()?;
        let recovered = OptionsArguments::from_arguments(&original.build_arguments())?;
        assert_eq!(original, recovered);
        Ok(())
    }
}
