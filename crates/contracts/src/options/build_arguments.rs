use std::collections::HashMap;

use simplicityhl::elements::hashes::Hash;
use simplicityhl::elements::{AssetId, ContractHash, OutPoint, Txid};
use simplicityhl::num::U256;
use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

use crate::arguments_helpers::{extract_bool, extract_u32, extract_u64, extract_u256_bytes};
use crate::error::FromArgumentsError;

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct OutPointWithConfidential {
    txid: [u8; 32],
    vout: u32,
    confidential: bool,
}

impl OutPointWithConfidential {
    #[must_use]
    pub fn new(outpoint: OutPoint, confidential: bool) -> Self {
        Self {
            txid: outpoint.txid.to_byte_array(),
            vout: outpoint.vout,
            confidential,
        }
    }

    /// Convert back to `OutPoint`.
    ///
    /// # Panics
    ///
    /// Panics if the stored txid bytes are invalid (should never happen).
    #[must_use]
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(Txid::from_slice(&self.txid).unwrap(), self.vout)
    }

    /// Returns the confidential flag.
    #[must_use]
    pub const fn confidential(&self) -> bool {
        self.confidential
    }

    /// Returns as tuple (`OutPoint`, bool).
    #[must_use]
    pub fn as_tuple(&self) -> (OutPoint, bool) {
        (self.outpoint(), self.confidential)
    }
}

impl From<(OutPoint, bool)> for OutPointWithConfidential {
    fn from((outpoint, confidential): (OutPoint, bool)) -> Self {
        Self::new(outpoint, confidential)
    }
}

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq, Default)]
pub struct OptionsArguments {
    start_time: u32,
    expiry_time: u32,
    collateral_per_contract: u64,
    settlement_per_contract: u64,
    collateral_asset_id: [u8; 32],
    settlement_asset_id: [u8; 32],
    issuance_asset_entropy: [u8; 32],
    option_creation_outpoint: OutPointWithConfidential,
    grantor_creation_outpoint: OutPointWithConfidential,
}

impl OptionsArguments {
    /// Create new options arguments.
    ///
    /// # Arguments
    ///
    /// * `option_creation_outpoint` - Tuple of (`OutPoint`, `confidential_flag`) for option token
    /// * `grantor_creation_outpoint` - Tuple of (`OutPoint`, `confidential_flag`) for grantor token
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
        option_creation_outpoint: (OutPoint, bool),
        grantor_creation_outpoint: (OutPoint, bool),
    ) -> Self {
        Self {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id: collateral_asset_id.into_inner().0,
            settlement_asset_id: settlement_asset_id.into_inner().0,
            issuance_asset_entropy,
            option_creation_outpoint: option_creation_outpoint.into(),
            grantor_creation_outpoint: grantor_creation_outpoint.into(),
        }
    }

    /// Returns the start time.
    #[must_use]
    pub const fn start_time(&self) -> u32 {
        self.start_time
    }

    /// Returns the expiry time.
    #[must_use]
    pub const fn expiry_time(&self) -> u32 {
        self.expiry_time
    }

    /// Returns the collateral per contract amount.
    #[must_use]
    pub const fn collateral_per_contract(&self) -> u64 {
        self.collateral_per_contract
    }

    /// Returns the settlement per contract amount.
    #[must_use]
    pub const fn settlement_per_contract(&self) -> u64 {
        self.settlement_per_contract
    }

    /// Returns the issuance asset entropy.
    #[must_use]
    pub const fn issuance_asset_entropy(&self) -> [u8; 32] {
        self.issuance_asset_entropy
    }

    /// Returns the option creation outpoint with confidential flag.
    #[must_use]
    pub fn option_creation_outpoint(&self) -> (OutPoint, bool) {
        self.option_creation_outpoint.as_tuple()
    }

    /// Returns the grantor creation outpoint with confidential flag.
    #[must_use]
    pub fn grantor_creation_outpoint(&self) -> (OutPoint, bool) {
        self.grantor_creation_outpoint.as_tuple()
    }

    /// Computes and returns the option token entropy.
    #[must_use]
    pub fn option_token_entropy(&self) -> [u8; 32] {
        let contract_hash = ContractHash::from_byte_array(self.issuance_asset_entropy);
        AssetId::generate_asset_entropy(self.option_creation_outpoint.outpoint(), contract_hash).0
    }

    /// Computes and returns the grantor token entropy.
    #[must_use]
    pub fn grantor_token_entropy(&self) -> [u8; 32] {
        let contract_hash = ContractHash::from_byte_array(self.issuance_asset_entropy);
        AssetId::generate_asset_entropy(self.grantor_creation_outpoint.outpoint(), contract_hash).0
    }

    /// Computes and returns the option token asset ID.
    #[must_use]
    pub fn option_token(&self) -> AssetId {
        let entropy = simplicityhl::elements::hashes::sha256::Midstate::from_byte_array(
            self.option_token_entropy(),
        );
        AssetId::from_entropy(entropy)
    }

    /// Computes and returns the option reissuance token asset ID.
    #[must_use]
    pub fn option_reissuance_token(&self) -> AssetId {
        let entropy = simplicityhl::elements::hashes::sha256::Midstate::from_byte_array(
            self.option_token_entropy(),
        );
        AssetId::reissuance_token_from_entropy(
            entropy,
            self.option_creation_outpoint.confidential(),
        )
    }

    /// Computes and returns the grantor token asset ID.
    #[must_use]
    pub fn grantor_token(&self) -> AssetId {
        let entropy = simplicityhl::elements::hashes::sha256::Midstate::from_byte_array(
            self.grantor_token_entropy(),
        );
        AssetId::from_entropy(entropy)
    }

    /// Computes and returns the grantor reissuance token asset ID.
    #[must_use]
    pub fn grantor_reissuance_token(&self) -> AssetId {
        let entropy = simplicityhl::elements::hashes::sha256::Midstate::from_byte_array(
            self.grantor_token_entropy(),
        );
        AssetId::reissuance_token_from_entropy(
            entropy,
            self.grantor_creation_outpoint.confidential(),
        )
    }

    /// Returns the option token ID and reissuance asset ID as a tuple.
    #[must_use]
    pub fn get_option_token_ids(&self) -> (AssetId, AssetId) {
        (self.option_token(), self.option_reissuance_token())
    }

    /// Returns the grantor token ID and reissuance asset ID as a tuple.
    #[must_use]
    pub fn get_grantor_token_ids(&self) -> (AssetId, AssetId) {
        (self.grantor_token(), self.grantor_reissuance_token())
    }

    /// Build Simplicity arguments for contract instantiation.
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
                WitnessName::from_str_unchecked("ISSUANCE_ASSET_ENTROPY"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.issuance_asset_entropy,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("OPTION_OUTPOINT_TXID"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.option_creation_outpoint.txid,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("OPTION_OUTPOINT_VOUT"),
                simplicityhl::Value::from(UIntValue::U32(self.option_creation_outpoint.vout)),
            ),
            (
                WitnessName::from_str_unchecked("OPTION_CONFIDENTIAL"),
                simplicityhl::Value::from(self.option_creation_outpoint.confidential),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_OUTPOINT_TXID"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.grantor_creation_outpoint.txid,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_OUTPOINT_VOUT"),
                simplicityhl::Value::from(UIntValue::U32(self.grantor_creation_outpoint.vout)),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_CONFIDENTIAL"),
                simplicityhl::Value::from(self.grantor_creation_outpoint.confidential),
            ),
            // Also include computed values for convenience
            (
                WitnessName::from_str_unchecked("OPTION_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.option_token().into_inner().0,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("OPTION_REISSUANCE_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.option_reissuance_token().into_inner().0,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.grantor_token().into_inner().0,
                ))),
            ),
            (
                WitnessName::from_str_unchecked("GRANTOR_REISSUANCE_TOKEN_ASSET"),
                simplicityhl::Value::from(UIntValue::U256(U256::from_byte_array(
                    self.grantor_reissuance_token().into_inner().0,
                ))),
            ),
        ]))
    }

    /// Build struct from Simplicity Arguments.
    ///
    /// # Errors
    ///
    /// Returns error if any required witness is missing, has wrong type, or has invalid value.
    pub fn from_arguments(args: &Arguments) -> Result<Self, FromArgumentsError> {
        let start_time = extract_u32(args, "START_TIME")?;
        let expiry_time = extract_u32(args, "EXPIRY_TIME")?;
        let collateral_per_contract = extract_u64(args, "COLLATERAL_PER_CONTRACT")?;
        let settlement_per_contract = extract_u64(args, "SETTLEMENT_PER_CONTRACT")?;
        let collateral_asset_id = extract_u256_bytes(args, "COLLATERAL_ASSET_ID")?;
        let settlement_asset_id = extract_u256_bytes(args, "SETTLEMENT_ASSET_ID")?;
        let issuance_asset_entropy = extract_u256_bytes(args, "ISSUANCE_ASSET_ENTROPY")?;

        let option_outpoint_txid = extract_u256_bytes(args, "OPTION_OUTPOINT_TXID")?;
        let option_outpoint_vout = extract_u32(args, "OPTION_OUTPOINT_VOUT")?;
        let option_confidential = extract_bool(args, "OPTION_CONFIDENTIAL")?;

        let grantor_outpoint_txid = extract_u256_bytes(args, "GRANTOR_OUTPOINT_TXID")?;
        let grantor_outpoint_vout = extract_u32(args, "GRANTOR_OUTPOINT_VOUT")?;
        let grantor_confidential = extract_bool(args, "GRANTOR_CONFIDENTIAL")?;

        Ok(Self {
            start_time,
            expiry_time,
            collateral_per_contract,
            settlement_per_contract,
            collateral_asset_id,
            settlement_asset_id,
            issuance_asset_entropy,
            option_creation_outpoint: OutPointWithConfidential {
                txid: option_outpoint_txid,
                vout: option_outpoint_vout,
                confidential: option_confidential,
            },
            grantor_creation_outpoint: OutPointWithConfidential {
                txid: grantor_outpoint_txid,
                vout: grantor_outpoint_vout,
                confidential: grantor_confidential,
            },
        })
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
    use simplicityhl::elements::hashes::Hash;
    use simplicityhl_core::{Encodable, LIQUID_TESTNET_BITCOIN_ASSET};

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
        let args = OptionsArguments::new(
            10,
            50,
            100,
            1000,
            *LIQUID_TESTNET_BITCOIN_ASSET,
            *LIQUID_TESTNET_BITCOIN_ASSET,
            get_random_seed(),
            (OutPoint::new(Txid::from_slice(&[1; 32])?, 0), false),
            (OutPoint::new(Txid::from_slice(&[2; 32])?, 0), false),
        );

        let serialized = args.encode()?;
        let deserialized = OptionsArguments::decode(&serialized)?;

        assert_eq!(args, deserialized);

        Ok(())
    }

    #[test]
    fn test_arguments_roundtrip_default() -> anyhow::Result<()> {
        let original = OptionsArguments::default();
        let arguments = original.build_option_arguments();

        let recovered = OptionsArguments::from_arguments(&arguments)?;

        assert_eq!(original, recovered);

        Ok(())
    }

    #[test]
    fn test_arguments_roundtrip_full() -> anyhow::Result<()> {
        let original = OptionsArguments::new(
            10,
            50,
            100,
            1000,
            *LIQUID_TESTNET_BITCOIN_ASSET,
            *LIQUID_TESTNET_BITCOIN_ASSET,
            get_random_seed(),
            (OutPoint::new(Txid::from_slice(&[1; 32])?, 0), false),
            (OutPoint::new(Txid::from_slice(&[2; 32])?, 0), true),
        );
        let arguments = original.build_option_arguments();

        let recovered = OptionsArguments::from_arguments(&arguments)?;

        assert_eq!(original, recovered);

        Ok(())
    }
}
