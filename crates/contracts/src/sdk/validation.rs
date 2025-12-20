//! Extensions and validation helpers for Elements transaction outputs.

use simplicityhl::elements::{AssetId, TxOut};

use crate::error::ValidationError;

/// Extension trait for [`TxOut`] providing convenient access to explicit values.
pub trait TxOutExt {
    /// Returns the explicit (non-confidential) asset and value.
    ///
    /// # Errors
    ///
    /// Returns an error if the asset or value is confidential (blinded).
    fn explicit(&self) -> Result<(AssetId, u64), ValidationError>;

    /// Returns the explicit (non-confidential) value.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is confidential (blinded).
    fn explicit_value(&self) -> Result<u64, ValidationError>;

    /// Returns the explicit (non-confidential) asset ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the asset is confidential (blinded).
    fn explicit_asset(&self) -> Result<AssetId, ValidationError>;

    /// Validates that this UTXO can cover the required amount.
    ///
    /// Returns the change amount (available - required) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The value is confidential
    /// - The available amount is less than required
    fn validate_amount(&self, required: u64) -> Result<u64, ValidationError>;

    /// Validates that this UTXO can cover the required fee with the expected asset.
    ///
    /// Returns the change amount (available - required) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The value or asset is confidential
    /// - The asset doesn't match the expected fee asset
    /// - The available amount is less than required
    fn validate_fee(&self, required: u64, expected_asset: AssetId) -> Result<u64, ValidationError>;
}

impl TxOutExt for TxOut {
    fn explicit(&self) -> Result<(AssetId, u64), ValidationError> {
        Ok((self.explicit_asset()?, self.explicit_value()?))
    }

    fn explicit_value(&self) -> Result<u64, ValidationError> {
        self.value
            .explicit()
            .ok_or_else(|| ValidationError::ConfidentialValue {
                script_hash: self.script_pubkey.script_hash().to_string(),
            })
    }

    fn explicit_asset(&self) -> Result<AssetId, ValidationError> {
        self.asset
            .explicit()
            .ok_or_else(|| ValidationError::ConfidentialAsset {
                script_hash: self.script_pubkey.script_hash().to_string(),
            })
    }

    fn validate_amount(&self, required: u64) -> Result<u64, ValidationError> {
        let available = self.explicit_value()?;

        if available < required {
            return Err(ValidationError::InsufficientFunds {
                script_hash: self.script_pubkey.script_hash().to_string(),
                available,
                required,
            });
        }

        Ok(available - required)
    }

    fn validate_fee(&self, required: u64, expected_asset: AssetId) -> Result<u64, ValidationError> {
        let asset = self.explicit_asset()?;

        if asset != expected_asset {
            return Err(ValidationError::FeeAssetMismatch {
                script_hash: self.script_pubkey.script_hash().to_string(),
                expected: expected_asset.to_string(),
                actual: asset.to_string(),
            });
        }

        self.validate_amount(required)
    }
}
