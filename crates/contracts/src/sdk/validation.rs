//! Extensions and validation helpers for Elements transaction outputs.

use anyhow::{Result, ensure};
use simplicityhl::elements::{AssetId, TxOut};

/// Extension trait for [`TxOut`] providing convenient access to explicit values.
pub trait TxOutExt {
    /// Returns the explicit (non-confidential) asset and value.
    ///
    /// # Errors
    ///
    /// Returns an error if the asset or value is confidential (blinded).
    fn explicit(&self) -> Result<(AssetId, u64)>;

    /// Returns the explicit (non-confidential) value.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is confidential (blinded).
    fn explicit_value(&self) -> Result<u64>;

    /// Returns the explicit (non-confidential) asset ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the asset is confidential (blinded).
    fn explicit_asset(&self) -> Result<AssetId>;

    /// Validates that this UTXO can cover the required amount.
    ///
    /// Returns the change amount (available - required) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The value is confidential
    /// - The available amount is less than required
    fn validate_amount(&self, required: u64) -> Result<u64>;

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
    fn validate_fee(&self, required: u64, expected_asset: AssetId) -> Result<u64>;
}

impl TxOutExt for TxOut {
    fn explicit(&self) -> Result<(AssetId, u64)> {
        Ok((self.explicit_asset()?, self.explicit_value()?))
    }

    fn explicit_value(&self) -> Result<u64> {
        self.value
            .explicit()
            .ok_or_else(|| anyhow::anyhow!("UTXO has confidential value"))
    }

    fn explicit_asset(&self) -> Result<AssetId> {
        self.asset
            .explicit()
            .ok_or_else(|| anyhow::anyhow!("UTXO has confidential asset"))
    }

    fn validate_amount(&self, required: u64) -> Result<u64> {
        let available = self.explicit_value()?;

        ensure!(
            available >= required,
            "Insufficient funds: have {available}, need {required}"
        );

        Ok(available - required)
    }

    fn validate_fee(&self, required: u64, expected_asset: AssetId) -> Result<u64> {
        let asset = self.explicit_asset()?;

        ensure!(
            asset == expected_asset,
            "Fee UTXO has wrong asset: expected {expected_asset}, got {asset}"
        );

        self.validate_amount(required)
    }
}
