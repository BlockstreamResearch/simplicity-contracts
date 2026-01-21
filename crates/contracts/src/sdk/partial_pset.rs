use crate::error::TransactionBuildError;
use crate::sdk::{SignerOnceTrait, SignerTrait};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{AssetId, Script, Transaction};
use simplicityhl::elements::{TxOut, TxOutSecrets};
use simplicityhl_core::SimplicityNetwork;
use std::collections::HashMap;

/// Witness scale factor for weight-to-vsize conversion.
/// In segwit, weight = 4 * `base_size` + `witness_size`, so vsize = weight / 4.
pub const WITNESS_SCALE_FACTOR: usize = 4;

/// Placeholder fee for first-pass weight measurement (1 satoshi).
/// Used when building a transaction to measure its actual weight before
/// calculating the real fee.
pub const PLACEHOLDER_FEE: u64 = 1;

#[derive(Debug, Clone, Copy)]
struct PolicyAssetInfo {
    input: u64,
    output: u64,
    policy_asset: AssetId,
}

#[derive(Debug, Clone)]
pub struct PartialPset {
    pset: PartiallySignedTransaction,
    change_recipient_script: Script,
    inp_tx_out_sec: Option<HashMap<usize, TxOutSecrets>>,
    fee_amount: Option<u64>,
    spent_tx_outs: Vec<TxOut>,
    fee_rate: Option<f32>,
}

impl PartialPset {
    #[must_use]
    pub const fn new(
        pset: PartiallySignedTransaction,
        change_recipient_script: Script,
        spent_tx_out: Vec<TxOut>,
    ) -> Self {
        Self {
            pset,
            change_recipient_script,
            inp_tx_out_sec: None,
            fee_amount: None,
            spent_tx_outs: spent_tx_out,
            fee_rate: None,
        }
    }

    /// Sets input transaction output secrets for blinding purposes.
    ///
    /// # Arguments
    ///
    /// * `value` - A map of input indices to their corresponding `TxOutSecrets`
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn inp_tx_out_secrets(mut self, value: HashMap<usize, TxOutSecrets>) -> Self {
        self.inp_tx_out_sec = Some(value);
        self
    }

    /// Sets a fixed fee amount for the transaction.
    ///
    /// # Arguments
    ///
    /// * `amount` - The fee amount in satoshis
    #[must_use]
    pub const fn fee(mut self, amount: u64) -> Self {
        self.fee_amount = Some(amount);
        self
    }

    /// Removes the currently set fee amount.
    #[must_use]
    pub const fn remove_fee(mut self) -> Self {
        self.fee_amount = None;
        self
    }

    /// Sets the fee rate for automatic fee calculation.
    ///
    /// # Arguments
    ///
    /// * `fee_rate` - Fee rate in satoshis per 1000 virtual bytes (sats/kvb)
    #[must_use]
    pub const fn fee_rate(mut self, fee_rate: f32) -> Self {
        self.fee_rate = Some(fee_rate);
        self
    }

    /// Removes the currently set fee rate.
    #[must_use]
    pub const fn remove_fee_rate(mut self) -> Self {
        self.fee_rate = None;
        self
    }

    /// Returns a copy of the internal partially signed transaction.
    #[must_use]
    pub fn pset(&self) -> PartiallySignedTransaction {
        self.pset.clone()
    }

    /// Returns a copy of the change recipient script.
    #[must_use]
    pub fn change_recipient_script(&self) -> Script {
        self.change_recipient_script.clone()
    }

    /// Returns a reference to the list of spent transaction outputs.
    #[must_use]
    pub fn get_spent_tx_outs(&self) -> &[TxOut] {
        &self.spent_tx_outs
    }

    /// Returns a reference to the input transaction output secrets.
    #[must_use]
    pub fn get_inp_tx_out_sec(&self) -> &Option<HashMap<usize, TxOutSecrets>> {
        &self.inp_tx_out_sec
    }

    /// Returns the currently set fee amount.
    #[must_use]
    pub fn get_fee(&self) -> Option<u64> {
        self.fee_amount
    }

    /// Returns the currently set fee rate.
    #[must_use]
    pub fn get_fee_rate(&self) -> Option<f32> {
        self.fee_rate
    }

    /// Calculates policy asset input and output amounts from the PSET.
    /// Policy asset is derived from input.
    #[must_use]
    fn calculate_policy_asset_info(&self, network: SimplicityNetwork) -> PolicyAssetInfo {
        let policy_asset = network.policy_asset();

        let input = self.pset.inputs().iter().fold(0, |acc, x| {
            if let Some(witness_utxo) = &x.witness_utxo
                && let Some(witness_asset) = witness_utxo.asset.explicit()
                && witness_asset == policy_asset
                && let Some(amount) = witness_utxo.value.explicit()
            {
                acc + amount
            } else {
                acc
            }
        });
        let output = self.pset.outputs().iter().fold(0, |acc, x| {
            if let Some(asset) = x.asset
                && asset == policy_asset
                && let Some(amount) = x.amount
            {
                acc + amount
            } else {
                acc
            }
        });

        PolicyAssetInfo {
            input,
            output,
            policy_asset,
        }
    }

    /// Creates a draft (blinded but unsigned) transaction for weight estimation or blinding factor extraction.
    ///
    /// This method creates a copy of the PSET, blinds it if secrets are available,
    /// and extracts the transaction. Useful for:
    /// - Extracting blinding factors before finalization
    /// - Weight estimation for fee calculation
    ///
    /// # Arguments
    ///
    /// * `network` - The Simplicity network to use for deriving the policy asset
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if blinding or transaction extraction fails.
    pub fn create_draft_pset(
        &self,
        network: SimplicityNetwork,
    ) -> Result<PartiallySignedTransaction, TransactionBuildError> {
        let temp_pset = self.pset.clone();
        let policy_asset_info = self.calculate_policy_asset_info(network);

        Self::insert_fees_raw(
            temp_pset,
            self.change_recipient_script.clone(),
            policy_asset_info,
            PLACEHOLDER_FEE,
        )
    }

    /// Creates a PSET with fees inserted and outputs balanced.
    ///
    /// # Arguments
    ///
    /// * `fee` - The fee amount in satoshis to deduct from inputs
    /// * `network` - The Simplicity network to use for deriving the policy asset
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if fee insertion or asset calculation fails.
    pub fn create_pset(
        &self,
        fee: u64,
        network: SimplicityNetwork,
    ) -> Result<PartiallySignedTransaction, TransactionBuildError> {
        let temp_pset = self.pset.clone();
        let policy_asset_info = self.calculate_policy_asset_info(network);

        Self::insert_fees_raw(
            temp_pset,
            self.change_recipient_script.clone(),
            policy_asset_info,
            fee,
        )
    }

    /// Finalizes the partial PSET into a signed transaction via adding fees and running internal checks.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if inputs are insufficient, fee rate is missing,
    ///     or signing/blinding/extraction fails.
    #[allow(clippy::too_many_lines)]
    pub fn finalize(
        self,
        network: SimplicityNetwork,
        signer: impl SignerTrait,
    ) -> Result<Transaction, TransactionBuildError> {
        let policy_asset_info = self.calculate_policy_asset_info(network);
        let fee = match self.fee_amount {
            None => {
                let temp_pset = self.pset.clone();
                let temp_pset_with_fees = Self::insert_fees_raw(
                    temp_pset,
                    self.change_recipient_script.clone(),
                    policy_asset_info,
                    PLACEHOLDER_FEE,
                )?;

                let fee_rate = self.fee_rate.ok_or(TransactionBuildError::FeeRateIsEmpty)?;
                let temp_finalized_pset = Self::finalize_pset_raw(
                    temp_pset_with_fees,
                    &self.inp_tx_out_sec,
                    &self.spent_tx_outs,
                )?;
                let temp_tx = temp_finalized_pset.extract_tx()?;
                let temp_signed_tx =
                    Self::sign_tx_raw(temp_tx, &self.spent_tx_outs, network, signer.clone())?;
                Self::calculate_fee_raw(&temp_signed_tx, fee_rate)?
            }
            Some(fee) => fee,
        };

        let pset_with_fees = Self::insert_fees_raw(
            self.pset,
            self.change_recipient_script,
            policy_asset_info,
            fee,
        )?;
        let finalized_pset =
            Self::finalize_pset_raw(pset_with_fees, &self.inp_tx_out_sec, &self.spent_tx_outs)?;
        let tx = finalized_pset.extract_tx()?;
        let signed_tx = Self::sign_tx_raw(tx, &self.spent_tx_outs, network, signer)?;

        Ok(signed_tx)
    }

    /// Inserts fees and change outputs into a PSET, balancing the policy asset.
    ///
    /// # Arguments
    ///
    /// * `pset` - The partially signed transaction to modify
    /// * `change_recipient_script` - The script for receiving change
    /// * `policy_asset_info` - Information about policy asset inputs and outputs
    /// * `fee` - The fee amount to deduct
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError::InsufficientAssetAmount`] if inputs are insufficient to cover outputs and fees.
    fn insert_fees_raw(
        mut pset: PartiallySignedTransaction,
        change_recipient_script: Script,
        policy_asset_info: PolicyAssetInfo,
        fee: u64,
    ) -> Result<PartiallySignedTransaction, TransactionBuildError> {
        let PolicyAssetInfo {
            input: policy_asset_in,
            output: policy_asset_out,
            policy_asset,
        } = policy_asset_info;

        if policy_asset_in < (policy_asset_out + fee) {
            return Err(TransactionBuildError::InsufficientAssetAmount {
                available: policy_asset_in,
                has_to_be: policy_asset_out + fee,
                asset_id: policy_asset,
            });
        }

        let policy_change = policy_asset_in - policy_asset_out - fee;

        if policy_change != 0 {
            pset.add_output(Output::new_explicit(
                change_recipient_script,
                policy_change,
                policy_asset,
                None,
            ));
        }

        pset.add_output(Output::from_txout(TxOut::new_fee(fee, policy_asset)));

        Ok(pset)
    }

    /// Calculates the transaction fee from its weight and a given fee rate.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to calculate fee for
    /// * `fee_rate` - Fee rate in satoshis per 1000 virtual bytes (sats/kvb)
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if weight calculation fails.
    pub fn calculate_fee_raw(
        tx: &Transaction,
        fee_rate: f32,
    ) -> Result<u64, TransactionBuildError> {
        let weight = tx.discount_weight();
        let fee = weight_to_sats_fee(weight, fee_rate);
        Ok(fee)
    }

    /// Signs a transaction using the provided signer implementation.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign
    /// * `spent_tx_outs` - The outputs being spent by this transaction
    /// * `network` - The Simplicity network for signing context
    /// * `signer` - A one-time signer implementation
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if signing fails.
    pub fn sign_tx_raw(
        tx: Transaction,
        spent_tx_outs: &[TxOut],
        network: SimplicityNetwork,
        signer: impl SignerOnceTrait,
    ) -> Result<Transaction, TransactionBuildError> {
        let tx = signer(network, tx, spent_tx_outs).map_err(TransactionBuildError::PsetSign)?;
        Ok(tx)
    }

    /// Finalizes a PSET by blinding and verifying proof constraints.
    ///
    /// # Arguments
    ///
    /// * `pset` - The partially signed transaction to finalize
    /// * `inp_tx_out_sec` - Optional input secrets for blinding
    /// * `spent_tx_outs` - The outputs being spent by this transaction
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if blinding, extraction, or proof verification fails.
    pub fn finalize_pset_raw(
        mut pset: PartiallySignedTransaction,
        inp_tx_out_sec: &Option<HashMap<usize, TxOutSecrets>>,
        spent_tx_outs: &[TxOut],
    ) -> Result<PartiallySignedTransaction, TransactionBuildError> {
        if let Some(inp_tx_out_sec) = &inp_tx_out_sec {
            pset.blind_last(&mut thread_rng(), secp256k1::SECP256K1, inp_tx_out_sec)?;
        }

        pset.extract_tx()?
            .verify_tx_amt_proofs(secp256k1::SECP256K1, spent_tx_outs)?;
        Ok(pset)
    }
}

/// Calculate fee from weight and fee rate (sats/kvb).
///
/// Formula: `fee = ceil(vsize * fee_rate / 1000)`
/// where `vsize = ceil(weight / 4)`
///
/// # Arguments
///
/// * `weight` - Transaction weight in weight units (WU)
/// * `fee_rate` - Fee rate in satoshis per 1000 virtual bytes (sats/kvb)
///
/// # Returns
///
/// The calculated fee in satoshis.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn weight_to_sats_fee(weight: usize, fee_rate: f32) -> u64 {
    let vsize = weight.div_ceil(WITNESS_SCALE_FACTOR);
    (vsize as f32 * fee_rate / 1000.0).ceil() as u64
}
