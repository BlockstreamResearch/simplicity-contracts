use crate::error::TransactionBuildError;
use crate::sdk::{DummySigner, SignerTrait};
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::pset::{Output, PartiallySignedTransaction};
use simplicityhl::elements::secp256k1_zkp::rand::thread_rng;
use simplicityhl::elements::{Script, Transaction};
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

    #[must_use]
    pub(crate) fn inp_tx_out_secrets(mut self, value: HashMap<usize, TxOutSecrets>) -> Self {
        self.inp_tx_out_sec = Some(value);
        self
    }

    #[must_use]
    pub const fn fee(mut self, amount: u64) -> Self {
        self.fee_amount = Some(amount);
        self
    }

    #[must_use]
    pub const fn fee_rate(mut self, fee_rate: f32) -> Self {
        self.fee_rate = Some(fee_rate);
        self
    }

    #[must_use]
    pub fn pset(&self) -> PartiallySignedTransaction {
        self.pset.clone()
    }

    /// Finalizes the partial PSET into a signed transaction via adding fees and running internal checks.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionBuildError`] if inputs are insufficient, fee rate is missing,
    ///     or signing/blinding/extraction fails.
    #[allow(clippy::too_many_lines)]
    pub fn finalize(
        mut self,
        network: SimplicityNetwork,
        signer: impl SignerTrait,
    ) -> Result<Transaction, TransactionBuildError> {
        let policy_asset = network.policy_asset();

        let policy_asset_in = self.pset.inputs().iter().fold(0, |acc, x| {
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
        let policy_asset_out = self.pset.outputs().iter().fold(0, |acc, x| {
            if let Some(asset) = x.asset
                && asset == policy_asset
                && let Some(amount) = x.amount
            {
                acc + amount
            } else {
                acc
            }
        });

        match self.fee_amount {
            None => {
                {
                    // TODO: add change if empty??

                    let temp_fee = PLACEHOLDER_FEE;
                    if policy_asset_in < (policy_asset_out + temp_fee) {
                        return Err(TransactionBuildError::InsufficientAssetAmount {
                            available: policy_asset_in,
                            has_to_be: policy_asset_out + temp_fee,
                            asset_id: policy_asset,
                        });
                    }

                    let policy_change_temp = policy_asset_in - policy_asset_out - temp_fee;

                    self.pset.add_output(Output::new_explicit(
                        self.change_recipient_script,
                        policy_change_temp,
                        policy_asset,
                        None,
                    ));

                    self.pset
                        .add_output(Output::from_txout(TxOut::new_fee(temp_fee, policy_asset)));
                }

                let fee_rate = self.fee_rate.ok_or(TransactionBuildError::FeeRateIsEmpty)?;

                let weight = {
                    let mut temp_pset = self.pset.clone();

                    if let Some(inp_tx_out_sec) = &self.inp_tx_out_sec {
                        temp_pset.blind_last(
                            &mut thread_rng(),
                            secp256k1::SECP256K1,
                            inp_tx_out_sec,
                        )?;
                    }

                    let tx = temp_pset.extract_tx()?;
                    let signed_tx =
                        DummySigner::get_signer_closure()(network, tx, &self.spent_tx_outs)
                            .map_err(TransactionBuildError::PsetDummySign)?;

                    signed_tx.discount_weight()
                };

                let fee = weight_to_sats_fee(weight, fee_rate);
                if policy_asset_in < (policy_asset_out + fee) {
                    return Err(TransactionBuildError::InsufficientAssetAmount {
                        available: policy_asset_in,
                        has_to_be: policy_asset_out + fee,
                        asset_id: policy_asset,
                    });
                }
                let policy_change = policy_asset_in - policy_asset_out - fee;

                // Replace change and fee outputs
                let n_outputs = self.pset.n_outputs();
                let outputs = self.pset.outputs_mut();
                let change_output = &mut outputs[n_outputs - 2];
                change_output.amount = Some(policy_change);
                let fee_output = &mut outputs[n_outputs - 1];
                fee_output.amount = Some(fee);
            }
            Some(fee) => {
                if policy_asset_in < (policy_asset_out + fee) {
                    return Err(TransactionBuildError::InsufficientAssetAmount {
                        available: policy_asset_in,
                        has_to_be: policy_asset_out + fee,
                        asset_id: policy_asset,
                    });
                }

                // TODO: add change if empty?

                let total_lbtc_left = policy_asset_in - policy_asset_out - fee;
                self.pset.add_output(Output::new_explicit(
                    self.change_recipient_script,
                    total_lbtc_left,
                    policy_asset,
                    None,
                ));

                self.pset
                    .add_output(Output::from_txout(TxOut::new_fee(fee, policy_asset)));
            }
        }

        if let Some(inp_tx_out_sec) = &self.inp_tx_out_sec {
            self.pset
                .blind_last(&mut thread_rng(), secp256k1::SECP256K1, inp_tx_out_sec)?;
        }

        self.pset
            .extract_tx()?
            .verify_tx_amt_proofs(secp256k1::SECP256K1, &self.spent_tx_outs)?;

        let tx = self.pset.extract_tx()?;
        let tx =
            signer(network, tx, &self.spent_tx_outs).map_err(TransactionBuildError::PsetSign)?;

        Ok(tx)
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
