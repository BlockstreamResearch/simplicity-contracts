//! Runtime transaction builder/finalizer.
//!
//! High-level flow:
//! 1. Build a fee-targeted PSET (`resolve_inputs` + `balance_out`).
//! 2. Estimate required fee from a finalized+blinded estimation transaction.
//! 3. Iterate fee target to fixed-point convergence (bounded).
//! 4. Build final PSET with converged fee, blind, finalize, and verify proofs.
//!
//! Fee convergence:
//! - initial target: `1 sat`
//! - max iterations: `MAX_FEE_ITERS`
//! - cycle handling: if oscillation is detected, escalate once to max cycle value
//! - failure mode: deterministic `Funding` error when convergence is not reached
//!
//! Formal references:
//! - Bitcoin Core coin selection context:
//!   <https://github.com/bitcoin/bitcoin/blob/master/src/wallet/coinselection.cpp>
//! - Murch, *An Evaluation of Coin Selection Strategies*:
//!   <http://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf>
//!
pub mod utils;

mod input_resolution;
mod output_resolution;

use crate::error::WalletAbiError;
use crate::schema::tx_create::{TransactionInfo, TxCreateRequest, TxCreateResponse};
use crate::{FinalizerSpec, InputSchema, LockFilter, RuntimeParams, UTXOSource};
use std::collections::HashMap;

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::runtime::utils::to_lwk_wollet_network;
use crate::schema::values::{resolve_arguments, resolve_witness};
use lwk_common::{Bip, Network, Signer};
use lwk_signer::SwSigner;
use lwk_signer::bip39::rand::thread_rng;
use lwk_simplicity::runner::run_program;
use lwk_simplicity::scripts::{control_block, load_program};
use lwk_simplicity::signer::get_and_verify_env;
use lwk_wollet::asyncr::EsploraClient;
use lwk_wollet::bitcoin::bip32::{DerivationPath, Xpriv};
use lwk_wollet::elements::hex::ToHex;
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements::pset::raw::ProprietaryKey;
use lwk_wollet::elements::{Address, BlockHash, OutPoint, Script, TxOut, TxOutSecrets};
use lwk_wollet::elements_miniscript::ToPublicKey;
use lwk_wollet::elements_miniscript::psbt::PsbtExt;
use lwk_wollet::hashes::Hash;
use lwk_wollet::secp256k1::{Keypair, XOnlyPublicKey};
use lwk_wollet::{EC, Wollet, WolletDescriptor};
use simplicityhl::elements::{Transaction, encode};
use simplicityhl::tracker::TrackerLogLevel;
use tokio::sync::Mutex;

/// Maximum number of fee fixed-point iterations before failing.
const MAX_FEE_ITERS: usize = 8;

pub(crate) fn get_finalizer_spec_key() -> ProprietaryKey {
    ProprietaryKey::from_pset_pair(1, b"finalizer-spec".to_vec())
}

pub(crate) fn get_secrets_spec_key() -> ProprietaryKey {
    ProprietaryKey::from_pset_pair(1, b"secrets-spec".to_vec())
}

pub const DEFAULT_FEE_RATE_SAT_VB: f32 = 0.1;

#[derive(Debug)]
pub struct WalletRuntimeConfig {
    pub signer: SwSigner,
    pub network: Network,
    pub esplora: Arc<Mutex<EsploraClient>>,
    pub wollet: Wollet,
}

impl WalletRuntimeConfig {
    pub fn build_random(
        network: Network,
        esplora_url: &str,
        wallet_data_dir: impl AsRef<Path>,
    ) -> Result<Self, WalletAbiError> {
        let (signer, _) = SwSigner::random(network.is_mainnet())?;

        Self::from_signer(signer, network, esplora_url, wallet_data_dir)
    }

    pub fn from_mnemonic(
        mnemonic: &str,
        network: Network,
        esplora_url: &str,
        wallet_data_dir: impl AsRef<Path>,
    ) -> Result<Self, WalletAbiError> {
        let signer = SwSigner::new(mnemonic, network.is_mainnet())?;

        Self::from_signer(signer, network, esplora_url, wallet_data_dir)
    }

    fn x_private(&self, bip: Bip) -> Result<Xpriv, WalletAbiError> {
        let x_private = self.signer.derive_xprv(&self.get_derivation_path(bip))?;

        Ok(x_private)
    }

    pub(crate) fn get_derivation_path(&self, bip: Bip) -> DerivationPath {
        let coin_type = if self.network.is_mainnet() { 1776 } else { 1 };
        let path = match bip {
            Bip::Bip84 => format!("84h/{coin_type}h/0h"),
            Bip::Bip49 => format!("49h/{coin_type}h/0h"),
            Bip::Bip87 => format!("87h/{coin_type}h/0h"),
        };

        DerivationPath::from_str(&format!("m/{path}")).expect("static")
    }

    pub fn from_signer(
        signer: SwSigner,
        network: Network,
        esplora_url: &str,
        wallet_data_dir: impl AsRef<Path>,
    ) -> Result<Self, WalletAbiError> {
        let descriptor = WolletDescriptor::from_str(
            &signer
                .wpkh_slip77_descriptor()
                .map_err(WalletAbiError::InvalidSignerConfig)?,
        )?;

        let lwk_wollet_network = to_lwk_wollet_network(network);

        let esplora = Arc::new(Mutex::new(EsploraClient::new(
            lwk_wollet_network,
            esplora_url,
        )));
        let wollet = Wollet::with_fs_persist(lwk_wollet_network, descriptor, wallet_data_dir)?;

        Ok(Self {
            signer,
            network,
            esplora,
            wollet,
        })
    }

    pub fn get_descriptor(&self) -> Result<WolletDescriptor, WalletAbiError> {
        Ok(WolletDescriptor::from_str(
            &self
                .signer
                .wpkh_slip77_descriptor()
                .map_err(WalletAbiError::InvalidSignerConfig)?,
        )?)
    }

    pub fn signer_x_only_public_key(&self) -> Result<XOnlyPublicKey, WalletAbiError> {
        Ok(self.signer_keypair()?.x_only_public_key().0)
    }

    pub fn signer_receive_address(&self) -> Result<Address, WalletAbiError> {
        let descriptor = self.get_descriptor()?;

        Ok(descriptor.address(0, self.network.address_params())?)
    }

    pub(crate) fn signer_keypair(&self) -> Result<Keypair, WalletAbiError> {
        Ok(self.x_private(Bip::Bip87)?.to_keypair(&EC))
    }

    pub async fn sync_wallet(&mut self) -> Result<(), WalletAbiError> {
        self.sync_descriptor(self.get_descriptor()?).await
    }

    /// TODO: (this is broken for now) Request a full scan using a script descriptor.
    pub async fn sync_script_wollet(
        &mut self,
        script_pubkey: &Script,
    ) -> Result<(), WalletAbiError> {
        let spk_descriptor = format!(":{}", script_pubkey.to_hex());

        self.sync_descriptor(WolletDescriptor::from_str(&spk_descriptor)?)
            .await
    }

    /// TODO: (this is broken for now) Request a full scan while validating an arbitrary descriptor shape.
    pub async fn sync_descriptor(
        &mut self,
        wollet_descriptor: WolletDescriptor,
    ) -> Result<(), WalletAbiError> {
        // TODO: fix.
        // The descriptor is validated by constructing a temporary wollet, while the full scan is
        // currently executed against the runtime's persisted primary wallet.
        let _wollet =
            Wollet::without_persist(to_lwk_wollet_network(self.network), wollet_descriptor)?;

        if let Some(update) = {
            let mut inner_esplora = self.esplora.lock().await;
            inner_esplora.full_scan(&self.wollet).await?
        } {
            self.wollet.apply_update(update)?;
        }

        Ok(())
    }

    pub async fn fetch_tx_out(&self, outpoint: &OutPoint) -> Result<TxOut, WalletAbiError> {
        let tx = {
            let inner_esplora = self.esplora.lock().await;
            inner_esplora.get_transaction(outpoint.txid).await?
        };
        let tx_out = tx.output.get(outpoint.vout as usize).ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "prevout transaction {} missing vout {}",
                outpoint.txid, outpoint.vout
            ))
        })?;

        Ok(tx_out.clone())
    }

    pub async fn process_request(
        &mut self,
        request: &TxCreateRequest,
    ) -> Result<TxCreateResponse, WalletAbiError> {
        request.validate_for_runtime(self.network)?;

        let fee_rate_sat_vb = validate_fee_rate_sat_vb(
            request
                .params
                .fee_rate_sat_vb
                .unwrap_or(DEFAULT_FEE_RATE_SAT_VB),
        )?;

        self.sync_wallet().await?;
        self.pre_sync_inputs(&request.params.inputs).await?;

        let finalized_tx = self.finalize(&request.params, fee_rate_sat_vb).await?;

        let txid = finalized_tx.txid();

        if request.broadcast {
            let published_txid = {
                let inner_esplora = self.esplora.lock().await;
                inner_esplora.broadcast(&finalized_tx).await?
            };
            if txid != published_txid {
                return Err(WalletAbiError::InvalidResponse(format!(
                    "broadcast txid mismatch: locally built txid={txid}, esplora returned txid={published_txid}"
                )));
            }
        }

        let response = TxCreateResponse::ok(
            request,
            TransactionInfo {
                tx_hex: encode::serialize_hex(&finalized_tx),
                txid,
            },
            None,
        );

        Ok(response)
    }

    /// Build, blind and finalize a transaction with bounded fee fixed-point convergence.
    ///
    /// The output stage models fee as explicit policy-asset demand, so this method iterates
    /// `fee_target_sat` until the estimated fee matches the target.
    ///
    /// Failure conditions:
    /// - convergence not reached within `MAX_FEE_ITERS`
    /// - any intermediate funding deficit raised by resolvers
    async fn finalize(
        &self,
        params: &RuntimeParams,
        fee_rate: f32,
    ) -> Result<Transaction, WalletAbiError> {
        // Bounded fixed-point fee convergence:
        // fee_target -> build tx -> estimate fee -> repeat until stable or cap reached.
        let mut fee_target_sat = 1u64;
        let mut seen_targets = Vec::new();
        let mut escalated_cycle_once = false;
        let mut converged_fee_target = None;

        for _ in 0..MAX_FEE_ITERS {
            let estimated_fee_sat = self
                .estimate_fee_target(params, fee_target_sat, fee_rate)
                .await?;

            if estimated_fee_sat == fee_target_sat {
                converged_fee_target = Some(estimated_fee_sat);
                break;
            }

            if let Some(cycle_start) = seen_targets
                .iter()
                .position(|previous| *previous == estimated_fee_sat)
            {
                let cycle_max = seen_targets[cycle_start..]
                    .iter()
                    .copied()
                    .chain(std::iter::once(estimated_fee_sat))
                    .max()
                    .unwrap_or(estimated_fee_sat);
                if !escalated_cycle_once {
                    escalated_cycle_once = true;
                    seen_targets.push(fee_target_sat);
                    fee_target_sat = cycle_max;
                    continue;
                }
            }

            seen_targets.push(fee_target_sat);
            fee_target_sat = estimated_fee_sat;
        }

        let converged_fee_target = converged_fee_target.ok_or_else(|| {
            WalletAbiError::Funding(format!(
                "fee convergence failed after {MAX_FEE_ITERS} iterations; last target={} sat, visited=[{}]",
                fee_target_sat,
                seen_targets
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ))
        })?;

        let mut pst = self.build_transaction(params, converged_fee_target).await?;
        let inp_txout_secrets = Self::input_blinding_secrets(&pst)?;
        pst.blind_last(&mut thread_rng(), &EC, &inp_txout_secrets)?;
        let pst = self.finalize_all_inputs(pst)?;

        let utxos: Vec<TxOut> = pst
            .inputs()
            .iter()
            .filter_map(|x| x.witness_utxo.clone())
            .collect();

        let tx = pst.extract_tx()?;

        tx.verify_tx_amt_proofs(&EC, &utxos)?;

        Ok(tx)
    }

    /// Collect input secrets used by blinding and surjection-proof domain construction.
    fn input_blinding_secrets(
        pst: &PartiallySignedTransaction,
    ) -> Result<HashMap<usize, TxOutSecrets>, WalletAbiError> {
        let mut inp_txout_secrets: HashMap<usize, TxOutSecrets> = HashMap::new();
        for (input_index, input) in pst.inputs().iter().enumerate() {
            let encoded_secrets =
                input
                    .proprietary
                    .get(&get_secrets_spec_key())
                    .ok_or_else(|| {
                        WalletAbiError::InvalidRequest(format!(
                            "missing input blinding secrets metadata for input index {input_index}"
                        ))
                    })?;
            let secrets: TxOutSecrets = serde_json::from_slice(encoded_secrets)?;
            inp_txout_secrets.insert(input_index, secrets);
        }

        Ok(inp_txout_secrets)
    }

    fn input_finalizer_spec(
        pst: &PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<FinalizerSpec, WalletAbiError> {
        let finalizer_payload = pst
            .inputs()
            .get(input_index)
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(format!(
                    "missing input index {input_index} while finalizing transaction"
                ))
            })?
            .proprietary
            .get(&get_finalizer_spec_key())
            .ok_or_else(|| {
                WalletAbiError::InvalidRequest(format!(
                    "missing finalizer metadata for input index {input_index}"
                ))
            })?;

        FinalizerSpec::decode(finalizer_payload)
    }

    /// Estimate required fee for a candidate fee target using a finalized+blinded estimation tx.
    ///
    /// This is used inside the bounded fixed-point loop in `finalize`.
    async fn estimate_fee_target(
        &self,
        params: &RuntimeParams,
        fee_target_sat: u64,
        fee_rate: f32,
    ) -> Result<u64, WalletAbiError> {
        let fee_estimation_build = self.build_transaction(params, fee_target_sat).await?;
        let mut pst = self.finalize_all_inputs(fee_estimation_build)?;
        let inp_txout_secrets = Self::input_blinding_secrets(&pst)?;
        pst.blind_last(&mut thread_rng(), &EC, &inp_txout_secrets)?;

        Ok(calculate_fee(pst.extract_tx()?.discount_weight(), fee_rate))
    }

    fn unblind_with_wallet(&self, tx_out: TxOut) -> Result<(TxOut, TxOutSecrets), WalletAbiError> {
        let blinding_private_key = self
            .signer
            .slip77_master_blinding_key()?
            .blinding_private_key(&tx_out.script_pubkey);

        let secrets = tx_out.unblind(&EC, blinding_private_key)?;

        Ok((tx_out, secrets))
    }

    /// Build a fee-targeted PSET by running fee-aware input and output resolvers.
    async fn build_transaction(
        &self,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime = params.locktime;

        // Input resolution is fee-aware and receives the current fee target.
        pst = self.resolve_inputs(pst, params, fee_target_sat).await?;

        pst = self.balance_out(pst, params, fee_target_sat)?;

        Ok(pst)
    }

    pub fn finalize_all_inputs(
        &self,
        mut pst: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        let utxos: Vec<TxOut> = pst
            .inputs()
            .iter()
            .filter_map(|x| x.witness_utxo.clone())
            .collect();

        self.signer.sign(&mut pst)?;

        for input_index in 0..pst.inputs().len() {
            let finalizer = Self::input_finalizer_spec(&pst, input_index)?;

            match finalizer {
                FinalizerSpec::Wallet => {
                    pst.finalize_inp_mut(&EC, input_index, BlockHash::all_zeros())
                        .map_err(|error| {
                            WalletAbiError::InvalidFinalizationSteps(format!(
                                "wallet finalization failed for input index {input_index}: {error}"
                            ))
                        })?;
                }
                FinalizerSpec::Simf {
                    source_simf,
                    internal_key,
                    arguments,
                    witness,
                } => {
                    let arguments = resolve_arguments(&arguments, &pst)?;

                    let program = load_program(&source_simf, arguments)?;

                    let env = get_and_verify_env(
                        &pst.extract_tx()?,
                        &program,
                        &internal_key.pubkey.to_x_only_pubkey(),
                        &utxos,
                        self.network,
                        input_index,
                    )?;

                    let witness = resolve_witness(&witness, self, &env)?;

                    let pruned = run_program(&program, witness, &env, TrackerLogLevel::None)?.0;

                    let (simplicity_program_bytes, simplicity_witness_bytes) =
                        pruned.to_vec_with_witness();
                    let cmr = pruned.cmr();

                    pst.inputs_mut()[input_index].final_script_witness = Some(vec![
                        simplicity_witness_bytes,
                        simplicity_program_bytes,
                        cmr.as_ref().to_vec(),
                        control_block(cmr, internal_key.pubkey.to_x_only_pubkey()).serialize(),
                    ]);
                }
            }
        }

        Ok(pst)
    }

    /// Pre-sync script-locked wallet filters before input resolution.
    ///
    /// Current behavior note:
    /// this only triggers sync calls; input resolution still reads UTXOs from
    /// `self.wollet.utxos()` and does not switch the resolver snapshot source.
    async fn pre_sync_inputs(&mut self, inputs: &[InputSchema]) -> Result<(), WalletAbiError> {
        for i in inputs {
            match &i.utxo_source {
                UTXOSource::Wallet { filter } => match &filter.lock {
                    LockFilter::None => {}
                    LockFilter::Script { script } => {
                        self.sync_script_wollet(script).await?;
                    }
                },
                UTXOSource::Provided { .. } => {}
            }
        }

        Ok(())
    }
}

fn validate_fee_rate_sat_vb(fee_rate_sat_vb: f32) -> Result<f32, WalletAbiError> {
    if !fee_rate_sat_vb.is_finite() || fee_rate_sat_vb < 0.0 {
        return Err(WalletAbiError::InvalidRequest(format!(
            "fee_rate_sat_vb must be a finite non-negative value in sat/vB, got {fee_rate_sat_vb}"
        )));
    }

    Ok(fee_rate_sat_vb)
}

/// Calculate fee from weight and fee rate (sat/vB).
///
/// Formula: `fee = ceil(vsize * fee_rate_sat_vb)`
/// where `vsize = ceil(weight / 4)`
///
/// # Arguments
///
/// * `weight` - Transaction weight in weight units (WU)
/// * `fee_rate` - Fee rate in satoshis per virtual byte (sat/vB)
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
pub fn calculate_fee(weight: usize, fee_rate: f32) -> u64 {
    let vsize = weight.div_ceil(4);
    (vsize as f32 * fee_rate).ceil() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use lwk_wollet::elements::hashes::Hash;
    use lwk_wollet::elements::pset::Input;
    use lwk_wollet::elements::{OutPoint, Txid};

    fn test_outpoint(tag: u8, vout: u32) -> OutPoint {
        OutPoint::new(
            Txid::from_slice(&[tag; 32]).expect("txid from fixed bytes"),
            vout,
        )
    }

    #[test]
    fn calculate_fee_rounds_vsize_and_fee_up() {
        assert_eq!(calculate_fee(4, 1.0), 1);
        assert_eq!(calculate_fee(5, 1.0), 2);
        assert_eq!(calculate_fee(8, 1.5), 3);
    }

    #[test]
    fn calculate_fee_allows_zero_fee_rate() {
        assert_eq!(calculate_fee(123, 0.0), 0);
    }

    #[test]
    fn validate_fee_rate_rejects_negative_and_non_finite_values() {
        for invalid in [-0.01, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let err = validate_fee_rate_sat_vb(invalid).expect_err("invalid fee rate must fail");
            match err {
                WalletAbiError::InvalidRequest(message) => {
                    assert!(message.contains("fee_rate_sat_vb"));
                }
                other => panic!("unexpected error variant: {other}"),
            }
        }
    }

    #[test]
    fn input_blinding_secrets_missing_metadata_returns_error() {
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(test_outpoint(1, 0)));

        let err =
            WalletRuntimeConfig::input_blinding_secrets(&pst).expect_err("missing secrets key");
        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("missing input blinding secrets metadata"));
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn input_finalizer_spec_missing_metadata_returns_error() {
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(test_outpoint(2, 0)));

        let err = WalletRuntimeConfig::input_finalizer_spec(&pst, 0)
            .expect_err("missing finalizer key should fail");
        match err {
            WalletAbiError::InvalidRequest(message) => {
                assert!(message.contains("missing finalizer metadata"));
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }
}
