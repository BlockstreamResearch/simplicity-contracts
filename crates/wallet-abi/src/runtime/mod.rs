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
use std::sync::{Arc, Mutex};

use crate::runtime::utils::to_lwk_wollet_network;
use crate::schema::values::{resolve_arguments, resolve_witness};
use lwk_common::{Bip, Network, Signer};
use lwk_signer::SwSigner;
use lwk_signer::bip39::rand::thread_rng;
use lwk_simplicity::runner::run_program;
use lwk_simplicity::scripts::{control_block, load_program};
use lwk_simplicity::signer::get_and_verify_env;
use lwk_wollet::bitcoin::bip32::{DerivationPath, Xpriv};
use lwk_wollet::blocking::BlockchainBackend;
use lwk_wollet::blocking::EsploraClient;
use lwk_wollet::elements::hex::ToHex;
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements::pset::raw::ProprietaryKey;
use lwk_wollet::elements::secp256k1_zkp::ZERO_TWEAK;
use lwk_wollet::elements::{Address, BlockHash, OutPoint, Script, TxOut, TxOutSecrets};
use lwk_wollet::elements_miniscript::ToPublicKey;
use lwk_wollet::elements_miniscript::psbt::PsbtExt;
use lwk_wollet::hashes::Hash;
use lwk_wollet::secp256k1::{Keypair, XOnlyPublicKey};
use lwk_wollet::{EC, Wollet, WolletDescriptor};
use simplicityhl::elements::{Transaction, encode};
use simplicityhl::tracker::TrackerLogLevel;

/// Maximum number of fee fixed-point iterations before failing.
const MAX_FEE_ITERS: usize = 8;

pub(crate) fn get_finalizer_spec_key() -> ProprietaryKey {
    ProprietaryKey::from_pset_pair(1, b"finalizer-spec".to_vec())
}

pub(crate) fn get_secrets_spec_key() -> ProprietaryKey {
    ProprietaryKey::from_pset_pair(1, b"secrets-spec".to_vec())
}

#[derive(Debug)]
pub struct WalletRuntimeConfig {
    pub signer: SwSigner,
    pub network: Network,
    pub esplora: Arc<Mutex<EsploraClient>>,
    pub wollet: Wollet,
    pub default_fee_rate_sat_vb: f32,
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
            esplora_url,
            lwk_wollet_network,
        )?));
        let wollet = Wollet::with_fs_persist(lwk_wollet_network, descriptor, wallet_data_dir)?;

        Ok(Self {
            signer,
            network,
            esplora,
            wollet,
            default_fee_rate_sat_vb: 1.5,
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

    pub fn sync_wallet(&mut self) -> Result<(), WalletAbiError> {
        self.sync_descriptor(self.get_descriptor()?)
    }

    pub fn sync_script_wollet(&mut self, script_pubkey: &Script) -> Result<(), WalletAbiError> {
        let spk_descriptor = format!(":{}", script_pubkey.to_hex());

        self.sync_descriptor(WolletDescriptor::from_str(&spk_descriptor)?)
    }

    pub fn sync_descriptor(
        &mut self,
        wollet_descriptor: WolletDescriptor,
    ) -> Result<(), WalletAbiError> {
        // TODO: fix this
        let _wollet =
            Wollet::without_persist(to_lwk_wollet_network(self.network), wollet_descriptor)?;

        if let Some(update) = {
            let mut inner_esplora = self
                .esplora
                .lock()
                .map_err(|e| WalletAbiError::EsploraPoisoned(e.to_string()))?;
            inner_esplora.full_scan(&self.wollet)?
        } {
            self.wollet.apply_update(update)?;
        }

        Ok(())
    }

    pub fn fetch_tx_out(&self, outpoint: &OutPoint) -> Result<TxOut, WalletAbiError> {
        let tx = {
            let inner_esplora = self
                .esplora
                .lock()
                .map_err(|e| WalletAbiError::EsploraPoisoned(e.to_string()))?;
            inner_esplora.get_transaction(outpoint.txid)?
        };
        let tx_out = tx.output.get(outpoint.vout as usize).ok_or_else(|| {
            WalletAbiError::InvalidRequest(format!(
                "prevout transaction {} missing vout {}",
                outpoint.txid, outpoint.vout
            ))
        })?;

        Ok(tx_out.clone())
    }

    pub fn process_request(
        &mut self,
        request: &TxCreateRequest,
    ) -> Result<TxCreateResponse, WalletAbiError> {
        self.ensure_defaults()?;

        self.sync_wallet()?;
        self.pre_sync_inputs(&request.params.inputs)?;

        let finalized_tx = self.finalize(&request.params)?;

        let txid = finalized_tx.txid();

        if request.broadcast {
            let published_txid = self
                .esplora
                .lock()
                .map_err(|e| WalletAbiError::EsploraPoisoned(e.to_string()))?
                .broadcast(&finalized_tx)?;
            assert_eq!(txid, published_txid);
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
    fn finalize(&self, params: &RuntimeParams) -> Result<Transaction, WalletAbiError> {
        // Bounded fixed-point fee convergence:
        // fee_target -> build tx -> estimate fee -> repeat until stable or cap reached.
        let mut fee_target_sat = 1u64;
        let mut seen_targets = Vec::new();
        let mut escalated_cycle_once = false;
        let mut converged_fee_target = None;

        for _ in 0..MAX_FEE_ITERS {
            let estimated_fee_sat = self.estimate_fee_target(params, fee_target_sat)?;
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

        let mut pst = self.build_transaction(params, converged_fee_target)?;
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

    /// Collect non-explicit input secrets to be used as blinding inputs.
    fn input_blinding_secrets(
        pst: &PartiallySignedTransaction,
    ) -> Result<HashMap<usize, TxOutSecrets>, WalletAbiError> {
        let mut inp_txout_secrets: HashMap<usize, TxOutSecrets> = HashMap::new();
        for (input_index, input) in pst.inputs().iter().enumerate() {
            let secrets: TxOutSecrets = serde_json::from_slice(
                input
                    .proprietary
                    .get(&get_secrets_spec_key())
                    .expect("handled by the inputs resolver"),
            )?;
            if secrets.asset_bf.into_inner() == ZERO_TWEAK {
                continue;
            }
            inp_txout_secrets.insert(input_index, secrets);
        }

        Ok(inp_txout_secrets)
    }

    /// Estimate required fee for a candidate fee target using a finalized+blinded estimation tx.
    ///
    /// This is used inside the bounded fixed-point loop in `finalize`.
    fn estimate_fee_target(
        &self,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<u64, WalletAbiError> {
        let fee_estimation_build = self.build_transaction(params, fee_target_sat)?;
        let mut pst = self.finalize_all_inputs(fee_estimation_build)?;
        let inp_txout_secrets = Self::input_blinding_secrets(&pst)?;
        pst.blind_last(&mut thread_rng(), &EC, &inp_txout_secrets)?;

        Ok(calculate_fee(
            pst.extract_tx()?.discount_weight(),
            self.default_fee_rate_sat_vb,
        ))
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
    fn build_transaction(
        &self,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime = params.locktime;

        // Input resolution is fee-aware and receives the current fee target.
        pst = self.resolve_inputs(pst, params, fee_target_sat)?;

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
            let finalizer: FinalizerSpec = FinalizerSpec::decode(
                pst.inputs()[input_index]
                    .proprietary
                    .get(&get_finalizer_spec_key())
                    .expect("resolved inputs always include this key"),
            )?;

            match finalizer {
                FinalizerSpec::Wallet => {
                    pst.finalize_inp_mut(&EC, input_index, BlockHash::all_zeros())
                        .expect("must pass");
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

    fn pre_sync_inputs(&mut self, inputs: &[InputSchema]) -> Result<(), WalletAbiError> {
        for i in inputs {
            match &i.utxo_source {
                UTXOSource::Wallet { filter } => match &filter.lock {
                    LockFilter::None => {}
                    LockFilter::Script { script } => {
                        self.sync_script_wollet(script)?;
                    }
                },
                UTXOSource::Provided { .. } => {}
            }
        }

        Ok(())
    }

    fn ensure_defaults(&self) -> Result<(), WalletAbiError> {
        if self.default_fee_rate_sat_vb <= 0.0 {
            return Err(WalletAbiError::InvalidRequest(
                "runtime.default_fee_rate_sat_vb must be > 0".to_string(),
            ));
        }

        Ok(())
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
pub fn calculate_fee(weight: usize, fee_rate: f32) -> u64 {
    let vsize = weight.div_ceil(4);
    (vsize as f32 * fee_rate / 1000.0).ceil() as u64
}
