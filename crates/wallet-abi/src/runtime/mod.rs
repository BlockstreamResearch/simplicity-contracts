pub mod utils;

mod input_resolution;
mod output_resolution;

use crate::error::WalletAbiError;
use crate::schema::tx_create::{TransactionInfo, TxCreateRequest, TxCreateResponse};
use crate::{FinalizerSpec, InputSchema, LockFilter, RuntimeParams, UTXOSource};

use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::runtime::utils::to_lwk_wollet_network;
use crate::schema::values::{resolve_arguments, resolve_witness};
use lwk_common::{Bip, Network, Signer};
use lwk_signer::SwSigner;
use lwk_simplicity::runner::run_program;
use lwk_simplicity::scripts::{control_block, load_program};
use lwk_simplicity::signer::get_and_verify_env;
use lwk_wollet::bitcoin::bip32::{DerivationPath, Xpriv};
use lwk_wollet::blocking::BlockchainBackend;
use lwk_wollet::blocking::EsploraClient;
use lwk_wollet::elements::hex::ToHex;
use lwk_wollet::elements::pset::PartiallySignedTransaction;
use lwk_wollet::elements::pset::raw::ProprietaryKey;
use lwk_wollet::elements::{Address, OutPoint, Script, TxOut, TxOutSecrets, secp256k1_zkp};
use lwk_wollet::elements_miniscript::ToPublicKey;
use lwk_wollet::secp256k1::{Keypair, XOnlyPublicKey};
use lwk_wollet::{EC, Wollet, WolletDescriptor};
use simplicityhl::elements::{Transaction, encode};
use simplicityhl::tracker::TrackerLogLevel;

pub(crate) fn get_finalizer_spec_key() -> ProprietaryKey {
    ProprietaryKey::from_pset_pair(1, b"finalizer-spec".to_vec())
}

#[derive(Debug)]
pub struct WalletRuntimeConfig {
    pub signer: SwSigner,
    pub network: Network,
    pub esplora: Arc<Mutex<EsploraClient>>,
    pub wollet: Wollet,
    pub default_fee_rate_sat_vb: f64,
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
        let coin_type = if self.network.is_mainnet() { 1776 } else { 1 };
        let path = match bip {
            Bip::Bip84 => format!("84h/{coin_type}h/0h"),
            Bip::Bip49 => format!("49h/{coin_type}h/0h"),
            Bip::Bip87 => format!("87h/{coin_type}h/0h"),
        };

        let x_private = self
            .signer
            .derive_xprv(&DerivationPath::from_str(&format!("m/{path}")).expect("static"))?;

        Ok(x_private)
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
        let wollet =
            Wollet::without_persist(to_lwk_wollet_network(self.network), wollet_descriptor)?;

        let mut inner_esplora = self
            .esplora
            .lock()
            .map_err(|e| WalletAbiError::EsploraPoisoned(e.to_string()))?;

        if let Some(update) = inner_esplora.full_scan(&wollet)? {
            self.wollet.apply_update(update)?;
        }

        Ok(())
    }

    pub fn fetch_tx_out(&self, outpoint: &OutPoint) -> Result<TxOut, WalletAbiError> {
        let inner_esplora = self
            .esplora
            .lock()
            .map_err(|e| WalletAbiError::EsploraPoisoned(e.to_string()))?;

        let tx = inner_esplora.get_transaction(outpoint.txid)?;
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

        self.pre_sync_inputs(&request.params.inputs)?;

        let finalized_tx = self.finalize(&request.params)?;

        let txid = finalized_tx.txid();

        let inner_esplora = self
            .esplora
            .lock()
            .map_err(|e| WalletAbiError::EsploraPoisoned(e.to_string()))?;

        if request.broadcast {
            let published_txid = inner_esplora.broadcast(&finalized_tx)?;
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

    fn finalize(&self, params: &RuntimeParams) -> Result<Transaction, WalletAbiError> {
        let fee_estimation_build = self.build_transaction(params, 1u64)?;

        let finalized_tx = self.finalize_all_inputs(fee_estimation_build)?;

        let finalized_fee =
            calculate_fee_from_weight(finalized_tx.discount_weight(), self.default_fee_rate_sat_vb);

        self.finalize_all_inputs(self.build_transaction(params, finalized_fee)?)
    }

    fn unblind_with_wallet(&self, tx_out: TxOut) -> Result<(TxOut, TxOutSecrets), WalletAbiError> {
        let blinding_private_key = self
            .signer
            .slip77_master_blinding_key()?
            .blinding_private_key(&tx_out.script_pubkey);

        let secrets = tx_out.unblind(&EC, blinding_private_key)?;

        Ok((tx_out, secrets))
    }

    fn build_transaction(
        &self,
        params: &RuntimeParams,
        fee_target_sat: u64,
    ) -> Result<PartiallySignedTransaction, WalletAbiError> {
        let mut pst = PartiallySignedTransaction::new_v2();
        pst.global.tx_data.fallback_locktime = params.locktime;

        pst = self.resolve_inputs(pst, params)?;
        pst = self.balance_out(pst, params, fee_target_sat)?;

        Ok(pst)
    }

    pub fn finalize_all_inputs(
        &self,
        mut pst: PartiallySignedTransaction,
    ) -> Result<Transaction, WalletAbiError> {
        let utxos: Vec<TxOut> = pst
            .inputs()
            .iter()
            .filter_map(|x| x.witness_utxo.clone())
            .collect();

        self.signer.sign(&mut pst)?;
        let non_final_transaction = self.wollet.finalize(&mut pst)?;

        // This is used to resolve issuance during arguments and witness resolution
        let pst_clone = pst.clone();

        for (input_index, input) in pst.inputs_mut().iter_mut().enumerate() {
            let finalizer: FinalizerSpec = FinalizerSpec::decode(
                input
                    .proprietary
                    .get(&get_finalizer_spec_key())
                    .expect("resolved inputs always include this key"),
            )?;

            match finalizer {
                // Finalized before the cycle
                FinalizerSpec::Wallet => continue,
                FinalizerSpec::Simf {
                    source_simf,
                    internal_key,
                    arguments,
                    witness,
                } => {
                    let arguments = resolve_arguments(&arguments, &pst_clone)?;

                    let program = load_program(&source_simf, arguments)?;

                    let env = get_and_verify_env(
                        &non_final_transaction,
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

                    input.final_script_witness = Some(vec![
                        simplicity_witness_bytes,
                        simplicity_program_bytes,
                        cmr.as_ref().to_vec(),
                        control_block(cmr, internal_key.pubkey.to_x_only_pubkey()).serialize(),
                    ]);
                }
            }
        }

        let tx = pst.extract_tx()?;

        tx.verify_tx_amt_proofs(secp256k1_zkp::SECP256K1, &utxos)?;

        Ok(tx)
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

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn calculate_fee_from_weight(weight: usize, fee_rate_sat_vb: f64) -> u64 {
    let vbytes = weight.div_ceil(4);
    ((vbytes as f64) * fee_rate_sat_vb).ceil() as u64
}
