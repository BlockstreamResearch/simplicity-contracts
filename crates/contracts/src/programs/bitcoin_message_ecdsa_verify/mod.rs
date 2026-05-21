use std::sync::Arc;

use crate::error::ProgramError;
use crate::runner::run_program;
use crate::scripts::{control_block, create_p2tr_address, load_program};

use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::bitcoin::secp256k1::PublicKey;
use simplex::simplicityhl::elements::hashes::Hash as _;
use simplex::simplicityhl::elements::{Address, Script, Transaction, TxInWitness, TxOut};
use simplex::simplicityhl::simplicity::RedeemNode;
use simplex::simplicityhl::simplicity::bitcoin::XOnlyPublicKey;
use simplex::simplicityhl::simplicity::jet::Elements;
use simplex::simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};
use simplex::simplicityhl::tracker::TrackerLogLevel;
use simplex::simplicityhl::{CompiledProgram, WitnessValues};
use simplex::utils::hash_script;

mod build_witness;

pub use build_witness::{
    build_bitcoin_message_ecdsa_verify_arguments, build_bitcoin_message_ecdsa_verify_witness,
};

pub type Point = (bool, [u8; 32]);
pub type Scalar = [u8; 32];

pub const BITCOIN_MESSAGE_ECDSA_VERIFY_SOURCE: &str =
    include_str!("source_simf/bitcoin_message_ecdsa_verify.simf");

#[derive(Debug, Clone, Copy)]
pub struct BitcoinMessageEcdsaVerifyParameters {
    pub public_key: Point,
    pub network: SimplicityNetwork,
}

#[derive(Debug, Clone, Copy)]
pub struct BitcoinMessageEcdsaVerifyWitness {
    pub nonce_point: Point,
    pub r: Scalar,
    pub s: Scalar,
}

pub struct BitcoinMessageEcdsaVerify {
    compiled_program: CompiledProgram,
    internal_key: XOnlyPublicKey,
    pub parameters: BitcoinMessageEcdsaVerifyParameters,
}

impl BitcoinMessageEcdsaVerify {
    /// Compile the Bitcoin signed-message ECDSA verification contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded SIMF source cannot be compiled.
    pub fn new(parameters: BitcoinMessageEcdsaVerifyParameters) -> Result<Self, ProgramError> {
        Self::from_internal_key(unspendable_internal_key(), parameters)
    }

    /// Compile the contract using an explicit Taproot internal key.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded SIMF source cannot be compiled.
    pub fn from_internal_key(
        internal_key: XOnlyPublicKey,
        parameters: BitcoinMessageEcdsaVerifyParameters,
    ) -> Result<Self, ProgramError> {
        let compiled_program = load_program(
            BITCOIN_MESSAGE_ECDSA_VERIFY_SOURCE,
            build_bitcoin_message_ecdsa_verify_arguments(parameters.public_key),
        )?;

        Ok(Self {
            compiled_program,
            internal_key,
            parameters,
        })
    }

    /// Compile the contract from a compressed ECDSA public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded SIMF source cannot be compiled.
    pub fn from_public_key(
        public_key: &PublicKey,
        network: SimplicityNetwork,
    ) -> Result<Self, ProgramError> {
        Self::new(BitcoinMessageEcdsaVerifyParameters {
            public_key: Self::point_from_public_key(public_key),
            network,
        })
    }

    /// Compile the contract from an explicit internal key and compressed ECDSA public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded SIMF source cannot be compiled.
    pub fn from_internal_key_and_public_key(
        internal_key: XOnlyPublicKey,
        public_key: &PublicKey,
        network: SimplicityNetwork,
    ) -> Result<Self, ProgramError> {
        Self::from_internal_key(
            internal_key,
            BitcoinMessageEcdsaVerifyParameters {
                public_key: Self::point_from_public_key(public_key),
                network,
            },
        )
    }

    /// Convert a compressed ECDSA public key into the contract point representation.
    ///
    /// # Panics
    ///
    /// Panics only if `PublicKey::serialize` stops returning the standard
    /// 33-byte compressed encoding.
    #[must_use]
    pub fn point_from_public_key(public_key: &PublicKey) -> Point {
        let serialized = public_key.serialize();
        (serialized[0] == 0x03, serialized[1..].try_into().unwrap())
    }

    #[must_use]
    pub const fn get_witness(
        nonce_y_is_odd: bool,
        r: Scalar,
        s: Scalar,
    ) -> BitcoinMessageEcdsaVerifyWitness {
        BitcoinMessageEcdsaVerifyWitness {
            nonce_point: (nonce_y_is_odd, r),
            r,
            s,
        }
    }

    #[must_use]
    pub const fn get_program(&self) -> &CompiledProgram {
        &self.compiled_program
    }

    #[must_use]
    pub const fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_key
    }

    #[must_use]
    pub fn get_address(&self) -> Address {
        create_p2tr_address(
            self.compiled_program.commit().cmr(),
            &self.internal_key,
            self.parameters.network.address_params(),
        )
    }

    #[must_use]
    pub fn get_script_pubkey(&self) -> Script {
        self.get_address().script_pubkey()
    }

    #[must_use]
    pub fn get_script_hash(&self) -> [u8; 32] {
        hash_script(&self.get_script_pubkey())
    }

    /// Build and verify the Elements environment for this contract input.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected UTXO is missing, has a mismatched script
    /// pubkey, or the input index does not fit in the Simplicity environment.
    pub fn get_env(
        &self,
        tx: &Transaction,
        utxos: &[TxOut],
        input_index: usize,
    ) -> Result<ElementsEnv<Arc<Transaction>>, ProgramError> {
        let cmr = self.compiled_program.commit().cmr();

        if utxos.len() <= input_index {
            return Err(ProgramError::UtxoIndexOutOfBounds {
                input_index,
                utxo_count: utxos.len(),
            });
        }

        let target_utxo = &utxos[input_index];
        let script_pubkey = self.get_script_pubkey();

        if target_utxo.script_pubkey != script_pubkey {
            return Err(ProgramError::ScriptPubkeyMismatch {
                expected_hash: script_pubkey.script_hash().to_string(),
                actual_hash: target_utxo.script_pubkey.script_hash().to_string(),
            });
        }

        Ok(ElementsEnv::new(
            Arc::new(tx.clone()),
            utxos
                .iter()
                .map(|utxo| ElementsUtxo {
                    script_pubkey: utxo.script_pubkey.clone(),
                    asset: utxo.asset,
                    value: utxo.value,
                })
                .collect(),
            u32::try_from(input_index)?,
            cmr,
            control_block(cmr, self.internal_key),
            None,
            self.parameters.network.genesis_block_hash(),
        ))
    }

    /// Compute the Simplicity `sighash_all` used by the Bitcoin signed-message digest.
    ///
    /// # Errors
    ///
    /// Returns an error if environment construction fails.
    pub fn sighash_all(
        &self,
        tx: &Transaction,
        utxos: &[TxOut],
        input_index: usize,
    ) -> Result<[u8; 32], ProgramError> {
        Ok(self
            .get_env(tx, utxos, input_index)?
            .c_tx_env()
            .sighash_all()
            .to_byte_array())
    }

    /// Execute this contract with an already-built environment.
    ///
    /// # Errors
    ///
    /// Returns an error if witness satisfaction, pruning, or execution fails.
    pub fn execute(
        &self,
        witness: &BitcoinMessageEcdsaVerifyWitness,
        env: &ElementsEnv<Arc<Transaction>>,
        log_level: TrackerLogLevel,
    ) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
        self.execute_witness_values(
            build_bitcoin_message_ecdsa_verify_witness(witness),
            env,
            log_level,
        )
    }

    /// Execute this contract with manually supplied witness values.
    ///
    /// # Errors
    ///
    /// Returns an error if witness satisfaction, pruning, or execution fails.
    pub fn execute_witness_values(
        &self,
        witness_values: WitnessValues,
        env: &ElementsEnv<Arc<Transaction>>,
        log_level: TrackerLogLevel,
    ) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
        Ok(run_program(&self.compiled_program, witness_values, env, log_level)?.0)
    }

    /// Finalize a transaction input with this contract witness.
    ///
    /// # Errors
    ///
    /// Returns an error if environment construction or program execution fails.
    pub fn finalize_transaction(
        &self,
        mut tx: Transaction,
        utxos: &[TxOut],
        input_index: usize,
        witness: &BitcoinMessageEcdsaVerifyWitness,
        log_level: TrackerLogLevel,
    ) -> Result<Transaction, ProgramError> {
        let env = self.get_env(&tx, utxos, input_index)?;
        let pruned = self.execute(witness, &env, log_level)?;

        let (simplicity_program_bytes, simplicity_witness_bytes) = pruned.to_vec_with_witness();
        let cmr = pruned.cmr();
        let tx_input_count = tx.input.len();
        let tx_input = tx
            .input
            .get_mut(input_index)
            .ok_or(ProgramError::UtxoIndexOutOfBounds {
                input_index,
                utxo_count: tx_input_count,
            })?;

        tx_input.witness = TxInWitness {
            amount_rangeproof: None,
            inflation_keys_rangeproof: None,
            script_witness: vec![
                simplicity_witness_bytes,
                simplicity_program_bytes,
                cmr.as_ref().to_vec(),
                control_block(cmr, self.internal_key).serialize(),
            ],
            pegin_witness: vec![],
        };

        Ok(tx)
    }
}

/// The unspendable internal key specified in BIP-0341.
///
/// # Panics
///
/// Panics if the hard-coded key bytes stop parsing as an x-only public key.
#[rustfmt::skip]
#[must_use]
pub fn unspendable_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ])
    .expect("key should be valid")
}
