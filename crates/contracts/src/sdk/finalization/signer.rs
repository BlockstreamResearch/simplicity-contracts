use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::secp256k1_zkp::SecretKey;
use simplicityhl::elements::{Transaction, TxOut};
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl_core::{
    SimplicityNetwork, create_p2pk_signature, create_p2tr_address, finalize_p2pk_transaction,
    get_p2pk_program,
};

pub trait SignerTrait:
    FnOnce(
    SimplicityNetwork,
    Transaction,
    &[TxOut],
) -> Result<Transaction, simplicityhl_core::ProgramError>
{
}

impl<T> SignerTrait for T where
    T: FnOnce(
        SimplicityNetwork,
        Transaction,
        &[TxOut],
    ) -> Result<Transaction, simplicityhl_core::ProgramError>
{
}

pub struct DummySigner;

impl DummySigner {
    const DUMMY_SECRET_KEY: [u8; 32] = [1; 32];

    /// Get the dummy keypair used for fee estimation.
    /// This keypair is deterministic and used only to produce valid transaction structures.
    fn get_dummy_keypair() -> secp256k1::Keypair {
        secp256k1::Keypair::from_secret_key(
            secp256k1::SECP256K1,
            &SecretKey::from_slice(&Self::DUMMY_SECRET_KEY).expect("valid secret key"),
        )
    }

    /// Returns a closure that signs a transaction with dummy signatures.
    ///
    /// This is used for fee estimation - the transaction needs valid witness data
    /// to calculate accurate weight/fees, but the actual signatures don't need
    /// to be cryptographically valid for spending (they just need to be the right size).
    #[allow(clippy::type_complexity)]
    pub(crate) fn get_signer_closure() -> Box<
        dyn FnOnce(
            SimplicityNetwork,
            Transaction,
            &[TxOut],
        ) -> Result<Transaction, simplicityhl_core::ProgramError>,
    > {
        Box::new(
            |network: SimplicityNetwork, tx: Transaction, utxos: &[TxOut]| {
                let keypair = Self::get_dummy_keypair();
                let x_only_public_key = keypair.x_only_public_key().0;
                let p2pk_program = get_p2pk_program(&x_only_public_key)?;
                let cmr = p2pk_program.commit().cmr();

                let dummy_address =
                    create_p2tr_address(cmr, &x_only_public_key, network.address_params());
                let dummy_script_pubkey = dummy_address.script_pubkey();

                let dummy_utxos: Vec<TxOut> = utxos
                    .iter()
                    .map(|utxo: &TxOut| TxOut {
                        script_pubkey: dummy_script_pubkey.clone(),
                        ..utxo.clone()
                    })
                    .collect();

                let mut signed_tx = tx;

                for i in 0..signed_tx.input.len() {
                    let signature = create_p2pk_signature(
                        &signed_tx,
                        &dummy_utxos,
                        &keypair,
                        i,
                        network.address_params(),
                        network.genesis_block_hash(),
                    )?;

                    signed_tx = finalize_p2pk_transaction(
                        signed_tx,
                        &dummy_utxos,
                        &x_only_public_key,
                        &signature,
                        i,
                        network.address_params(),
                        network.genesis_block_hash(),
                        TrackerLogLevel::None,
                    )?;
                }

                Ok(signed_tx)
            },
        )
    }
}
