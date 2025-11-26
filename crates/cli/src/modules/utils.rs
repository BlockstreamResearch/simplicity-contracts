use crate::modules::keys::derive_secret_key_from_index;
use simplicityhl::elements::bitcoin::secp256k1;
use simplicityhl::elements::schnorr::Keypair;

#[must_use]
pub fn derive_keypair(index: u32) -> Keypair {
    Keypair::from_secret_key(secp256k1::SECP256K1, &derive_secret_key_from_index(index))
}
