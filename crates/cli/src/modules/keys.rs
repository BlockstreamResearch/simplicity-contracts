use crate::modules::settings::Settings;
use simplicityhl::elements::secp256k1_zkp as secp256k1;

/// Derive a secret key from index using seed from environment.
///
/// # Panics
/// Panics if `SEED_HEX` is not configured or invalid.
#[must_use]
pub fn derive_secret_key_from_index(index: u32) -> secp256k1::SecretKey {
    let settings = Settings::load().expect("SEED_HEX should be configured");
    let seed_vec = hex::decode(settings.seed_hex).expect("SEED_HEX must be hex");
    assert_eq!(seed_vec.len(), 32, "SEED_HEX must be 32 bytes hex");

    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&seed_vec);

    for (i, b) in index.to_be_bytes().iter().enumerate() {
        seed_bytes[24 + i] ^= *b;
    }
    secp256k1::SecretKey::from_slice(&seed_bytes).unwrap()
}
