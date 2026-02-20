//! Script and Taproot helpers shared by contract crates.

use sha2::{Digest, Sha256};

pub use lwk_simplicity::scripts::{
    control_block, create_p2tr_address, load_program, simplicity_leaf_version, tap_data_hash,
};
use simplicityhl::elements::{AssetId, ContractHash, OutPoint, Script};
use simplicityhl::simplicity::hashes::{Hash, sha256};

/// SHA256 of a scriptPubKey byte payload.
#[must_use]
pub fn hash_script(script: &Script) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(script.as_bytes());
    hasher.finalize().into()
}

/// Compute issuance entropy for a new issuance from outpoint + contract hash entropy.
#[must_use]
pub fn get_new_asset_entropy(outpoint: &OutPoint, entropy: [u8; 32]) -> sha256::Midstate {
    let contract_hash = ContractHash::from_byte_array(entropy);
    AssetId::generate_asset_entropy(*outpoint, contract_hash)
}
