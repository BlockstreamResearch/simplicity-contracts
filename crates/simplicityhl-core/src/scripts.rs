//! Script and Taproot utilities plus minor helpers around Elements types.

use anyhow::anyhow;

use sha2::{Digest, Sha256};
use simplicityhl::simplicity::elements;
use simplicityhl::simplicity::elements::{Address, AddressParams, AssetId, ContractHash, OutPoint};

use simplicityhl::simplicity::bitcoin::{XOnlyPublicKey, secp256k1};
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::{Arguments, CompiledProgram};

/// Load program source and compile it to a Simplicity program.
pub fn load_program(source: &str, arguments: Arguments) -> anyhow::Result<CompiledProgram> {
    let compiled = CompiledProgram::new(source, arguments, true)
        .map_err(|e| anyhow!("Failed to compile Simplicity program: {}", e))?;
    Ok(compiled)
}

/// Generate a non-confidential P2TR address for the given program CMR and key.
pub fn create_p2tr_address(
    cmr: simplicityhl::simplicity::Cmr,
    x_only_public_key: &XOnlyPublicKey,
    params: &'static AddressParams,
) -> Address {
    let spend_info = taproot_spending_info(cmr, *x_only_public_key);

    Address::p2tr(
        secp256k1::SECP256K1,
        spend_info.internal_key(),
        spend_info.merkle_root(),
        None,
        params,
    )
}

fn script_version(
    cmr: simplicityhl::simplicity::Cmr,
) -> (elements::Script, elements::taproot::LeafVersion) {
    let script = elements::script::Script::from(cmr.as_ref().to_vec());
    (script, simplicityhl::simplicity::leaf_version())
}

fn taproot_spending_info(
    cmr: simplicityhl::simplicity::Cmr,
    internal_key: XOnlyPublicKey,
) -> elements::taproot::TaprootSpendInfo {
    let builder = elements::taproot::TaprootBuilder::new();
    let (script, version) = script_version(cmr);
    let builder = builder
        .add_leaf_with_ver(0, script, version)
        .expect("tap tree should be valid");
    builder
        .finalize(secp256k1::SECP256K1, internal_key)
        .expect("tap tree should be valid")
}

pub fn control_block(
    cmr: simplicityhl::simplicity::Cmr,
    internal_key: XOnlyPublicKey,
) -> elements::taproot::ControlBlock {
    let info = taproot_spending_info(cmr, internal_key);
    let script_ver = script_version(cmr);
    info.control_block(&script_ver)
        .expect("control block should exist")
}

/// SHA256 hash of an address's scriptPubKey bytes.
pub fn hash_script_pubkey(address: Address) -> [u8; 32] {
    let mut hasher = Sha256::new();
    sha2::digest::Update::update(&mut hasher, address.script_pubkey().as_bytes());
    hasher.finalize().into()
}

/// Compute issuance entropy for a new asset given an outpoint and contract hash entropy.
pub fn get_new_asset_entropy(outpoint: &OutPoint, entropy: [u8; 32]) -> sha256::Midstate {
    let contract_hash = ContractHash::from_byte_array(entropy);
    AssetId::generate_asset_entropy(*outpoint, contract_hash)
}
