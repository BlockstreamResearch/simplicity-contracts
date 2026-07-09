use simplex::simplicityhl::ast::ElementsJetHinter;
use simplex::simplicityhl::elements::{Address, AddressParams, Script, taproot};

use simplex::simplicityhl::simplicity::Cmr;
use simplex::simplicityhl::simplicity::bitcoin::{XOnlyPublicKey, secp256k1};
use simplex::simplicityhl::simplicity::hashes::{Hash, HashEngine, sha256};
use simplex::simplicityhl::{Arguments, CompiledProgram};

use super::error::ProgramError;

/// Compile `SimplicityHL` source into a Simplicity program with debug symbols.
///
/// # Errors
/// Returns an error if the program fails to compile.
pub fn load_program(source: &str, arguments: Arguments) -> Result<CompiledProgram, ProgramError> {
    CompiledProgram::new(source, arguments, true, Box::new(ElementsJetHinter))
        .map_err(ProgramError::Compilation)
}

/// Generate a non-confidential P2TR address for the given program CMR and key.
#[must_use]
pub fn create_p2tr_address(
    cmr: Cmr,
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

/// Return the version of Simplicity leaves inside a tap tree.
#[must_use]
pub fn simplicity_leaf_version() -> taproot::LeafVersion {
    simplex::simplicityhl::simplicity::leaf_version()
}

/// The unspendable internal key specified in BIP-0341.
///
/// # Panics
/// Never: the hard-coded bytes are a valid x-only public key.
#[rustfmt::skip] // mangles byte vectors
#[must_use]
pub fn unspendable_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ])
    .expect("key is valid")
}

/// Create a SHA256 context, initialized with a "`TapData`" tag and data
///
/// Based on the C implementation of the `tapdata_init` jet:
/// <https://github.com/BlockstreamResearch/simplicity/blob/d190505509f4c04b1b9193c6739515f9faa18aac/C/jets.c#L1408>
#[must_use]
pub fn tap_data_hash(data: &[u8]) -> sha256::Hash {
    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(data);
    sha256::Hash::from_engine(eng)
}

/// Compute the Taproot control block for script-path spending.
///
/// # Panics
/// Panics if the CMR leaf is not part of the tap tree (never happens for a
/// tree built from the same CMR).
#[must_use]
pub fn control_block(cmr: Cmr, internal_key: XOnlyPublicKey) -> taproot::ControlBlock {
    let info = taproot_spending_info(cmr, internal_key);
    let script_ver = script_ver(cmr);

    info.control_block(&script_ver)
        .expect("control block should exist")
}

/// Return the (script, leaf version) pair for the CMR of a Simplicity program.
#[must_use]
pub fn script_ver(cmr: Cmr) -> (Script, taproot::LeafVersion) {
    (
        Script::from(cmr.as_ref().to_vec()),
        simplicity_leaf_version(),
    )
}

/// Compute the [`taproot::TaprootSpendInfo`] for a tap tree with the program
/// CMR as its single leaf.
///
/// # Panics
/// Panics if the tap tree cannot be built (never happens for a valid CMR).
#[must_use]
pub fn taproot_spending_info(cmr: Cmr, internal_key: XOnlyPublicKey) -> taproot::TaprootSpendInfo {
    let (script, version) = script_ver(cmr);
    let builder = taproot::TaprootBuilder::new()
        .add_leaf_with_ver(0, script, version)
        .expect("tap tree should be valid");
    builder
        .finalize(secp256k1::SECP256K1, internal_key)
        .expect("tap tree should be valid")
}

/// Compute the [`taproot::TaprootSpendInfo`] for a tap tree with two leaves:
/// the program CMR and a hidden leaf committing to contract state.
///
/// Both leaves sit at depth 1, directly under the root. The state hash is
/// inserted with `add_hidden`, which commits to the hash as-is instead of
/// hashing a script.
///
/// # Panics
/// Panics if the tap tree cannot be built (never happens for a valid CMR).
#[must_use]
pub fn state_taproot_spend_info(
    internal_key: XOnlyPublicKey,
    state_hash: sha256::Hash,
    cmr: Cmr,
) -> taproot::TaprootSpendInfo {
    let (script, version) = script_ver(cmr);
    let builder = taproot::TaprootBuilder::new()
        .add_leaf_with_ver(1, script, version)
        .expect("tap tree should be valid")
        .add_hidden(1, state_hash)
        .expect("tap tree should be valid");

    builder
        .finalize(secp256k1::SECP256K1, internal_key)
        .expect("tap tree should be valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tap_data_hash() {
        assert_eq!(
            tap_data_hash([0u8; 32].as_ref()).to_string(),
            "a33ad504fd45357a3909bf9dea8ce4aca38fe6e7d9c9d3e9e01211408990123f"
        );
    }
}
