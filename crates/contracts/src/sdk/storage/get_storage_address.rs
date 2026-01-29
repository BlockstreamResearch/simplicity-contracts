use simplicityhl::elements::schnorr::XOnlyPublicKey;
use simplicityhl::simplicity::elements::Address;
use simplicityhl::simplicity::elements::Script;
use simplicityhl::simplicity::elements::taproot::TaprootSpendInfo;
use simplicityhl_core::SimplicityNetwork;

use crate::error::TransactionBuildError;
use crate::smt_storage::{
    DEPTH, SparseMerkleTree, get_smt_storage_compiled_program, smt_storage_taproot_spend_info,
};

/// Derives the Taproot address for the SMT storage contract based on its initial state.
///
/// This function calculates the script pubkey by committing to the Simplicity program
/// configured with the provided `storage_bytes` (root hash) and `path`. It then
/// encodes this script into a network-specific address.
///
/// # Errors
///
/// Returns an error if:
/// - The function signature requires a `Result` for consistency with the builder API,
///   though the current implementation primarily panics on failure rather than returning `Err`.
///
/// # Panics
///
/// Panics if:
/// - The generated script is invalid for address creation (e.g., invalid witness program).
pub fn get_storage_address(
    storage_key: &XOnlyPublicKey,
    storage_bytes: &[u8; 32],
    path: [bool; DEPTH],
    network: SimplicityNetwork,
) -> Result<Address, TransactionBuildError> {
    let mut smt = SparseMerkleTree::new();
    let merkle_hashes = smt.update(storage_bytes, path);

    let merkle_data = std::array::from_fn(|i| (merkle_hashes[DEPTH - i - 1], path[DEPTH - i - 1]));

    let program = get_smt_storage_compiled_program();
    let cmr = program.commit().cmr();

    let mint_spend_info: TaprootSpendInfo =
        smt_storage_taproot_spend_info(*storage_key, storage_bytes, &merkle_data, cmr);

    let mint_script_pubkey = Script::new_v1_p2tr_tweaked(mint_spend_info.output_key());

    Ok(Address::from_script(&mint_script_pubkey, None, network.address_params()).unwrap())
}
