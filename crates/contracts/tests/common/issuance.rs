#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use crate::common::signer::{finalize_and_broadcast, get_lbtc_utxo};

use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use simplex::simplicityhl::elements::secp256k1_zkp::rand::RngCore;
use simplex::simplicityhl::elements::{AssetId, Txid};

/// System-random 32-byte seed.
///
/// # Panics
/// Panics if the system random number generator fails.
#[must_use]
pub fn get_random_seed() -> [u8; 32] {
    let mut bytes: [u8; 32] = [0; 32];
    simplex::simplicityhl::elements::secp256k1_zkp::rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub fn issue_asset(
    context: &simplex::TestContext,
    asset_amount: u64,
) -> anyhow::Result<(Txid, AssetId)> {
    let signer = context.get_default_signer();

    let mut ft = FinalTransaction::new();

    let first_utxo = get_lbtc_utxo(context)?;

    let asset_entropy = get_random_seed();

    let issuance_details = ft.add_issuance_input(
        PartialInput::new(first_utxo.clone()),
        IssuanceInput::new_issuance(asset_amount, 0, asset_entropy),
        RequiredSignature::NativeEcdsa,
    );

    let signer_script_pubkey = signer.get_address().script_pubkey();

    ft.add_output(PartialOutput::new(
        signer_script_pubkey.clone(),
        asset_amount,
        issuance_details.asset_id,
    ));

    let (utxo_asset_id, utxo_amount) = (first_utxo.asset(), first_utxo.amount());

    ft.add_output(PartialOutput::new(
        signer_script_pubkey,
        utxo_amount,
        utxo_asset_id,
    ));

    let txid = finalize_and_broadcast(context, &ft)?;

    Ok((txid, issuance_details.asset_id))
}
