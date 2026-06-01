use crate::artifacts::bytes32_tr_storage::derived_bytes32_tr_storage::Bytes32TrStorageWitness;
use simplex::program::WitnessTrait;
use simplex::simplicityhl::WitnessValues;

#[must_use]
pub fn build_bytes32_tr_witness(state: [u8; 32]) -> WitnessValues {
    Bytes32TrStorageWitness { state }.build_witness()
}
