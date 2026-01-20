//! Ephemeral Taproot pubkey and address generator for argument-bound programs.
//!
//! Produces a deterministic X-only public key and corresponding address without
//! holding a private key, based on a random seed. The resulting trio
//! `<seed_hex>:<xonly_pubkey_hex>:<taproot_address>` can be printed and
//! later verified with the same arguments to prevent mismatches.

use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::str::FromStr;

use simplicityhl::elements::{Address, schnorr::XOnlyPublicKey};

use crate::error::TaprootPubkeyGenError;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::bitcoin::PublicKey;
use simplicityhl::simplicity::bitcoin::key::Parity;
use simplicityhl_core::SimplicityNetwork;

/// Container for the seed, public key and derived address.
#[derive(Debug, Clone)]
pub struct TaprootPubkeyGen {
    pub seed: Vec<u8>,
    pub pubkey: PublicKey,
    pub address: Address,
}

impl TaprootPubkeyGen {
    /// Build from current process randomness and compute the address given `arguments`.
    ///
    /// # Errors
    /// Returns error if address generation fails.
    pub fn from<A>(
        arguments: &A,
        network: SimplicityNetwork,
        get_address: &impl Fn(
            &XOnlyPublicKey,
            &A,
            SimplicityNetwork,
        ) -> Result<Address, simplicityhl_core::ProgramError>,
    ) -> Result<Self, TaprootPubkeyGenError> {
        let (not_existent_public_key, seed) = generate_public_key_without_private();

        let address = get_address(
            &not_existent_public_key.to_x_only_pubkey(),
            arguments,
            network,
        )?;

        Ok(Self {
            seed,
            pubkey: not_existent_public_key,
            address,
        })
    }

    /// Parse from string and verify that pubkey and address match the provided arguments.
    ///
    /// # Errors
    /// Returns error if parsing fails or verification doesn't match.
    pub fn build_from_str<A>(
        s: &str,
        arguments: &A,
        network: SimplicityNetwork,
        get_address: &impl Fn(
            &XOnlyPublicKey,
            &A,
            SimplicityNetwork,
        ) -> Result<Address, simplicityhl_core::ProgramError>,
    ) -> Result<Self, TaprootPubkeyGenError> {
        let taproot_pubkey_gen = Self::parse_from_str(s)?;

        taproot_pubkey_gen.verify(arguments, network, get_address)?;

        Ok(taproot_pubkey_gen)
    }

    /// Verify that the stored pubkey and address are consistent with `arguments`.
    ///
    /// # Errors
    /// Returns error if pubkey or address doesn't match the expected values.
    pub fn verify<A>(
        &self,
        arguments: &A,
        network: SimplicityNetwork,
        get_address: &impl Fn(
            &XOnlyPublicKey,
            &A,
            SimplicityNetwork,
        ) -> Result<Address, simplicityhl_core::ProgramError>,
    ) -> Result<(), TaprootPubkeyGenError> {
        let rand_seed = self.seed.as_slice();

        let mut hasher = Sha256::new();
        sha2::digest::Update::update(&mut hasher, rand_seed);
        sha2::digest::Update::update(&mut hasher, rand_seed);
        sha2::digest::Update::update(&mut hasher, rand_seed);
        let potential_pubkey: [u8; 32] = hasher.finalize().into();

        let expected_pubkey: PublicKey = XOnlyPublicKey::from_slice(&potential_pubkey)?
            .public_key(Parity::Even)
            .into();

        if expected_pubkey != self.pubkey {
            return Err(TaprootPubkeyGenError::InvalidPubkey {
                expected: expected_pubkey.to_string(),
                actual: self.pubkey.to_string(),
            });
        }

        let expected_address = get_address(&self.pubkey.to_x_only_pubkey(), arguments, network)?;
        if self.address != expected_address {
            return Err(TaprootPubkeyGenError::InvalidAddress {
                expected: expected_address.to_string(),
                actual: self.address.to_string(),
            });
        }

        Ok(())
    }

    /// Get the X-only public key.
    #[must_use]
    pub fn get_x_only_pubkey(&self) -> XOnlyPublicKey {
        self.pubkey.to_x_only_pubkey()
    }

    /// Parse `<seed_hex>:<pubkey>:<address>` representation.
    fn parse_from_str(s: &str) -> Result<Self, TaprootPubkeyGenError> {
        let parts = s.split(':').collect::<Vec<&str>>();

        if parts.len() != 3 {
            return Err(TaprootPubkeyGenError::InvalidFormat {
                parts_count: parts.len(),
            });
        }

        Ok(Self {
            seed: hex::decode(parts[0])?,
            pubkey: PublicKey::from_str(parts[1])?,
            address: Address::from_str(parts[2])?,
        })
    }
}

impl Display for TaprootPubkeyGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            hex::encode(&self.seed),
            self.pubkey,
            self.address
        )
    }
}

/// Try to deterministically map a random seed into a valid X-only pubkey.
fn try_generate_public_key_without_private() -> Result<(PublicKey, Vec<u8>), TaprootPubkeyGenError>
{
    let rand_seed: [u8; 32] = get_random_seed();

    let mut hasher = Sha256::new();
    sha2::digest::Update::update(&mut hasher, &rand_seed);
    sha2::digest::Update::update(&mut hasher, &rand_seed);
    sha2::digest::Update::update(&mut hasher, &rand_seed);
    let potential_pubkey: [u8; 32] = hasher.finalize().into();

    Ok((
        XOnlyPublicKey::from_slice(&potential_pubkey)?
            .public_key(Parity::Even)
            .into(),
        rand_seed.to_vec(),
    ))
}

/// Generate a valid ephemeral public key and its seed; repeats until valid.
#[must_use]
pub fn generate_public_key_without_private() -> (PublicKey, Vec<u8>) {
    let not_existent_public_key;
    loop {
        if let Ok(public_key) = try_generate_public_key_without_private() {
            not_existent_public_key = public_key;
            break;
        }
    }

    not_existent_public_key
}

/// System-random 32-byte seed.
///
/// # Panics
/// Panics if the system random number generator fails.
#[must_use]
pub fn get_random_seed() -> [u8; 32] {
    ring::rand::generate(&ring::rand::SystemRandom::new())
        .unwrap()
        .expose()
}
