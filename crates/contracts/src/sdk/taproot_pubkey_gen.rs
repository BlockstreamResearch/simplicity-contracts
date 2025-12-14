//! Ephemeral Taproot pubkey and address generator for argument-bound programs.
//!
//! Produces a deterministic X-only public key and corresponding address without
//! holding a private key, based on a random seed. The resulting trio
//! `<seed_hex>:<xonly_pubkey_hex>:<taproot_address>` can be printed and
//! later verified with the same arguments to prevent mismatches.

use std::{fmt::Display, str::FromStr};

use sha2::{Digest, Sha256};

use simplicityhl::elements::{Address, AddressParams, schnorr::XOnlyPublicKey};

use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::bitcoin::PublicKey;
use simplicityhl::simplicity::bitcoin::key::Parity;

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
        params: &'static AddressParams,
        get_address: &impl Fn(&XOnlyPublicKey, &A, &'static AddressParams) -> anyhow::Result<Address>,
    ) -> anyhow::Result<Self> {
        let (not_existent_public_key, seed) = generate_public_key_without_private();

        let address = get_address(
            &not_existent_public_key.to_x_only_pubkey(),
            arguments,
            params,
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
        params: &'static AddressParams,
        get_address: &impl Fn(&XOnlyPublicKey, &A, &'static AddressParams) -> anyhow::Result<Address>,
    ) -> anyhow::Result<Self> {
        let taproot_pubkey_gen = Self::from_str(s)?;

        taproot_pubkey_gen.verify(arguments, params, get_address)?;

        Ok(taproot_pubkey_gen)
    }

    /// Verify that the stored pubkey and address are consistent with `arguments`.
    ///
    /// # Errors
    /// Returns error if pubkey or address doesn't match the expected values.
    pub fn verify<A>(
        &self,
        arguments: &A,
        params: &'static AddressParams,
        get_address: &impl Fn(&XOnlyPublicKey, &A, &'static AddressParams) -> anyhow::Result<Address>,
    ) -> anyhow::Result<()> {
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
            return Err(anyhow::anyhow!("Invalid pubkey"));
        }

        if self.address != get_address(&self.pubkey.to_x_only_pubkey(), arguments, params)? {
            return Err(anyhow::anyhow!("Invalid address"));
        }

        Ok(())
    }

    /// Get the X-only public key.
    #[must_use]
    pub fn get_x_only_pubkey(&self) -> XOnlyPublicKey {
        self.pubkey.to_x_only_pubkey()
    }

    /// Parse `<seed_hex>:<pubkey>:<address>` representation.
    fn from_str(s: &str) -> anyhow::Result<Self> {
        let parts = s.split(':').collect::<Vec<&str>>();

        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid taproot pubkey gen string"));
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
fn try_generate_public_key_without_private() -> anyhow::Result<(PublicKey, Vec<u8>)> {
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
