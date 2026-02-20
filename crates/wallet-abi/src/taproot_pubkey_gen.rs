//! Ephemeral Taproot pubkey and address generator for argument-bound programs.
//!
//! Produces a deterministic X-only public key and corresponding address without
//! holding a private key, based on a random seed. The resulting trio
//! `<seed_or_ext-xonly_hex>:<pubkey_hex>:<taproot_address>` can be printed and
//! later verified with the same arguments to prevent mismatches.
//!
//! Identity field formats:
//! - `seed_hex`: 32-byte random seed (legacy/current default)
//! - `ext-<xonly_hex>`: externally supplied 32-byte x-only key handle

use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::str::FromStr;

use lwk_common::Network;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use simplicityhl::elements::{Address, schnorr::XOnlyPublicKey};

use crate::ProgramError;
use simplicityhl::simplicity::ToXOnlyPubkey;
use simplicityhl::simplicity::bitcoin::PublicKey;
use simplicityhl::simplicity::bitcoin::key::Parity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum TaprootIdentity {
    Seed(Vec<u8>),
    ExternalXOnly(XOnlyPublicKey),
}

/// Errors from taproot pubkey generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum TaprootPubkeyGenError {
    #[error("Invalid pubkey recovered: expected {expected}, got {actual}")]
    InvalidPubkey { expected: String, actual: String },

    #[error("Invalid address recovered: expected {expected}, got {actual}")]
    InvalidAddress { expected: String, actual: String },

    #[error(
        "Invalid taproot pubkey gen string: expected 3 parts separated by ':', got {parts_count}"
    )]
    InvalidFormat { parts_count: usize },

    #[error("Failed to decode seed hex: {0}")]
    SeedHexDecode(#[from] hex::FromHexError),

    #[error("Invalid seed length: expected 32 bytes, got {actual}")]
    InvalidSeedLength { actual: usize },

    #[error("Failed to parse public key: {0}")]
    PublicKeyParse(#[from] simplicityhl::simplicity::bitcoin::key::ParsePublicKeyError),

    #[error("Failed to parse address: {0}")]
    AddressParse(#[from] simplicityhl::elements::address::AddressError),

    #[error("Failed to create X-only public key from bytes: {0}")]
    XOnlyPublicKey(#[from] simplicityhl::simplicity::bitcoin::secp256k1::Error),

    #[error("Invalid external x-only key: {0}")]
    InvalidExternalKey(String),

    #[error("Failed to generate address: {0}")]
    AddressGeneration(#[from] ProgramError),
}

/// Container for the seed, public key and derived address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaprootPubkeyGen {
    identity: TaprootIdentity,
    pub pubkey: PublicKey,
    pub address: Address,
}

impl TaprootPubkeyGen {
    /// Build from current process randomness and compute the address given `arguments`.
    ///
    /// Kept as `from` for compatibility with existing callers.
    ///
    /// # Errors
    /// Returns error if address generation fails.
    pub fn from<A>(
        arguments: &A,
        network: Network,
        get_address: &impl Fn(&XOnlyPublicKey, &A, Network) -> Result<Address, ProgramError>,
    ) -> Result<Self, TaprootPubkeyGenError> {
        let (not_existent_public_key, seed) = generate_public_key_without_private();

        let address = get_address(
            &not_existent_public_key.to_x_only_pubkey(),
            arguments,
            network,
        )?;

        Ok(Self {
            identity: TaprootIdentity::Seed(seed),
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
        network: Network,
        get_address: &impl Fn(&XOnlyPublicKey, &A, Network) -> Result<Address, ProgramError>,
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
        network: Network,
        get_address: &impl Fn(&XOnlyPublicKey, &A, Network) -> Result<Address, ProgramError>,
    ) -> Result<(), TaprootPubkeyGenError> {
        match &self.identity {
            TaprootIdentity::Seed(seed) => {
                let rand_seed = seed.as_slice();

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
            }
            TaprootIdentity::ExternalXOnly(xonly) => {
                if &self.pubkey.to_x_only_pubkey() != xonly {
                    let expected_pubkey: PublicKey = xonly.public_key(Parity::Even).into();
                    return Err(TaprootPubkeyGenError::InvalidPubkey {
                        expected: expected_pubkey.to_string(),
                        actual: self.pubkey.to_string(),
                    });
                }
            }
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

    pub fn to_json(&self) -> serde_json::Result<Value> {
        serde_json::to_value(self)
    }

    /// Parse `<seed_or_ext-xonly_hex>:<pubkey>:<address>` representation.
    fn parse_from_str(s: &str) -> Result<Self, TaprootPubkeyGenError> {
        let parts = s.split(':').collect::<Vec<&str>>();

        if parts.len() != 3 {
            return Err(TaprootPubkeyGenError::InvalidFormat {
                parts_count: parts.len(),
            });
        }

        let identity = if let Some(xonly_hex) = parts[0].strip_prefix("ext-") {
            let xonly_bytes = hex::decode(xonly_hex)
                .map_err(|e| TaprootPubkeyGenError::InvalidExternalKey(e.to_string()))?;
            if xonly_bytes.len() != 32 {
                return Err(TaprootPubkeyGenError::InvalidExternalKey(format!(
                    "expected 32-byte x-only pubkey, got {} bytes",
                    xonly_bytes.len()
                )));
            }
            TaprootIdentity::ExternalXOnly(
                XOnlyPublicKey::from_slice(&xonly_bytes)
                    .map_err(|e| TaprootPubkeyGenError::InvalidExternalKey(e.to_string()))?,
            )
        } else {
            let seed = hex::decode(parts[0])?;
            if seed.len() != 32 {
                return Err(TaprootPubkeyGenError::InvalidSeedLength { actual: seed.len() });
            }
            TaprootIdentity::Seed(seed)
        };

        Ok(Self {
            identity,
            pubkey: PublicKey::from_str(parts[1])?,
            address: Address::from_str(parts[2])?,
        })
    }
}

impl Display for TaprootPubkeyGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = match &self.identity {
            TaprootIdentity::Seed(seed) => hex::encode(seed),
            TaprootIdentity::ExternalXOnly(xonly) => {
                format!("ext-{}", hex::encode(xonly.serialize()))
            }
        };
        write!(f, "{}:{}:{}", id, self.pubkey, self.address)
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

#[cfg(test)]
mod tests {
    use super::*;
    use simplicityhl::elements::schnorr::Keypair;
    use simplicityhl::elements::secp256k1_zkp::{SECP256K1, SecretKey};

    struct TestArgs;

    fn address_for_key(
        xonly: &XOnlyPublicKey,
        _args: &TestArgs,
        network: Network,
    ) -> Result<Address, ProgramError> {
        crate::get_p2pk_address(xonly, network)
    }

    fn deterministic_test_keypair(byte: u8) -> (XOnlyPublicKey, PublicKey) {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("secret");
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        let xonly = keypair.x_only_public_key().0;
        let pubkey: PublicKey = xonly.public_key(Parity::Even).into();
        (xonly, pubkey)
    }

    #[test]
    fn build_from_str_supports_legacy_seed_handle() {
        let args = TestArgs;
        let generated = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &address_for_key)
            .expect("generated handle");
        let encoded = generated.to_string();
        let decoded = TaprootPubkeyGen::build_from_str(
            &encoded,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect("decoded handle");
        assert_eq!(decoded.pubkey, generated.pubkey);
        assert_eq!(decoded.address, generated.address);
    }

    #[test]
    fn build_from_str_supports_external_xonly_handle() {
        let args = TestArgs;
        let (xonly, pubkey) = deterministic_test_keypair(0x12);
        let address = address_for_key(&xonly, &args, Network::TestnetLiquid).expect("address");

        let encoded = format!(
            "ext-{}:{}:{}",
            hex::encode(xonly.serialize()),
            pubkey,
            address
        );
        let decoded = TaprootPubkeyGen::build_from_str(
            &encoded,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect("decoded handle");

        assert_eq!(decoded.pubkey, pubkey);
        assert_eq!(decoded.address, address);
    }

    #[test]
    fn build_from_str_rejects_non_32_byte_seed_handle() {
        let args = TestArgs;
        let generated = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &address_for_key)
            .expect("generated handle");
        let encoded = generated.to_string();
        let parts = encoded.split(':').collect::<Vec<_>>();

        let invalid_seed_handle = format!("{}:{}:{}", hex::encode([0x11; 31]), parts[1], parts[2]);
        let err = TaprootPubkeyGen::build_from_str(
            &invalid_seed_handle,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect_err("must reject non-32-byte seed");

        assert!(matches!(
            err,
            TaprootPubkeyGenError::InvalidSeedLength { actual } if actual == 31
        ));
    }

    #[test]
    fn build_from_str_rejects_external_identity_with_wrong_length() {
        let args = TestArgs;
        let (xonly, pubkey) = deterministic_test_keypair(0x22);
        let address = address_for_key(&xonly, &args, Network::TestnetLiquid).expect("address");

        let encoded = format!("ext-{}:{}:{}", hex::encode([0xAB; 31]), pubkey, address);
        let err = TaprootPubkeyGen::build_from_str(
            &encoded,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect_err("must reject external x-only keys with wrong size");

        assert!(matches!(err, TaprootPubkeyGenError::InvalidExternalKey(_)));
    }

    #[test]
    fn build_from_str_rejects_external_identity_with_invalid_hex() {
        let args = TestArgs;
        let (xonly, pubkey) = deterministic_test_keypair(0x23);
        let address = address_for_key(&xonly, &args, Network::TestnetLiquid).expect("address");

        let encoded = format!("ext-not_hex:{pubkey}:{address}");
        let err = TaprootPubkeyGen::build_from_str(
            &encoded,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect_err("must reject non-hex external x-only prefix");

        assert!(matches!(err, TaprootPubkeyGenError::InvalidExternalKey(_)));
    }

    #[test]
    fn build_from_str_rejects_mismatched_pubkey_for_seed_identity() {
        let args = TestArgs;
        let generated = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &address_for_key)
            .expect("generated handle");
        let encoded = generated.to_string();
        let parts = encoded.split(':').collect::<Vec<_>>();
        let wrong_pubkey = deterministic_test_keypair(0x44).1;

        let tampered = format!("{}:{}:{}", parts[0], wrong_pubkey, parts[2]);
        let err = TaprootPubkeyGen::build_from_str(
            &tampered,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect_err("must reject mismatched seed-derived public key");

        assert!(matches!(err, TaprootPubkeyGenError::InvalidPubkey { .. }));
    }

    #[test]
    fn build_from_str_rejects_mismatched_address() {
        let args = TestArgs;
        let generated = TaprootPubkeyGen::from(&args, Network::TestnetLiquid, &address_for_key)
            .expect("generated handle");
        let encoded = generated.to_string();
        let parts = encoded.split(':').collect::<Vec<_>>();
        let wrong_network_address = address_for_key(
            &generated.get_x_only_pubkey(),
            &args,
            Network::LocaltestLiquid,
        )
        .expect("address");

        let tampered = format!("{}:{}:{}", parts[0], parts[1], wrong_network_address);
        let err = TaprootPubkeyGen::build_from_str(
            &tampered,
            &args,
            Network::TestnetLiquid,
            &address_for_key,
        )
        .expect_err("must reject mismatched address");

        assert!(matches!(err, TaprootPubkeyGenError::InvalidAddress { .. }));
    }
}
