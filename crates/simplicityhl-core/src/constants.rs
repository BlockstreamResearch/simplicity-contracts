//! Common Liquid network constants and helpers.
//!
//! Exposes policy asset identifiers and the Liquid testnet genesis hash.
//!
//! These are used throughout the CLI and examples to ensure consistent
//! parameters when constructing Elements transactions.

use simplicityhl::simplicity::elements;
use simplicityhl::simplicity::hashes::{Hash, sha256};

/// Policy asset id (hex, BE) for Liquid mainnet.
pub const LIQUID_POLICY_ASSET_STR: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

/// Policy asset id (hex, BE) for Liquid testnet.
pub const LIQUID_TESTNET_POLICY_ASSET_STR: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// Policy asset id (hex, BE) for Elements regtest.
pub const LIQUID_DEFAULT_REGTEST_ASSET_STR: &str =
    "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";

/// Example test asset id (hex, BE) on Liquid testnet.
pub static LIQUID_TESTNET_TEST_ASSET_ID_STR: &str =
    "38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5";

/// LBTC asset id for Liquid testnet.
pub static LIQUID_TESTNET_BITCOIN_ASSET: std::sync::LazyLock<elements::AssetId> =
    std::sync::LazyLock::new(|| {
        elements::AssetId::from_inner(sha256::Midstate([
            0x49, 0x9a, 0x81, 0x85, 0x45, 0xf6, 0xba, 0xe3, 0x9f, 0xc0, 0x3b, 0x63, 0x7f, 0x2a,
            0x4e, 0x1e, 0x64, 0xe5, 0x90, 0xca, 0xc1, 0xbc, 0x3a, 0x6f, 0x6d, 0x71, 0xaa, 0x44,
            0x43, 0x65, 0x4c, 0x14,
        ]))
    });

/// Genesis block hash for Liquid testnet.
pub static LIQUID_TESTNET_GENESIS: std::sync::LazyLock<elements::BlockHash> =
    std::sync::LazyLock::new(|| {
        elements::BlockHash::from_byte_array([
            0xc1, 0xb1, 0x6a, 0xe2, 0x4f, 0x24, 0x23, 0xae, 0xa2, 0xea, 0x34, 0x55, 0x22, 0x92,
            0x79, 0x3b, 0x5b, 0x5e, 0x82, 0x99, 0x9a, 0x1e, 0xed, 0x81, 0xd5, 0x6a, 0xee, 0x52,
            0x8e, 0xda, 0x71, 0xa7,
        ])
    });

pub const PUBLIC_SECRET_BLINDER_KEY: [u8; 32] = [1; 32];
