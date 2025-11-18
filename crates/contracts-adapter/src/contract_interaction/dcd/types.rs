use simplicityhl::elements::{AssetId, OutPoint};
use simplicityhl_core::{AssetEntropyBytes, AssetEntropyHex, LIQUID_TESTNET_BITCOIN_ASSET};

pub type UtxoList = [OutPoint; 3];
pub type AssetEntropyList = [String; 3];
pub type FillerTokenEntropyHex = AssetEntropyHex;
pub type FillerTokenEntropyBytes = AssetEntropyBytes;
pub type GrantorCollateralAssetEntropyHex = AssetEntropyHex;
pub type GrantorCollateralAssetEntropyBytes = AssetEntropyBytes;
pub type GrantorSettlementAssetEntropyHex = AssetEntropyHex;
pub type GrantorSettlementAssetEntropyBytes = AssetEntropyBytes;
pub const COLLATERAL_ASSET_ID: AssetId = LIQUID_TESTNET_BITCOIN_ASSET;
