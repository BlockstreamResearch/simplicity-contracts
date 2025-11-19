use anyhow::anyhow;
use simplicityhl::elements::hashes::sha256;
use simplicityhl_core::AssetEntropyBytes;

#[derive(Debug)]
pub struct AssetEntropyProcessed {
    pub entropy: sha256::Midstate,
    pub reversed_bytes: AssetEntropyBytes,
}

#[inline]
pub fn raw_asset_entropy_bytes_to_midstate(mut bytes: AssetEntropyBytes) -> AssetEntropyProcessed {
    bytes.reverse();
    AssetEntropyProcessed {
        entropy: sha256::Midstate::from_byte_array(bytes),
        reversed_bytes: bytes,
    }
}

/// Converts bytes asset entropy to 32 bytes representation, without any changes
pub fn convert_bytes_to_asset_entropy(val: impl AsRef<[u8]>) -> anyhow::Result<AssetEntropyBytes> {
    let asset_entropy_vec = val.as_ref().to_vec();
    let asset_entropy: AssetEntropyBytes = asset_entropy_vec.try_into().map_err(|x: Vec<u8>| {
        anyhow!(
            "Failed to parse asset entropy, got len: {}, has to be: {}",
            x.len(),
            AssetEntropyBytes::default().len()
        )
    })?;
    Ok(asset_entropy)
}
