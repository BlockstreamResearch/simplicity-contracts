pub use bincode::{Decode, Encode};

use crate::error::EncodingError;

/// Trait for binary encoding/decoding with hex string support.
pub trait Encodable {
    fn encode(&self) -> Result<Vec<u8>, EncodingError>
    where
        Self: Encode,
    {
        Ok(bincode::encode_to_vec(self, bincode::config::standard())?)
    }

    fn decode(buf: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized + Decode<()>,
    {
        Ok(bincode::decode_from_slice(buf, bincode::config::standard())?.0)
    }

    fn to_hex(&self) -> Result<String, EncodingError>
    where
        Self: Encode,
    {
        Ok(hex::encode(Encodable::encode(self)?))
    }

    fn from_hex(hex: &str) -> Result<Self, EncodingError>
    where
        Self: bincode::Decode<()>,
    {
        Encodable::decode(&hex::decode(hex)?)
    }
}
