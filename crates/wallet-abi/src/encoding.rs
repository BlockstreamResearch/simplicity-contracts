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

    /// Decode from binary and fail if trailing bytes remain.
    fn decode(buf: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized + Decode<()>,
    {
        let (decoded, consumed) = bincode::decode_from_slice(buf, bincode::config::standard())?;
        if consumed != buf.len() {
            return Err(EncodingError::TrailingBytes {
                consumed,
                total: buf.len(),
            });
        }

        Ok(decoded)
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

#[cfg(test)]
mod tests {
    use super::Encodable;
    use crate::error::EncodingError;

    #[derive(Debug, PartialEq, bincode::Encode, bincode::Decode)]
    struct TestPayload {
        value: u32,
    }

    impl Encodable for TestPayload {}

    #[test]
    fn decode_rejects_trailing_bytes() {
        let payload = TestPayload { value: 7 };
        let mut encoded = payload.encode().expect("encodes");
        encoded.push(0);

        let err = <TestPayload as Encodable>::decode(&encoded).expect_err("must reject trailing");
        assert!(matches!(
            err,
            EncodingError::TrailingBytes { consumed, total } if consumed + 1 == total
        ));
    }

    #[test]
    fn from_hex_rejects_trailing_bytes() {
        let payload = TestPayload { value: 7 };
        let mut encoded_hex = payload.to_hex().expect("encodes");
        encoded_hex.push_str("00");

        let err =
            <TestPayload as Encodable>::from_hex(&encoded_hex).expect_err("must reject trailing");
        assert!(matches!(
            err,
            EncodingError::TrailingBytes { consumed, total } if consumed + 1 == total
        ));
    }
}
