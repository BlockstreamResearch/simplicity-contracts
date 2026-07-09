#![allow(clippy::missing_errors_doc)]

pub mod filters;
pub mod issuance;
pub mod signer;

use simplex::simplicityhl::elements::{LockTime, Sequence};
use simplex::transaction::{PartialInput, UTXO};

/// Offset the chain tip timestamp by a signed delta, checking for overflow.
pub fn offset_timestamp(tip_timestamp: u64, delta_timestamp: i32) -> anyhow::Result<u32> {
    let tip_timestamp = u32::try_from(tip_timestamp)
        .map_err(|_| anyhow::anyhow!("tip timestamp {tip_timestamp} exceeds u32 range"))?;

    if delta_timestamp < 0 {
        tip_timestamp
            .checked_sub(delta_timestamp.unsigned_abs())
            .ok_or_else(|| anyhow::anyhow!("timestamp underflow"))
    } else {
        tip_timestamp
            .checked_add(delta_timestamp.unsigned_abs())
            .ok_or_else(|| anyhow::anyhow!("timestamp overflow"))
    }
}

/// Convert a unix timestamp into an absolute [`LockTime`].
pub fn locktime_from(time: u32) -> anyhow::Result<LockTime> {
    LockTime::from_time(time).map_err(|error| anyhow::anyhow!(error))
}

/// Wrap a UTXO into an input that enables the transaction-level locktime.
#[must_use]
pub fn locked_input(utxo: UTXO, locktime: LockTime) -> PartialInput {
    PartialInput::new(utxo)
        .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF)
        .with_locktime(locktime)
}
