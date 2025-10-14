//! Execution trackers used during Simplicity program evaluation.
//!
//! - `DefaultTracker`: configurable sinks for debug and jet traces.
//! - `DebugTracker`: collects dbg! logs into a map for tests and inspection.

mod debug_tracker;
mod default_tracker;

pub use debug_tracker::*;
pub use default_tracker::*;
