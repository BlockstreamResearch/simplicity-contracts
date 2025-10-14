//! Minimal tracker that collects dbg! logs into a map for assertions and inspection.

use std::collections::HashMap;

use simplicityhl::debug::DebugSymbols;
use simplicityhl::either::Either;
use simplicityhl::simplicity::Cmr;
use simplicityhl::simplicity::bit_machine::ExecTracker;
use simplicityhl::simplicity::ffi::ffi::UWORD;
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::value::StructuralValue;

/// Stores `dbg!` logs keyed by their label text.
#[derive(Debug)]
pub struct DebugTracker<'a> {
    pub debug_symbols: &'a DebugSymbols,
    pub debug_logs: HashMap<String, String>,
}

impl<'a> DebugTracker<'a> {
    pub fn new(debug_symbols: &'a DebugSymbols) -> Self {
        Self {
            debug_symbols,
            debug_logs: HashMap::new(),
        }
    }
}

impl<'a> ExecTracker<Elements> for DebugTracker<'a> {
    fn track_left(&mut self, _: simplicityhl::simplicity::Ihr) {}

    fn track_right(&mut self, _: simplicityhl::simplicity::Ihr) {}

    fn track_jet_call(&mut self, _: &Elements, _: &[UWORD], _: &[UWORD], _: bool) {}

    fn track_dbg_call(&mut self, cmr: &Cmr, value: simplicityhl::simplicity::Value) {
        if let Some(tracked_call) = self.debug_symbols.get(cmr)
            && let Some(Either::Right(debug_value)) =
                tracked_call.map_value(&StructuralValue::from(value))
        {
            self.debug_logs.insert(
                debug_value.text().to_string(),
                debug_value.value().to_string(),
            );
        }
    }

    fn is_track_debug_enabled(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use anyhow::anyhow;

    use std::sync::Arc;

    use simplicityhl::simplicity::elements;
    use simplicityhl::simplicity::elements::pset::PartiallySignedTransaction;
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::hashes::Hash;

    use simplicityhl::simplicity::jet::elements::ElementsEnv;
    use simplicityhl::{Arguments, TemplateProgram, WitnessValues};

    pub const MOCKED_PROGRAM_SOURCE: &str = r#"
    fn main() {
        let a: u64 = 1;
        let b: u64 = dbg!(a);
        assert!(true);
    }
    "#;

    #[test]
    fn test_debug_tracker() -> anyhow::Result<()> {
        let program = TemplateProgram::new(MOCKED_PROGRAM_SOURCE).map_err(|e| anyhow!("{}", e))?;
        let program = program
            .instantiate(Arguments::default(), true)
            .map_err(|e| anyhow!("{}", e))?;

        let tx = PartiallySignedTransaction::new_v2();

        let env = ElementsEnv::new(
            Arc::new(tx.extract_tx()?),
            vec![],
            0,
            Cmr::from_byte_array([0; 32]),
            ControlBlock::from_slice(&[0xc0; 33])?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let satisfied = program
            .satisfy(WitnessValues::default())
            .map_err(|e| anyhow!("{}", e))?;

        let pruned = match satisfied.redeem().prune(&env) {
            Ok(pruned) => pruned,
            Err(e) => return Err(e.into()),
        };
        let mut mac = match simplicityhl::simplicity::BitMachine::for_program(&pruned) {
            Ok(mac) => mac,
            Err(e) => return Err(e.into()),
        };

        let mut tracker = DebugTracker::new(satisfied.debug_symbols());
        match mac.exec_with_tracker(&pruned, &env, &mut tracker) {
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        };

        let logs = tracker.debug_logs.iter().collect::<Vec<_>>();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "a");
        assert_eq!(logs[0].1, "1");

        Ok(())
    }
}
