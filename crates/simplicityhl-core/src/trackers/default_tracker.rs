//! Default execution tracker with configurable sinks for debug and jet tracing.
//!
//! Intended for embedding in runners; avoids panics and exposes structured hooks
//! for observing program execution.

use simplicityhl::either::Either;

use anyhow::{Context, Result, anyhow};

use simplicityhl::debug::DebugSymbols;
use simplicityhl::jet::{source_type, target_type};
use simplicityhl::str::AliasName;
use simplicityhl::types::AliasedType;
use simplicityhl::value::StructuralValue;
use simplicityhl::{ResolvedType, Value};

use simplicityhl::simplicity::bit_machine::ExecTracker;
use simplicityhl::simplicity::ffi::ffi::UWORD;
use simplicityhl::simplicity::jet::type_name::TypeName;
use simplicityhl::simplicity::jet::{Elements, Jet};
use simplicityhl::simplicity::{BitIter, Cmr, Value as SimValue, ValueRef};

type TrackerDebugSink<'a> = Box<dyn FnMut(&str, &dyn core::fmt::Display) + 'a>;
type TrackerJetTraceSink<'a> = Box<dyn FnMut(Elements, &[Value], &Value) + 'a>;

fn default_debug_sink(label: &str, value: &dyn core::fmt::Display) {
    println!("DBG: {label} = {value}");
}

fn default_jet_trace_sink(jet: Elements, args: &[Value], result: &Value) {
    print!("{jet:?}(");
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("{a}");
    }
    println!(") = {result}");
}

/// Tracks Simplicity execution events and forwards them to configurable sinks.
///
/// This tracker is designed to be embedded in higher-level runners. It avoids
/// printing or panicking on parse errors. Consumers can opt-in to receive
/// structured debug events and jet traces via builder methods.
pub struct DefaultTracker<'a> {
    debug_symbols: &'a DebugSymbols,
    debug_sink: Option<TrackerDebugSink<'a>>, // (label, value)
    jet_trace_sink: Option<TrackerJetTraceSink<'a>>, // (jet, args, result)
}

impl<'a> DefaultTracker<'a> {
    /// Create a new tracker bound to the provided debug symbol table.
    #[must_use]
    pub fn new(debug_symbols: &'a DebugSymbols) -> Self {
        Self {
            debug_symbols,
            debug_sink: None,
            jet_trace_sink: None,
        }
    }

    /// Enable forwarding of debug!() calls to the provided sink.
    #[must_use]
    pub fn with_debug_sink<F>(mut self, sink: F) -> Self
    where
        F: FnMut(&str, &dyn core::fmt::Display) + 'a,
    {
        self.debug_sink = Some(Box::new(sink));
        Self { ..self }
    }

    /// Enable the default debug!() sink that prints to stdout.
    #[must_use]
    pub fn with_default_debug_sink(self) -> Self {
        self.with_debug_sink(default_debug_sink)
    }

    /// Enable forwarding of jet call traces to the provided sink.
    #[must_use]
    pub fn with_jet_trace_sink<F>(mut self, sink: F) -> Self
    where
        F: FnMut(Elements, &[Value], &Value) + 'a,
    {
        self.jet_trace_sink = Some(Box::new(sink));
        Self { ..self }
    }

    /// Enable the default jet trace sink that prints to stdout.
    #[must_use]
    pub fn with_default_jet_trace_sink(self) -> Self {
        self.with_jet_trace_sink(default_jet_trace_sink)
    }
}

impl ExecTracker<Elements> for DefaultTracker<'_> {
    fn track_left(&mut self, _: simplicityhl::simplicity::Ihr) {}

    fn track_right(&mut self, _: simplicityhl::simplicity::Ihr) {}

    fn track_jet_call(
        &mut self,
        jet: &Elements,
        input_buffer: &[UWORD],
        output_buffer: &[UWORD],
        _: bool,
    ) {
        if let Some(sink) = self.jet_trace_sink.as_mut()
            && let (Ok(args), Ok(result)) = (
                parse_args(*jet, input_buffer),
                parse_result(*jet, output_buffer),
            )
        {
            sink(*jet, &args, &result);
        }
    }

    fn track_dbg_call(&mut self, cmr: &Cmr, value: simplicityhl::simplicity::Value) {
        if let Some(sink) = self.debug_sink.as_mut()
            && let Some(tracked_call) = self.debug_symbols.get(cmr)
            && let Some(Either::Right(debug_value)) =
                tracked_call.map_value(&StructuralValue::from(value))
        {
            sink(debug_value.text(), &debug_value.value());
        }
    }

    fn is_track_debug_enabled(&self) -> bool {
        self.debug_sink.is_some()
    }
}

/// Converts an array of words into a bit iterator.
/// Bits are reversed.
fn words_into_bit_iter(words: &[UWORD]) -> BitIter<std::vec::IntoIter<u8>> {
    let bytes_per_word = std::mem::size_of::<UWORD>();
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(words));
    for word in words.iter().rev() {
        for i in 0..bytes_per_word {
            let byte: u8 = u8::try_from((word >> ((bytes_per_word - i - 1) * 8)) & 0xFF)
                .expect("failed to convert word to byte");
            bytes.push(byte);
        }
    }
    BitIter::from(bytes.into_iter())
}

/// Converts an aliased type to a resolved type.
fn resolve_type(aliased_type: &AliasedType) -> Result<ResolvedType> {
    let get_alias = |_: &AliasName| -> Option<ResolvedType> { None };
    aliased_type
        .resolve(get_alias)
        .map_err(|alias| anyhow!("unexpected alias: {alias}"))
}

/// Traverses a product and collects the arguments.
fn collect_args(node: &ValueRef, num_args: usize, args: &mut Vec<SimValue>) -> Result<()> {
    if num_args == 0 {
        return Ok(());
    }
    if num_args == 1 {
        args.push(node.to_value());
        Ok(())
    } else if let Some((left, right)) = node.as_product() {
        args.push(left.to_value());
        collect_args(&right, num_args - 1, args)
    } else {
        Err(anyhow!(
            "unexpected value structure while collecting arguments"
        ))
    }
}

/// Parses a `SimValue` from an array of words.
fn parse_sim_value(words: &[UWORD], type_name: &TypeName) -> Result<SimValue> {
    let sim_type = type_name.to_final();
    let mut bit_iter = words_into_bit_iter(words);
    let sim_value = SimValue::from_padded_bits(&mut bit_iter, &sim_type)
        .context("failed to decode Simplicity value from padded bits")?;
    // Ensure the iterator is closed; ignore any trailing-bit discrepancies.
    let _ = bit_iter.close();
    Ok(sim_value)
}

/// Parses a Simf value from a Simplicity value.
fn parse_simf_value(sim_value: SimValue, aliased_type: &AliasedType) -> Result<Value> {
    let resolved_type = resolve_type(aliased_type)?;
    let value = Value::reconstruct(&sim_value.into(), &resolved_type)
        .ok_or_else(|| anyhow!("failed to reconstruct high-level value"))?;
    Ok(value)
}

/// Parses the arguments of a jet call.
fn parse_args(jet: Elements, words: &[UWORD]) -> Result<Vec<Value>> {
    let simf_types = source_type(jet);
    if simf_types.is_empty() {
        return Ok(vec![]);
    }

    let sim_value = parse_sim_value(words, &jet.source_ty())?;

    let mut args = Vec::with_capacity(simf_types.len());
    collect_args(&sim_value.as_ref(), simf_types.len(), &mut args)?;

    args.into_iter()
        .zip(simf_types.iter())
        .map(|(arg, ty)| parse_simf_value(arg, ty))
        .collect()
}

/// Parses the result of a jet call.
fn parse_result(jet: Elements, words: &[UWORD]) -> Result<Value> {
    let simf_type = target_type(jet);
    let sim_value = parse_sim_value(words, &jet.target_ty())?;
    parse_simf_value(sim_value, &simf_type)
}
