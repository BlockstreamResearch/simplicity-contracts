# Simplicity Contracts

This crate is a collection of contracts showcasing core possibilities of [Elements](https://docs.rs/elements)
and [SimplicityHL](https://github.com/BlockstreamResearch/simfony).

The generated [`src/artifacts`](src/artifacts) module is compiled from the
SimplicityHL sources in [`simf/`](simf) and checked in; rerun `simplex build`
in this directory after changing a `.simf` source (see
[CONTRIBUTING.md](../../CONTRIBUTING.md) for setup).

Current contract modules in this crate:

- Finance (Rust wrappers in [`src/programs`](src/programs), sources in [`simf/`](simf)):
  - [Options](src/programs/options.rs)
  - [Options Offer](src/programs/option_offer.rs)

- State management (each behind a feature flag, enabled by default; sources
  embedded from each module's `source_simf/` directory):
  - [Simple Storage](src/state_management/simple_storage) — `simple-storage`
  - [Bytes32 Taproot Storage](src/state_management/bytes32_tr_storage) — `bytes32-tr-storage`
  - [Array Taproot Storage](src/state_management/array_tr_storage) — `array-tr-storage`

> [!NOTE]
> Sparse Merkle Tree Storage was removed from the crate. The implementation
> with domain-separated `SMT/1.0/leaf` and `SMT/1.0/node` tagged hashes is
> preserved in the
> [`smt_storage` directory](https://github.com/BlockstreamResearch/simplicity-contracts/tree/24bdb8b4eed3b9ed311570c3143461d9c85e19ed/crates/contracts/src/state_management/smt_storage).
>
> For more details, see
> [PR #72](https://github.com/BlockstreamResearch/simplicity-contracts/pull/72).

## Testing

Unit tests run with `cargo test --lib`. The scenarios in [`tests/`](tests)
require a local regtest environment and are driven by `simplex test`.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
