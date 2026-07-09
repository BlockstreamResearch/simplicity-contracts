# Simplicity Contracts Workspace

This workspace contains reference implementations for working with [SimplicityHL](https://github.com/BlockstreamResearch/simfony) contracts on Elements/Liquid, built on the [Simplex](https://github.com/BlockstreamResearch/smplx) toolchain.

## Workspace Crates

- [`contracts`](crates/contracts): Contract templates and helpers (finance + state management modules).

## Repository Structure

- Finance contract sources: [`crates/contracts/simf`](crates/contracts/simf) — compiled by `simplex build` into the generated [`crates/contracts/src/artifacts`](crates/contracts/src/artifacts)
- State management contract sources: `crates/contracts/src/state_management/*/source_simf`
- Contract-side Rust helpers: [`crates/contracts/src`](crates/contracts/src)
- Regtest scenarios and test utilities: [`crates/contracts/tests`](crates/contracts/tests)

## Getting Started

- Development setup (Simplex install, building, testing): [CONTRIBUTING.md](CONTRIBUTING.md)
- Contract crate usage and module overview: [contracts README](crates/contracts/README.md)

## Notes

This repository is reference-oriented. Copying and adapting modules into your own project is expected while Simplicity tooling/import ergonomics are still evolving.

## SimplicityHL Core Package

Reference: https://crates.io/crates/simplicityhl-core

This package was previously used to help early adopters of Simplicity HL move faster when building with Simplicity.
It has now been yanked because most of its functionality is available and maintained in:
- https://github.com/Blockstream/lwk
- https://github.com/BlockstreamResearch/smplx
