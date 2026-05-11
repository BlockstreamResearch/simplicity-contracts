# Simplicity Contracts Workspace

This workspace contains reference implementations for working with [Simplicity HL](https://github.com/BlockstreamResearch/simfony) contracts on Elements/Liquid.

## Workspace Crates

- [`contracts`](crates/contracts): Contract templates and helpers (finance + state management modules).

## Repository Structure

- Simplicity sources: [`crates/contracts/src/**/*.simf`](crates/contracts)
- Contract-side Rust helpers: [`crates/contracts/src`](crates/contracts/src)

## Getting Started

- Contract crate usage and module overview: [contracts README](crates/contracts/README.md)

## Notes

This repository is reference-oriented. Copying and adapting modules into your own project is expected while Simplicity tooling/import ergonomics are still evolving.
