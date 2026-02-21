# Simplicity Contracts Workspace

This workspace contains reference implementations and tooling for working with [Simplicity HL](https://github.com/BlockstreamResearch/simfony) contracts on Elements/Liquid.

## Workspace Crates

- [`contracts`](crates/contracts): Contract templates and helpers (finance + state management modules).
- [`wallet-abi`](crates/wallet-abi): Schema-first wallet runtime and ABI layer used by contract flows.
- [`wallet-abi-transport`](crates/wallet-abi-transport): Shared `wa_v1` / `wa_resp_v1` / `wa_relay_v1` transport codecs and relay protocol types.
- [`wallet-abi-relayer`](crates/wallet-abi-relayer): Local websocket relay service for encrypted web <-> phone Wallet ABI messaging.
- [`cli`](crates/cli): `simplicity-cli` binary crate for wallet and option-offer command flows.

## Repository Structure

- Simplicity sources: [`crates/contracts/src/**/source_simf/*.simf`](crates/contracts/src)
- Contract-side Rust helpers: [`crates/contracts/src`](crates/contracts/src)
- Wallet runtime and schemas: [`crates/wallet-abi/src/runtime`](crates/wallet-abi/src/runtime), [`crates/wallet-abi/src/schema`](crates/wallet-abi/src/schema)
- CLI entrypoint and commands: [`crates/cli/src/main.rs`](crates/cli/src/main.rs), [`crates/cli/src/commands`](crates/cli/src/commands)

## Getting Started

- Contract crate usage and module overview: [contracts README](crates/contracts/README.md)
- CLI usage and command examples: [CLI README](crates/cli/README.md)

## Notes

This repository is reference-oriented. Copying and adapting modules into your own project is expected while Simplicity tooling/import ergonomics are still evolving.

## Old structure 

Use [this version (116b0eb)](https://github.com/BlockstreamResearch/simplicity-contracts/commit/116b0eb17c3fd84e302d5288ea884c46ba702b77) 
of the repo to interact with the pre-wallet-abi introduction (the last version of simplicityhl-core is here)
