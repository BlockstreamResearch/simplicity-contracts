# Simplicity Contracts

This crate is a collection of contracts showcasing core possibilities of [Elements](https://docs.rs/elements) and [Simplicity HL](https://github.com/BlockstreamResearch/simfony).

Here you will find Simplicity HL implementations of [Options](https://blockstream.com/assets/downloads/pdf/options-whitepaper.pdf) (see [finance/options](src/finance/options)), Dual Currency Deposit Contract (see [finance/dcd](src/finance/dcd)), storage contracts, and more.

Wallet-facing transaction construction is schema-first and lives in the wallet ABI crate. Contract-side modules in this crate focus on program compilation, argument/witness helpers, execution, and transaction finalization primitives.

## License

Dual-licensed under either of:
- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
