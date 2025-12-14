# Simplicity HL Core -- Contracts

This crate is a collection of contracts showcasing core possibilities of [Elements](https://docs.rs/elements) and [Simplicity HL](https://github.com/BlockstreamResearch/simfony).

Here you will find Simplicity HL implementations of [Options](https://blockstream.com/assets/downloads/pdf/options-whitepaper.pdf) (see [options](src/options)), Dual Currency Deposit Contract (see [dcd](src/dual_currency_deposit)), and more.

The module that stands out is [`sdk`](src/sdk). This module does not contain contract source code; instead, it provides builder functions to help build Elements transactions to issue assets or transfer native currency (see [basic](src/sdk/basic)), as well as builder functions for the Options contract.

This SDK can be used as a reference for how to build libraries targeting a particular Simplicity contract, integrateable with mobile/desktop, etc.

## License

Dual-licensed under either of:
- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
