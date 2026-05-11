# Simplicity Contracts

This crate is a collection of contracts showcasing core possibilities of [Elements](https://docs.rs/elements)
and [Simplicity HL](https://github.com/BlockstreamResearch/simfony).

Current contract modules in this crate:

- State management:
    - [Simple Storage](src/state_management/simple_storage)
    - [Bytes32 Taproot Storage](src/state_management/bytes32_tr_storage)
    - [Array Taproot Storage](src/state_management/array_tr_storage)
    - [Sparse Merkle Tree Storage](src/state_management/smt_storage)

- Finance:
  - [Options](src/programs/options.rs)
  - [Options Offer](src/programs/option_offer.rs)

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
