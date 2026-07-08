# Simplicity Contracts

This crate is a collection of contracts showcasing core possibilities of [Elements](https://docs.rs/elements)
and [Simplicity HL](https://github.com/BlockstreamResearch/simfony).

Current contract modules in this crate:

- State management:
    - [Simple Storage](src/state_management/simple_storage)
    - [Bytes32 Taproot Storage](src/state_management/bytes32_tr_storage)
    - [Array Taproot Storage](src/state_management/array_tr_storage)

> [!NOTE]
> Sparse Merkle Tree Storage was removed from the crate. The implementation
> with domain-separated `SMT/1.0/leaf` and `SMT/1.0/node` tagged hashes is
> preserved in the
> [`smt_storage` directory](https://github.com/BlockstreamResearch/simplicity-contracts/tree/24bdb8b4eed3b9ed311570c3143461d9c85e19ed/crates/contracts/src/state_management/smt_storage).
>
> For more details, see
> [PR #72](https://github.com/BlockstreamResearch/simplicity-contracts/pull/72).

- Finance:
  - [Options](src/programs/options.rs)
  - [Options Offer](src/programs/option_offer.rs)

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
