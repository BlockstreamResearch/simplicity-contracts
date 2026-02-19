# Simplicity Contracts

This repository is a reference for how you can interact and work with [Simplicity HL](https://github.com/BlockstreamResearch/simfony) contracts.

The only crate published to crates.io is `simplicity-contracts`, so read its [README](crates/contracts/README.md) to understand more about how to use it.

## Repository Structure

If you are new to contract development with Simplicity HL, below you will find a step-by-step workflow for how a contract can be developed, deployed, and used.

Everything starts with the actual Simplicity HL code. See the [.simf files](crates/contracts/src), especially the [Options contract](crates/contracts/src/finance/options/source_simf/options.simf) as the most structured example. Check the issues referenced in the contract for better understanding of development implications.

You can use tools like [`hal-simplicity`](https://github.com/BlockstreamResearch/hal-simplicity) for ad-hoc interaction and manual testing.

If you want to build an application or service around your new contract, take a look at the relevant builders of arguments and witness. See the [Options contract](crates/contracts/src/finance/options/mod.rs) for how to write Rust functions to build those.

The next step after writing helper functions to build args and witness is to do actual testing. Again, see [mod.rs](crates/contracts/src/finance/options/mod.rs) as the best example.

The last step is actual transaction publishing on the chain. This part can be found in the [CLI README](crates/cli/README.md).

## How to Use

You can install the [contracts crate](crates/contracts/Cargo.toml) to build services/SDK around available contracts.

Though this repository provides only examples, and because the basic Simplicity compiler does not support imports, you can just copy paste the code into your project.

## Important Concepts

It is recommended to study the [options.simf](crates/contracts/src/finance/options/source_simf/options.simf) and related issues on GitHub to understand better how to write such contracts securely.

You can see how to use the storage for 32 bytes in the [bytes32_tr_storage.simf](crates/contracts/src/state_management/bytes32_tr_storage/source_simf/bytes32_tr_storage.simf) file.  
For a more general case, see the [array_tr_storage.simf](crates/contracts/src/state_management/array_tr_storage/source_simf/array_tr_storage.simf) file.  
You can find a more detailed explanation of how it works in the first file.
