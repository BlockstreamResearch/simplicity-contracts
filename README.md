## Simplicity Contracts

Workspace for prototyping and exercising Simplicity-based contracts on Liquid testnet. It includes:
- A small CLI for building and broadcasting transactions
- A contracts crate housing Simplicity sources and helpers (e.g., an Options covenant contract)
- A high-level helper library to compile, run, and finalize Simplicity programs

## Workspace structure

- `crates/simplicityhl-core` — High-level helpers around Simplicity on Elements/Liquid
  - Address derivation for P2TR Simplicity programs (`create_p2tr_address`, `get_p2pk_address`)
  - Program compilation and execution (`load_program`, `run_program`), trackers, and logging
  - Transaction finalization helpers to attach Simplicity witnesses (`finalize_transaction`, `finalize_p2pk_transaction`)
  - Explorer utilities for Esplora broadcast/fetch with on-disk caching
  - Constants for Liquid testnet (policy asset, LBTC id, genesis hash)
  - Embedded `p2pk.simf` program

- `crates/contracts` — Contract templates and helpers
  - `options/` contains a Simplicity Options contract (`options.simf`) based on the [options whitepaper](https://blockstream.com/assets/downloads/pdf/options-whitepaper.pdf), argument builders, and witness builders
  - `simple_storage/` contains a minimal stateful storage covenant (`simple_storage.simf`), argument and witness builders
  - `get_options_program`, `get_options_address`, and `finalize_options_funding_path_transaction`
  - `get_storage_compiled_program`, `get_storage_address`, and helpers to finalize storage transactions
  - Bincode-based encoding of argument structs (via `simplicityhl-core` encoding feature)

- `crates/cli` — Simplicity helper CLI (Liquid testnet)
  - `basic` commands: P2PK address derivation and simple LBTC/asset transfers
  - `options` commands: create/fund/exercise/settle/expire/cancel paths for the Options contract
  - `storage` commands: initialize storage state and update state (mint/burn paths)
  - Uses a local sled store at `.cache/store` for argument persistence

### Note

- Finalization and verification
  - `finalize_transaction` and `finalize_p2pk_transaction` verify the input UTXO’s script matches the program CMR+key, build an `ElementsEnv`, execute the program, and attach the Simplicity witness to the chosen input.

- Ephemeral key binding
  - `TaprootPubkeyGen` deterministically binds a program’s arguments to a public key and address without holding a private key. Its string form is `<seed_hex>:<xonly_pubkey>:<taproot_address>` and can be re-verified later with the same arguments.

## Expected behavior

- General
  - All transactions built here are explicit (unblinded). Fee outputs are explicit LBTC. The code targets Liquid testnet (`AddressParams::LIQUID_TESTNET`).
  - The CLI fetches UTXOs from the Liquid Testnet explorer and caches raw tx hex under `.cache/explorer/tx/`.
  - When `--broadcast` is provided, transactions are POSTed to Esplora and the txid is printed. Without it, raw hex is printed.

- Basic CLI (P2PK)
  - `basic address <index>` prints the derived X-only public key and its P2TR address.
  - `basic transfer-native` builds a 1-in/2-out LBTC spend with change + a separate fee output, then Schnorr-signs and optionally broadcasts.
  - `basic split-native` enforces that `first + second + fee == input value` for exact splits.
  - `basic transfer-asset` spends an ASSET UTXO and a separate LBTC fee UTXO, returning change for both and enforcing the fee UTXO is LBTC.

- Options contract
  - Creation: mints two reissuance tokens (option/grantor), persists entropies for later reissuance, derives/stores `OptionsArguments`, and prints the `TaprootPubkeyGen` string for the covenant instance.
  - Funding: reissues both tokens forward to the covenant address, deposits LBTC collateral, returns base assets as change, and attaches Simplicity witnesses for both token inputs.
  - Exercise (option-holder): burns option tokens, posts the settlement amount in target asset back to the covenant, and withdraws the proportional collateral to a P2PK recipient. Uses `fallback_locktime` and `Sequence::ENABLE_LOCKTIME_NO_RBF` where required by the covenant.
  - Settlement (grantor): burns grantor tokens against target asset held by the covenant, forwards settlement asset, and pays fees from a P2PK LBTC UTXO.
  - Expiry (grantor): after expiry, burns grantor tokens and withdraws the corresponding collateral to a P2PK recipient (fees deducted from collateral input).
  - Cancellation: burns both tokens and withdraws a portion of collateral to a P2PK recipient (fees deducted from collateral input).
  - The covenant expects specific output ordering and conditional change outputs; the CLI constructs outputs in that order.

- Simple Storage
  - Init: issues a slot asset and a reissuance token, binds `StorageArguments` and persists the initial entropy for later reissuance.
  - Update: enforces that output[0] remains at the covenant with `SLOT_ID` set to `NEW_VALUE`.
    - Burn path (decrease): burns the exact delta to OP_RETURN at index 1.
    - Mint path (increase): consumes the reissuance token UTXO and enforces a covenant output at the next index.
  - Only the bound owner key may authorize updates (Schnorr over `sig_all_hash`).
  - See `crates/contracts/src/simple_storage/README.md` for details.

## Swaps in Liquid

Here are some resources to help you get started with asset swaps on Liquid:

- Learn about asset swap transactions and how to start developing smart contracts (such as options) on Liquid: https://docs.liquid.net/docs/swaps-and-smart-contracts
- A helpful article on two-step atomic swaps on the Liquid Network: https://medium.com/blockstream/liquidex-2-step-atomic-swaps-on-the-liquid-network-8a7ff6fb7aa5

This functionality completes the set of tools needed to build a DEX-like system where users can trade options.

Note: To swap two tokens for one (e.g., 1 Option Token and 1 Grantor Token for 1 LBTC), a custom Simplicity script is required.

## Getting started

Prerequisites
- Rust (as per crate requirements; `simplicityhl-core` declares `rust-version = 1.90`)

Setup
1. In `crates/cli`, create a `.env` file with a 32-byte hex seed:
   ```
   SEED_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
   ```
2. Build and view help:
   ```
   cargo run -p cli -- --help
   ```

Examples
- Address derivation:
  ```
  cargo run -p cli -- basic address 0
  ```
- Transfer LBTC (print hex or broadcast):
  ```
  cargo run -p cli -- basic transfer-native \
    --utxo <txid>:<vout> \
    --to-address <tlq1...> \
    --send-sats 150000 \
    --fee-sats 500 \
    --account-index 0 \
    --broadcast
  ```
- Options import/export of encoded arguments:
  ```
  cargo run -p cli -- options import  --help
  cargo run -p cli -- options export  --help
  ```

- Options flows (creation → funding → exercise/settlement/expiry/cancellation): see [`crates/cli/README.md`](https://github.com/BlockstreamResearch/simplicity-contracts/blob/main/crates/cli/README.md) for full command lines and an example run with actual values.

- Simple Storage flows, see [`crates/contracts/src/simple_storage/README.md`](https://github.com/BlockstreamResearch/simplicity-contracts/blob/main/crates/contracts/src/simple_storage/README.md) for the detailed explanation.

## Development tips

- Tests
  - Unit tests exist in `contracts` and `simplicityhl-core` (including program path tests). Run:
    ```
    cargo test -p simplicityhl-core -p contracts
    ```

- Debugging program execution
  - Use `RunnerLogLevel::{Debug,Trace}` and the provided trackers (`DefaultTracker`, `DebugTracker`) to observe `dbg!` values and jet traces during execution.
  - **Logs can be printed only if the program is successfully executed!** 

- Encoding and persistence
  - Enable the `encoding` feature in `simplicityhl-core` to use the `Encodable` trait for bincode encoding/decoding of arguments. The CLI persists encoded options arguments in a local sled store under `.cache/store`.

- Adding a new contract
  1. Add a new `*.simf` under `crates/contracts/<your_contract>/source_simf/`.
  2. Create argument and witness builders mirroring `options/build_arguments.rs` and `options/build_witness.rs`.
  3. Expose helpers to derive the address and finalize transactions.
  4. Add CLI subcommands that construct outputs in the order your covenant expects, then attach the appropriate Simplicity witness(es).

- Performance and UX
  - Transactions are explicit; Addresses are constantly reused; privacy is not a goal here.

## Safety and network notes

- Liquid testnet only. Explicit transactions leak amounts/assets by design here.
- Ensure UTXOs spent by the CLI belong to the derived P2TR address for the chosen `account-index`.
- Always verify the printed addresses and parameters match your expectations before broadcasting.
