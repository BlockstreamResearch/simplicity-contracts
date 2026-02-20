# Simplicity Contracts CLI

This crate provides `simplicity-cli`, a helper CLI for basic wallet flows and option-offer flows.

## Command Topology

- `basic ...`
- `option-offer ...`

`--network` is required for every command invocation.

Use `--help` at each level:

```bash
cargo run -p cli -- --help
cargo run -p cli -- --network testnet-liquid basic --help
cargo run -p cli -- --network testnet-liquid option-offer --help
```

Top-level command groups currently exposed:

- `basic`: address/balance/transfer/split/issue/reissue flows
- `option-offer`: create/import/export/exercise/withdraw/expiry flows

## Runtime Configuration

Current behavior:

- `--network` is required on every invocation.
  - supported: `liquid`, `testnet-liquid`, `localtest-liquid`
- `--mnemonic` is optional and also supports env var `MNEMONIC`.
- if mnemonic is not provided, a built-in test mnemonic is used.
- Esplora URL is derived from network in code (no env override in current build):
  - `liquid` -> `https://blockstream.info/liquid/api`
  - `testnet-liquid` -> `https://blockstream.info/liquidtestnet/api`
  - `localtest-liquid` -> `http://127.0.0.1:3001`
- wallet data dir defaults to `.cache/wallet` and can be overridden with `SIMPLICITY_CLI_WALLET_DATA_DIR`.

Example:

```bash
export MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
cargo run -p cli -- --network localtest-liquid basic address
```

## Local Store Behavior

Option-offer arguments are stored in `.cache/store`.

- `option-offer create` rejects duplicate keys.
- `option-offer import` overwrites existing keys.
- `option-offer export` reads by key.

Import/export examples:

```bash
cargo run -p cli -- --network testnet-liquid option-offer import \
  --option-offer-taproot-pubkey-gen <taproot-handle> \
  --encoded-option-offer-arguments <encoded-hex>

cargo run -p cli -- --network testnet-liquid option-offer export \
  --option-offer-taproot-pubkey-gen <taproot-handle>
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
