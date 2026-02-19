# Simplicity Contracts CLI

This CLI executes contract branches through typed `wallet-abi` command builders.

## Command Topology

- `contract p2pk ...`
- `contract options ...`
- `contract option-offer ...`
- `state smt ...`
- `args import|export ...`

Use `--help` at each level.

## Quick Start

```bash
cargo run -p cli -- contract p2pk --help
cargo run -p cli -- contract options --help
cargo run -p cli -- contract option-offer --help
cargo run -p cli -- state smt --help
cargo run -p cli -- args --help
```

See `crates/cli/assets/example-run.md` for end-to-end command examples.

## Runtime Configuration

Set once and reused for all commands:

- `SIMPLICITY_CLI_MNEMONIC` (required)
- `SIMPLICITY_CLI_NETWORK` (default: `testnet-liquid`)
  - supported: `liquid`, `testnet-liquid`, `localtest-liquid`
- `SIMPLICITY_CLI_ESPLORA_URL` (default: Blockstream Liquid testnet Esplora)

For local regtest:

```bash
export SIMPLICITY_CLI_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
export SIMPLICITY_CLI_NETWORK=localtest-liquid
export SIMPLICITY_CLI_ESPLORA_URL=http://127.0.0.1:<esplora-port>
```

## UTXO Selection Model

Manual outpoint flags were removed from contract/state execution flows.

- signer wallet UTXOs are synced via wollet and used for fee/aux inputs
- covenant/script UTXOs are synced via script descriptors and auto-selected deterministically
- selection order is deterministic: highest value first, then `txid`, then `vout`
- signer/runtime derivation is fixed to account 0

## Arg Store Operations

`options` and `option-offer` commands use local encoded argument storage (`.cache/store`).

Options notes:
- `contract options fund` now requires both `--collateral-amount` and `--expected-asset-amount`.
- options arg entries persist explicit token-id fields (no outpoint/confidential fields).

```bash
cargo run -p cli -- args import \
  --contract option-offer \
  --taproot-pubkey-gen <taproot-name> \
  --encoded-hex <encoded-args-hex>

cargo run -p cli -- args export \
  --taproot-pubkey-gen <taproot-name>
```

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (Apache-2.0)
- MIT license (MIT)

at your option.
