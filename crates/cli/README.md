# Simplicity CLI (Liquid Testnet)

Small helper CLI to derive testnet addresses from a configured seed and to build explicit, signed Elements transactions for LBTC and assets (with optional broadcast).

## Setup

1. Add a `.env` file in this crate directory (or export env var):

```
SEED_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

- SEED_HEX must be 32-byte hex.

2. Build/run:

```
cargo run -p cli -- --help
```

## Commands

- Address by index

```
cargo run -p cli -- basic address 0
```

- Transfer LBTC (native; build raw tx hex and optionally broadcast)

Meaning of terms:
- utxo: OutPoint of the LBTC UTXO to spend (format: <txid>:<vout>)
- to-address: Liquid testnet recipient address (tlq1...)
- send-sats: amount to send in satoshis
- fee-sats: miner fee in satoshis (separate fee output)
- account-index: which derived account index to use for change and signing (default 0)

Examples:
```
cargo run -p cli -- basic transfer-native \
  --utxo 0123...cdef:0 \
  --to-address tlq1qq...xyz \
  --send-sats 150000 \
  --fee-sats 500 \
  --account-index 0 \
  --broadcast
```

- Split LBTC into two recipients

```
cargo run -p cli -- basic split-native \
  --utxo <txid>:<vout> \
  --first-to-address <addr1> \
  --first-sats <sats1> \
  --second-to-address <addr2> \
  --second-sats <sats2> \
  --fee-sats <fee> \
  --account-index 0
```

- Transfer Asset (LBTC pays fee; build raw tx hex and optionally broadcast)

Meaning of terms:
- asset-utxo: OutPoint of the ASSET UTXO to spend (format: <txid>:<vout>)
- fee-utxo: OutPoint of the LBTC UTXO used to pay fees (format: <txid>:<vout>)
- to-address: Liquid testnet recipient address (tlq1...)
- send-sats: amount of the asset to send (asset's smallest units)
- fee-sats: LBTC fee in satoshis (separate fee output)
- account-index: which derived account index to use for change and signing (default 0)

Notes:
- Both the ASSET UTXO and the LBTC FEE UTXO must be controlled by the P2TR address returned by `address <account-index>`.
- The asset id is derived from the ASSET UTXO; it must be explicit (unblinded).
- The CLI fetches transactions from the Liquid Testnet explorer to determine input values.
- Transactions are explicit (unblinded), signed using the derived P2TR key(s), and printed in raw hex by default. To broadcast directly via Esplora, add `--broadcast`.

Examples:
```
cargo run -p cli -- basic transfer-asset \
  --asset-utxo 89ab...7654:1 \
  --fee-utxo 0123...abcd:0 \
  --to-address tlq1qq...xyz \
  --send-sats 250 \
  --fee-sats 500 \
  --account-index 0 \
  --broadcast
```

### Options Import/Export

Persist or retrieve encoded Options arguments for a given options taproot pubkey gen in the local store.

- Import (bind encoded args to an `option-taproot-pubkey-gen`):

```
cargo run -p cli -- options import \
  --option-taproot-pubkey-gen <taproot-pubkey-gen> \
  --encoded-options-arguments <hex>
```

- Export (print encoded args for an `option-taproot-pubkey-gen`):

```
cargo run -p cli -- options export \
  --option-taproot-pubkey-gen <taproot-pubkey-gen>
```

Print help:
```
cargo run -p cli -- options import --help
cargo run -p cli -- options export --help
```

### Options Creation (mint reissuance tokens and derive address)

Build and sign an issuance transaction that mints two reissuance tokens (option and grantor), persists entropies for funding, stores the instantiated arguments, and prints the options Taproot pubkey gen string.

Meaning of terms:
- first-fee-utxo / second-fee-utxo: LBTC UTXOs to fund issuances and fees
- start-time / expiry-time: UNIX seconds used by the covenant
- contract-size: units of collateral per option token
- asset-strike-price: target asset per unit of collateral
- collateral-amount: total collateral to be posted at funding time (used to derive internal prices)
- target-asset-id-hex-be: 32-byte hex asset id for the target asset (big-endian)
- account-index: key index for P2PK change/signing of issuance inputs
- fee-amount: LBTC miner fee

Example:
```
cargo run -p cli -- options creation-option \
  --first-fee-utxo <txid>:<vout> \
  --second-fee-utxo <txid>:<vout> \
  --start-time 1760358546 \
  --expiry-time 1760958546 \
  --contract-size 20 \
  --asset-strike-price 2 \
  --collateral-amount 1000 \
  --target-asset-id-hex-be <32-byte-hex> \
  --account-index 0 \
  --fee-amount 500 \
  --broadcast
```

### Options Funding (reissue tokens to covenant and lock collateral)

Move both reissuance tokens forward to the options address, deposit collateral LBTC, return base assets as change, and attach Simplicity witnesses for both token inputs.

Meaning of terms:
- option-asset-utxo / grantor-asset-utxo: UTXOs holding the reissuance tokens minted in creation
- collateral-and-fee-utxo: LBTC UTXO paying collateral and fees
- option-taproot-pubkey-gen: string printed by creation; identifies the covenant instance
- collateral-amount: total LBTC collateral to lock
- fee-amount: LBTC miner fee
- account-index: key index for P2PK change/signing of collateral input

Example:
```
cargo run -p cli -- options funding-option \
  --option-asset-utxo <txid>:<vout> \
  --grantor-asset-utxo <txid>:<vout> \
  --collateral-and-fee-utxo <txid>:<vout> \
  --option-taproot-pubkey-gen <taproot-pubkey-gen> \
  --collateral-amount 1000 \
  --account-index 0 \
  --fee-amount 500 \
  --broadcast
```

### Options Exercise (option holder burns options and settles)

Spend the collateral UTXO at the covenant, burn option tokens, and post the settlement target asset back to the covenant.

Meaning of terms:
- collateral-utxo: LBTC collateral UTXO at the options address
- option-asset-utxo: option token UTXO to burn
- asset-utxo: target asset UTXO to supply settlement asset
- fee-utxo: LBTC P2PK UTXO paying miner fee
- option-taproot-pubkey-gen: the covenant instance
- amount-to-burn: number of option tokens to burn
- fee-amount: LBTC miner fee
- account-index: P2PK account index for signing P2PK inputs (token/asset/fee)

Example:
```
cargo run -p cli -- options exercise-option \
  --collateral-utxo <txid>:<vout> \
  --option-asset-utxo <txid>:<vout> \
  --asset-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --option-taproot-pubkey-gen <taproot-pubkey-gen> \
  --amount-to-burn 25 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Options Settlement (grantor burns tokens against target asset)

Spend the target asset UTXO at the covenant, burn grantor tokens, forward the settlement amount in target asset back to the covenant, and pay fees from a P2PK LBTC UTXO.

Meaning of terms:
- target-asset-utxo: covenant UTXO holding the target asset
- grantor-asset-utxo: grantor token UTXO to burn
- fee-utxo: LBTC P2PK UTXO paying miner fee
- option-taproot-pubkey-gen: the covenant instance
- grantor-token-amount-to-burn: number of grantor tokens to burn
- fee-amount: LBTC miner fee
- account-index: P2PK account index for the fee input

Example:
```
cargo run -p cli -- options settlement-option \
  --target-asset-utxo <txid>:<vout> \
  --grantor-asset-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --option-taproot-pubkey-gen <taproot-pubkey-gen> \
  --grantor-token-amount-to-burn 10 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Options Expiry (grantor burns tokens to withdraw collateral)

Spend the collateral UTXO at the covenant, burn grantor tokens, withdraw the corresponding collateral to a P2PK recipient, and deduct fees from the collateral input.

Meaning of terms:
- collateral-utxo: LBTC collateral UTXO at the options address
- grantor-asset-utxo: grantor token UTXO to burn
- option-taproot-pubkey-gen: the covenant instance
- grantor-token-amount-to-burn: number of grantor tokens to burn
- fee-amount: LBTC miner fee (deducted from collateral input)
- account-index: P2PK account index for the recipient

Example:
```
cargo run -p cli -- options expiry-option \
  --collateral-utxo <txid>:<vout> \
  --grantor-asset-utxo <txid>:<vout> \
  --option-taproot-pubkey-gen <taproot-pubkey-gen> \
  --grantor-token-amount-to-burn 25 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Options Cancellation (both tokens burn, partial collateral withdrawal)

Spend the collateral UTXO at the covenant, burn both option and grantor tokens, withdraw a portion of collateral to a P2PK recipient, and deduct fees from the collateral input.

Meaning of terms:
- collateral-utxo: LBTC collateral UTXO at the options address
- option-asset-utxo: option token UTXO to burn
- grantor-asset-utxo: grantor token UTXO to burn
- option-taproot-pubkey-gen: the covenant instance
- amount-to-burn: number of both tokens to burn
- fee-amount: LBTC miner fee (deducted from collateral input)
- account-index: P2PK account index for the recipient

Example:
```
cargo run -p cli -- options cancellation-option \
  --collateral-utxo <txid>:<vout> \
  --option-asset-utxo <txid>:<vout> \
  --grantor-asset-utxo <txid>:<vout> \
  --option-taproot-pubkey-gen <taproot-pubkey-gen> \
  --amount-to-burn 25 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

## Notes

- Addresses are Liquid testnet P2TR derived from SEED_HEX and index.
- UTXOs you spend must belong to the derived address at the specified account index.
- Transactions are explicit (unblinded), signed, and printed in raw hex (or broadcast when `--broadcast` is provided).
- To verify on the explorer, use the Liquid Testnet explorer (example tx):
  - https://blockstream.info/liquidtestnet/tx/3d55a1c411f4cd3b9cf1aac2fcabb1b7722c4ac314e78d2661fcd776fee35340?expand

OutPoint format note:

- An OutPoint is specified as `<txid>:<vout>`, where `<txid>` is hex and `<vout>` is a non-negative integer index.
