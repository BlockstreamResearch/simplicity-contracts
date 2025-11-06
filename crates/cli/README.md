# Simplicity CLI (Liquid Testnet)

Small helper CLI to derive testnet addresses from a configured seed and to build explicit, signed Elements transactions for LBTC and assets (with optional broadcast).

## Setup

1. Add a `.env` file in the project root directory (or export env var). You can use `openssl rand -hex 32` to generate this value:

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

- Split LBTC into two outputs (same recipient)

```
cargo run -p cli -- basic split-native \
  --utxo <txid>:<vout> \
  --recipient-address <addr> \
  --send-sats <first_output_sats> \
  --fee-sats <fee> \
  --account-index 0
```

- Split LBTC into three outputs (same recipient)

```
cargo run -p cli -- basic split-native-three \
  --utxo <txid>:<vout> \
  --recipient-address <addr> \
  --send-sats <first_two_outputs_sats_each> \
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
- collateral-per-contract: amount of collateral asset per option token
- settlement-per-contract: amount of settlement asset per option token
- settlement-asset-id-hex-be: 32-byte hex asset id for the settlement asset (big-endian)
- account-index: key index for P2PK change/signing of issuance inputs
- fee-amount: LBTC miner fee

Example:
```
cargo run -p cli -- options creation-option \
  --first-fee-utxo <txid>:<vout> \
  --second-fee-utxo <txid>:<vout> \
  --start-time 1760358546 \
  --expiry-time 1760958546 \
  --collateral-per-contract 20 \
  --settlement-per-contract 2 \
  --settlement-asset-id-hex-be <32-byte-hex> \
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

Spend the collateral UTXO at the covenant, burn option tokens, and post the settlement asset back to the covenant.

Meaning of terms:
- collateral-utxo: LBTC collateral UTXO at the options address
- option-asset-utxo: option token UTXO to burn
- asset-utxo: settlement asset UTXO supplied by the option holder
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

### Options Settlement (grantor burns tokens against settlement asset)

Spend the settlement asset UTXO at the covenant, burn grantor tokens, forward the settlement amount back to the covenant, and pay fees from a P2PK LBTC UTXO.

Meaning of terms:
- settlement-asset-utxo: covenant UTXO holding the settlement asset
- grantor-asset-utxo: grantor token UTXO to burn
- fee-utxo: LBTC P2PK UTXO paying miner fee
- option-taproot-pubkey-gen: the covenant instance
- grantor-token-amount-to-burn: number of grantor tokens to burn
- fee-amount: LBTC miner fee
- account-index: P2PK account index for the fee input

Example:
```
cargo run -p cli -- options settlement-option \
  --settlement-asset-utxo <txid>:<vout> \
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

## DCD Commands

The DCD (Decentralized Collateralized Derivative) contract enables price-attested derivatives on Liquid Testnet.

### DCD Creation

Create a new DCD covenant by issuing three token types (filler, grantor collateral, grantor settlement) and storing the DCD arguments.

- Meaning of terms:
  - first-fee-utxo, second-fee-utxo, third-fee-utxo: Three LBTC UTXOs to use for token issuance
  - taker-funding-start-time: Block time when taker can start funding
  - taker-funding-end-time: Block time when taker funding period ends
  - contract-expiry-time: Block time when contract expires
  - early-termination-end-time: Block time when early termination is no longer allowed
  - settlement-height: Block height at which oracle price is attested
  - principal-collateral-amount: Base collateral amount
  - incentive-basis-points: Incentive in basis points (1 bp = 0.01%)
  - filler-per-principal-collateral: Filler token ratio
  - strike-price: Oracle strike price for settlement
  - settlement-asset-id: Asset ID (hex) for settlement
  - oracle-public-key: X-only pubkey of oracle
  - fee-amount: Transaction fee in satoshis
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo dcd-creation \
  --first-fee-utxo <txid>:<vout> \
  --second-fee-utxo <txid>:<vout> \
  --third-fee-utxo <txid>:<vout> \
  --taker-funding-start-time 1700000000 \
  --taker-funding-end-time 1700100000 \
  --contract-expiry-time 1700200000 \
  --early-termination-end-time 1700150000 \
  --settlement-height 1200000 \
  --principal-collateral-amount 1000000 \
  --incentive-basis-points 100 \
  --filler-per-principal-collateral 1000 \
  --strike-price 115000 \
  --settlement-asset-id <asset-id-hex> \
  --oracle-public-key <xonly-pubkey-hex> \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### DCD Import/Export

Persist or retrieve encoded DCD arguments for a given taproot pubkey gen in the local store.

- Import (bind encoded args to a `taproot-pubkey-gen`):

```
cargo run -p cli -- dcd-demo import \
  --taproot-pubkey-gen <taproot-pubkey-gen> \
  --encoded-dcd-arguments <hex>
```

- Export (print encoded args for a `taproot-pubkey-gen`):

```
cargo run -p cli -- dcd-demo export \
  --taproot-pubkey-gen <taproot-pubkey-gen>
```

### Oracle Signature

Generate a Schnorr signature for price attestation at settlement.

- Meaning of terms:
  - price-at-current-block-height: Oracle price to attest
  - settlement-height: Block height for settlement
  - oracle-account-index: Account index for oracle key

Example:
```
cargo run -p cli -- dcd-demo oracle-signature \
  --price-at-current-block-height 115000 \
  --settlement-height 1200000 \
  --oracle-account-index 2
```

### Merge Token UTXOs

Merge 2, 3, or 4 token UTXOs into a single UTXO. Useful for consolidating fragmented token holdings.

- Commands: `merge-2-tokens`, `merge-3-tokens`, `merge-4-tokens`
- Common parameters:
  - token-utxo-1, token-utxo-2, token-utxo-3, token-utxo-4: Token UTXOs to merge
  - fee-utxo: LBTC UTXO for transaction fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - fee-amount: Transaction fee in satoshis
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example (merging 2 tokens):
```
cargo run -p cli -- dcd-demo merge-2-tokens \
  --token-utxo-1 <txid>:<vout> \
  --token-utxo-2 <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Maker Funding Path

Maker deposits collateral and settlement assets, receives grantor tokens.

- Meaning of terms:
  - filler-token-utxo: Filler token UTXO for issuance
  - grantor-collateral-token-utxo: Grantor collateral token UTXO
  - grantor-settlement-token-utxo: Grantor settlement token UTXO
  - settlement-asset-utxo: Settlement asset UTXO to deposit
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - collateral-amount-to-deposit: Collateral amount to deposit
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo maker-funding-path \
  --filler-token-utxo <txid>:<vout> \
  --grantor-collateral-token-utxo <txid>:<vout> \
  --grantor-settlement-token-utxo <txid>:<vout> \
  --settlement-asset-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --collateral-amount-to-deposit 100000 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Taker Funding Path

Taker deposits collateral, receives filler tokens.

- Meaning of terms:
  - filler-token-utxo: Filler token UTXO from covenant
  - collateral-utxo: Collateral UTXO to deposit
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - collateral-amount-to-deposit: Collateral amount to deposit
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo taker-funding-path \
  --filler-token-utxo <txid>:<vout> \
  --collateral-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --collateral-amount-to-deposit 50000 \
  --fee-amount 500 \
  --account-index 1 \
  --broadcast
```

### Taker Early Termination

Taker returns filler tokens, gets collateral back before contract expiry.

- Meaning of terms:
  - collateral-utxo: Collateral UTXO at covenant
  - filler-token-utxo: Filler token UTXO to burn
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - filler-token-amount-to-return: Amount of filler tokens to return
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo taker-early-termination \
  --collateral-utxo <txid>:<vout> \
  --filler-token-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --filler-token-amount-to-return 1000 \
  --fee-amount 500 \
  --account-index 1 \
  --broadcast
```

### Maker Collateral Termination

Maker burns grantor collateral tokens, gets collateral back.

- Meaning of terms:
  - collateral-utxo: Collateral UTXO at covenant
  - grantor-collateral-token-utxo: Grantor collateral token UTXO to burn
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - grantor-collateral-amount-to-burn: Amount of grantor collateral tokens to burn
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo maker-collateral-termination \
  --collateral-utxo <txid>:<vout> \
  --grantor-collateral-token-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --grantor-collateral-amount-to-burn 1000 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Maker Settlement Termination

Maker burns grantor settlement tokens, gets settlement asset back.

- Meaning of terms:
  - settlement-asset-utxo: Settlement asset UTXO at covenant
  - grantor-settlement-token-utxo: Grantor settlement token UTXO to burn
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - grantor-settlement-amount-to-burn: Amount of grantor settlement tokens to burn
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo maker-settlement-termination \
  --settlement-asset-utxo <txid>:<vout> \
  --grantor-settlement-token-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --grantor-settlement-amount-to-burn 1000 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Maker Settlement

Maker settles at maturity based on oracle-attested price.

- Meaning of terms:
  - asset-utxo: Asset UTXO at covenant (collateral or settlement depending on price)
  - grantor-collateral-token-utxo: Grantor collateral token UTXO to burn
  - grantor-settlement-token-utxo: Grantor settlement token UTXO to burn
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - price-at-current-block-height: Oracle-attested price
  - oracle-signature: Schnorr signature from oracle
  - grantor-amount-to-burn: Amount of grantor tokens to burn
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo maker-settlement \
  --asset-utxo <txid>:<vout> \
  --grantor-collateral-token-utxo <txid>:<vout> \
  --grantor-settlement-token-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --price-at-current-block-height 115000 \
  --oracle-signature <hex> \
  --grantor-amount-to-burn 1000 \
  --fee-amount 500 \
  --account-index 0 \
  --broadcast
```

### Taker Settlement

Taker settles at maturity based on oracle-attested price.

- Meaning of terms:
  - asset-utxo: Asset UTXO at covenant (collateral or settlement depending on price)
  - filler-token-utxo: Filler token UTXO to burn
  - fee-utxo: LBTC UTXO for fees
  - dcd-taproot-pubkey-gen: DCD instance identifier
  - price-at-current-block-height: Oracle-attested price
  - oracle-signature: Schnorr signature from oracle
  - filler-amount-to-burn: Amount of filler tokens to burn
  - fee-amount: Transaction fee
  - account-index: Account index for signing
  - broadcast: When set, broadcast transaction

Example:
```
cargo run -p cli -- dcd-demo taker-settlement \
  --asset-utxo <txid>:<vout> \
  --filler-token-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --dcd-taproot-pubkey-gen <taproot-pubkey-gen> \
  --price-at-current-block-height 115000 \
  --oracle-signature <hex> \
  --filler-amount-to-burn 1000 \
  --fee-amount 500 \
  --account-index 1 \
  --broadcast
```

### Options

The Options contract and related CLI commands have moved to a separate repository and are no longer part of this CLI.

## Notes

- Addresses are Liquid testnet P2TR derived from SEED_HEX and index.
- UTXOs you spend must belong to the derived address at the specified account index.
- Transactions are explicit (unblinded), signed, and printed in raw hex (or broadcast when `--broadcast` is provided).
- To verify on the explorer, use the Liquid Testnet explorer (example tx):
  - https://blockstream.info/liquidtestnet/tx/3d55a1c411f4cd3b9cf1aac2fcabb1b7722c4ac314e78d2661fcd776fee35340?expand

OutPoint format note:

- An OutPoint is specified as `<txid>:<vout>`, where `<txid>` is hex and `<vout>` is a non-negative integer index.

## Example run:


```bash
cargo run -p cli -- basic split-native \
  --broadcast \
  --utxo 07ecfc3fb98db1693b2721c5efeea1a0bb348b4bc6ff4ef57526e9d5d8e4867f:3 \
  --recipient-address tex1pxztvg542emmh9h8txga43jcltt4uhphpt79lylqmlwrafzvcferq2qpdg9 \
  --send-sats 2000 \
  --fee-sats 50 \
  --account-index 0
```

Done: https://liquid.network/testnet/tx/0ebb7bbe4d2bd72d5bf12e5d65cf5e8816a821c7d9600bd6c8bf3a6d80b9f0ee

Done 2 (cancellation test): https://liquid.network/testnet/tx/0fb896c5620f9415172e02e48c98a3b27380398fe7af8d9d8c3ba974b55607dd

```bash
cargo run -p cli -- options creation-option \
  --broadcast \
  --first-fee-utxo 0fb896c5620f9415172e02e48c98a3b27380398fe7af8d9d8c3ba974b55607dd:0 \
  --second-fee-utxo 0fb896c5620f9415172e02e48c98a3b27380398fe7af8d9d8c3ba974b55607dd:1 \
  --start-time 1761821609 \
  --expiry-time 1761821609 \
  --collateral-per-contract 20 \
  --settlement-per-contract 5 \
  --settlement-asset-id-hex-be 38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5 \
  --account-index 0 \
  --fee-amount 100
```

options_taproot_pubkey_gen: 763d23b0bd02337bb267fa1282ae129cef814833e1456644afa3053b9031051f:027f8873a023e321ea3df56a0dcb098479030ee0be868f0f5fe6fba1da8d0bb9f9:tex1pt355pzatlmcxtuasd2rynd0wvmxh8l9g8y8kwk5fv7p0dckszd3sfwjnpv

Done: https://liquid.network/testnet/tx/fe3e22444adb80b5da75aa44cbf4ab52c6b3a6ecbfd9a010e2bc9bb81dfa2a26

options_taproot_pubkey_gen: 7efe3e23414653a1cf58cee8fed04113491ce002e225f28478733548dc51ec66:02b0a4727eefe4cae1748d20cc361b718d06b1bb5347b323ba1d71a617ee483933:tex1pahzvqxjle9zvdzf2gw3q86ps32hxet5tuy0zwdtys7zjg9s529jsf7ul2z

Done 2 (cancellation test): https://liquid.network/testnet/tx/6ca00f7cab1db9e7ed09e9fbc446c4fcc83074b67d83faa15a02510183793b02

```bash
cargo run -p cli -- options funding-option \
  --broadcast \
  --option-asset-utxo 6ca00f7cab1db9e7ed09e9fbc446c4fcc83074b67d83faa15a02510183793b02:0 \
  --grantor-asset-utxo 6ca00f7cab1db9e7ed09e9fbc446c4fcc83074b67d83faa15a02510183793b02:1 \
  --collateral-and-fee-utxo 6ca00f7cab1db9e7ed09e9fbc446c4fcc83074b67d83faa15a02510183793b02:2 \
  --option-taproot-pubkey-gen 7efe3e23414653a1cf58cee8fed04113491ce002e225f28478733548dc51ec66:02b0a4727eefe4cae1748d20cc361b718d06b1bb5347b323ba1d71a617ee483933:tex1pahzvqxjle9zvdzf2gw3q86ps32hxet5tuy0zwdtys7zjg9s529jsf7ul2z \
  --collateral-amount 2000 \
  --account-index 0 \
  --fee-amount 205
```

Done: https://liquid.network/testnet/tx/c71f1901a96d2f843eca628e595f97649a080668229d8800a2ca094051b77e5d

Done 2 (cancellation test): https://liquid.network/testnet/tx/9480d87d08f6dc8c4213548d159c40d5f93f5068e59c06e174e21a7d50a75dd2

```bash
cargo run -p cli -- options exercise-option \
  --broadcast \
  --collateral-utxo c71f1901a96d2f843eca628e595f97649a080668229d8800a2ca094051b77e5d:2 \
  --option-asset-utxo c71f1901a96d2f843eca628e595f97649a080668229d8800a2ca094051b77e5d:3 \
  --asset-utxo e8b5cc998d9fcc484cd6e0cf3768ca4dbd7376d8839f18599f9f000c1b9e0bd6:0 \
  --fee-utxo c71f1901a96d2f843eca628e595f97649a080668229d8800a2ca094051b77e5d:5 \
  --option-taproot-pubkey-gen 763d23b0bd02337bb267fa1282ae129cef814833e1456644afa3053b9031051f:027f8873a023e321ea3df56a0dcb098479030ee0be868f0f5fe6fba1da8d0bb9f9:tex1pt355pzatlmcxtuasd2rynd0wvmxh8l9g8y8kwk5fv7p0dckszd3sfwjnpv \
  --amount-to-burn 75 \
  --fee-amount 165 \
  --account-index 0
```

Done: https://liquid.network/testnet/tx/ceea050ab1da532ce4e60241eb948cc4a2ffaec8a320c494dc460ed75b376aae

```bash
cargo run -p cli -- options settlement-option \
  --broadcast \
  --settlement-asset-utxo ceea050ab1da532ce4e60241eb948cc4a2ffaec8a320c494dc460ed75b376aae:2 \
  --grantor-asset-utxo c71f1901a96d2f843eca628e595f97649a080668229d8800a2ca094051b77e5d:4 \
  --fee-utxo ceea050ab1da532ce4e60241eb948cc4a2ffaec8a320c494dc460ed75b376aae:5 \
  --option-taproot-pubkey-gen 763d23b0bd02337bb267fa1282ae129cef814833e1456644afa3053b9031051f:027f8873a023e321ea3df56a0dcb098479030ee0be868f0f5fe6fba1da8d0bb9f9:tex1pt355pzatlmcxtuasd2rynd0wvmxh8l9g8y8kwk5fv7p0dckszd3sfwjnpv \
  --grantor-token-amount-to-burn 25 \
  --fee-amount 150 \
  --account-index 0
```

Done: https://liquid.network/testnet/tx/4e07ca1481d6e8b39c29c89e784f436333e50596288af5f65f9a7151c5b8e19c

```bash
cargo run -p cli -- options expiry-option \
  --collateral-utxo ceea050ab1da532ce4e60241eb948cc4a2ffaec8a320c494dc460ed75b376aae:0 \
  --grantor-asset-utxo 4e07ca1481d6e8b39c29c89e784f436333e50596288af5f65f9a7151c5b8e19c:3 \
  --fee-utxo 4e07ca1481d6e8b39c29c89e784f436333e50596288af5f65f9a7151c5b8e19c:4 \
  --option-taproot-pubkey-gen 763d23b0bd02337bb267fa1282ae129cef814833e1456644afa3053b9031051f:027f8873a023e321ea3df56a0dcb098479030ee0be868f0f5fe6fba1da8d0bb9f9:tex1pt355pzatlmcxtuasd2rynd0wvmxh8l9g8y8kwk5fv7p0dckszd3sfwjnpv \
  --grantor-token-amount-to-burn 25 \
  --fee-amount 150 \
  --account-index 0 \
  --broadcast 
```

Done: https://liquid.network/testnet/tx/07ecfc3fb98db1693b2721c5efeea1a0bb348b4bc6ff4ef57526e9d5d8e4867f

```bash 
cargo run -p cli -- options cancellation-option \
  --collateral-utxo 9480d87d08f6dc8c4213548d159c40d5f93f5068e59c06e174e21a7d50a75dd2:2 \
  --option-asset-utxo 9480d87d08f6dc8c4213548d159c40d5f93f5068e59c06e174e21a7d50a75dd2:3 \
  --grantor-asset-utxo 9480d87d08f6dc8c4213548d159c40d5f93f5068e59c06e174e21a7d50a75dd2:4 \
  --fee-utxo 9480d87d08f6dc8c4213548d159c40d5f93f5068e59c06e174e21a7d50a75dd2:5 \
  --option-taproot-pubkey-gen 7efe3e23414653a1cf58cee8fed04113491ce002e225f28478733548dc51ec66:02b0a4727eefe4cae1748d20cc361b718d06b1bb5347b323ba1d71a617ee483933:tex1pahzvqxjle9zvdzf2gw3q86ps32hxet5tuy0zwdtys7zjg9s529jsf7ul2z \
  --amount-to-burn 100 \
  --fee-amount 150 \
  --account-index 0 \
  --broadcast
```

Done: https://liquid.network/testnet/tx/86c10905302c54812af0bbcae917b6458a1108ef0292634eaa1dbb9340aa870f
