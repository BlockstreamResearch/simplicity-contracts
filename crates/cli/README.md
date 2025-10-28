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

## Example run:

```bash
cargo run -p cli -- options creation-option \
  --broadcast \
  --first-fee-utxo 4b9673c0034090120dee92122a87971b6b76b74e5a0c2787d0e2407c4fb774fb:1 \
  --second-fee-utxo 4b9673c0034090120dee92122a87971b6b76b74e5a0c2787d0e2407c4fb774fb:2 \
  --start-time 1760358546 \
  --expiry-time 1760358546 \
  --contract-size 20 \
  --asset-strike-price 2 \
  --collateral-amount 2000 \
  --target-asset-id-hex-be 38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5 \
  --account-index 0 \
  --fee-amount 100
```

options_taproot_pubkey_gen: 1a9058141ebe163ff26739beb2f2c297e59aeb0983bd1696bb3b5dd18812baac:0270e34efde3af793343554a45be7c11b2b7289a0abf568295f909f81caa6fdedf:tex1pyj9x7gghxxtex90cxzlderjt0v69hm9zlz7ezzjmpzu4v3nwhgpq7pdnpa
Broadcasted txid: https://liquid.network/testnet/tx/1b723210d29a7941aab47cbb6f2f08853fa08d32ed744bb384f4eaf5b905480e

-- Expiry test
options_taproot_pubkey_gen: ca0367f594007e3b918b1d6390960a01a5f7704ee7d8902cbfa301cb276bb4a0:02e7ce0bbe949c9afe1671543bf8e49039f23bea800d3c4a89f9097b6ec7654889:tex1pxjm067n88g5xckhpqkss0cjntm3v27dky0qqenh8wpqqkr8mwxfqsag4uk
Broadcasted txid: https://liquid.network/testnet/tx/d0d6d886386a19d5019d25a0eb7f0a19437996b85d70b688e1030f7d6eee8a36

-- Cancellation test
options_taproot_pubkey_gen: a69b166def4cae06313f0791bd5d20d20d671e56cb6606b6fde261e6c3f17676:02c082825f70e6dcd1f5368e30cc290bf58127cddb3f4a0e5db20d8efd2ba7c504:tex1pr2eec37d0stuflmjlw62hrhr0uppw0jfdy8qnr5s2al3na3jwjrq8ans2x
Broadcasted txid: https://liquid.network/testnet/tx/d97de05cd0d721fb1c4902eab84787a6c8cf245bcee4e3c18fa307d807d05ad9

```bash
cargo run -p cli -- options funding-option \
  --broadcast \
  --option-asset-utxo d97de05cd0d721fb1c4902eab84787a6c8cf245bcee4e3c18fa307d807d05ad9:0 \
  --grantor-asset-utxo d97de05cd0d721fb1c4902eab84787a6c8cf245bcee4e3c18fa307d807d05ad9:1 \
  --collateral-and-fee-utxo d97de05cd0d721fb1c4902eab84787a6c8cf245bcee4e3c18fa307d807d05ad9:2 \
  --option-taproot-pubkey-gen a69b166def4cae06313f0791bd5d20d20d671e56cb6606b6fde261e6c3f17676:02c082825f70e6dcd1f5368e30cc290bf58127cddb3f4a0e5db20d8efd2ba7c504:tex1pr2eec37d0stuflmjlw62hrhr0uppw0jfdy8qnr5s2al3na3jwjrq8ans2x \
  --collateral-amount 2000 \
  --account-index 0 \
  --fee-amount 205
```

Done: https://liquid.network/testnet/tx/24dbb9f54f8302eae4610257898c218ae96c9e72512fe887f03a693180e7f037
Done (expiry test): https://liquid.network/testnet/tx/ad7670fb7d7c6538eb2f2478243e3fd8672aa689c87656dcd615e66d74905288
Done (cancellation test): https://liquid.network/testnet/tx/f4d171ac050d177e46b3ca68b33e42394e594bda2cc908113fed80a8c57dd8d0

```bash
cargo run -p cli -- options exercise-option \
  --broadcast \
  --collateral-utxo 6dc876cd4f41d7de588fecc88da9c5be02f3bfd16c402c8f7f233863d4cb5af3:0 \
  --option-asset-utxo 6dc876cd4f41d7de588fecc88da9c5be02f3bfd16c402c8f7f233863d4cb5af3:3 \
  --asset-utxo 6dc876cd4f41d7de588fecc88da9c5be02f3bfd16c402c8f7f233863d4cb5af3:4 \
  --fee-utxo 6dc876cd4f41d7de588fecc88da9c5be02f3bfd16c402c8f7f233863d4cb5af3:5 \
  --option-taproot-pubkey-gen 1a9058141ebe163ff26739beb2f2c297e59aeb0983bd1696bb3b5dd18812baac:0270e34efde3af793343554a45be7c11b2b7289a0abf568295f909f81caa6fdedf:tex1pyj9x7gghxxtex90cxzlderjt0v69hm9zlz7ezzjmpzu4v3nwhgpq7pdnpa \
  --amount-to-burn 75 \
  --fee-amount 160 \
  --account-index 0
```

Done 1: https://liquid.network/testnet/tx/6dc876cd4f41d7de588fecc88da9c5be02f3bfd16c402c8f7f233863d4cb5af3
Done 2: https://liquid.network/testnet/tx/ced2be5ee885df4b6230676e5d6b51c4e810d15f2324bf845d93d80ade7d29bf (full)

```bash
cargo run -p cli -- options settlement-option \
  --broadcast \
  --target-asset-utxo 6dc876cd4f41d7de588fecc88da9c5be02f3bfd16c402c8f7f233863d4cb5af3:2 \
  --grantor-asset-utxo 91cb8282b61ac6fd2d4ed9973d8c3e6ddef31277a28022f68e30e8c743fd792b:2 \
  --fee-utxo 91cb8282b61ac6fd2d4ed9973d8c3e6ddef31277a28022f68e30e8c743fd792b:3 \
  --option-taproot-pubkey-gen 1a9058141ebe163ff26739beb2f2c297e59aeb0983bd1696bb3b5dd18812baac:0270e34efde3af793343554a45be7c11b2b7289a0abf568295f909f81caa6fdedf:tex1pyj9x7gghxxtex90cxzlderjt0v69hm9zlz7ezzjmpzu4v3nwhgpq7pdnpa \
  --grantor-token-amount-to-burn 25 \
  --fee-amount 150 \
  --account-index 0
```

Done 1: https://liquid.network/testnet/tx/935820952db0590c168fd12da86d3a9729889d12871ee0a20a57ff4d061a5c73
Done 2: https://liquid.network/testnet/tx/91cb8282b61ac6fd2d4ed9973d8c3e6ddef31277a28022f68e30e8c743fd792b (full 1)
Done 3: https://liquid.network/testnet/tx/edcf54badff020ab84c4be83c8020e4b44dcab954ba337aa4a9beb1568d1842a (full 2)

```bash
cargo run -p cli -- options expiry-option \
  --collateral-utxo a341cb1dbc256e2483ca9119852b0b4b3c2eb8f5d3bb9160785f4939733f3984:0 \
  --grantor-asset-utxo a341cb1dbc256e2483ca9119852b0b4b3c2eb8f5d3bb9160785f4939733f3984:3 \
  --fee-utxo a341cb1dbc256e2483ca9119852b0b4b3c2eb8f5d3bb9160785f4939733f3984:4 \
  --option-taproot-pubkey-gen ca0367f594007e3b918b1d6390960a01a5f7704ee7d8902cbfa301cb276bb4a0:02e7ce0bbe949c9afe1671543bf8e49039f23bea800d3c4a89f9097b6ec7654889:tex1pxjm067n88g5xckhpqkss0cjntm3v27dky0qqenh8wpqqkr8mwxfqsag4uk \
  --grantor-token-amount-to-burn 75 \
  --fee-amount 150 \
  --account-index 0 \
  --broadcast 
```

Done 1: https://liquid.network/testnet/tx/a341cb1dbc256e2483ca9119852b0b4b3c2eb8f5d3bb9160785f4939733f3984
Done 2: https://liquid.network/testnet/tx/4b9673c0034090120dee92122a87971b6b76b74e5a0c2787d0e2407c4fb774fb (full)

```bash 
cargo run -p cli -- options cancellation-option \
  --collateral-utxo 2e622e2b235324d2a5731793deb0d384a346ccab8226ac848b25f710fbe8b6b4:0 \
  --option-asset-utxo 2e622e2b235324d2a5731793deb0d384a346ccab8226ac848b25f710fbe8b6b4:4 \
  --grantor-asset-utxo 2e622e2b235324d2a5731793deb0d384a346ccab8226ac848b25f710fbe8b6b4:5 \
  --fee-utxo 2e622e2b235324d2a5731793deb0d384a346ccab8226ac848b25f710fbe8b6b4:6 \
  --option-taproot-pubkey-gen a69b166def4cae06313f0791bd5d20d20d671e56cb6606b6fde261e6c3f17676:02c082825f70e6dcd1f5368e30cc290bf58127cddb3f4a0e5db20d8efd2ba7c504:tex1pr2eec37d0stuflmjlw62hrhr0uppw0jfdy8qnr5s2al3na3jwjrq8ans2x \
  --amount-to-burn 65 \
  --fee-amount 150 \
  --account-index 0 \
  --broadcast
```

Done 1: https://liquid.network/testnet/tx/2e622e2b235324d2a5731793deb0d384a346ccab8226ac848b25f710fbe8b6b4
Done 2: https://liquid.network/testnet/tx/e469665ea2bfe6ad3741f19f74a87abf4757caca09f1b08ec40e5bda0565eea7 (full)
