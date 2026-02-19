## Example Run (Contract-First CLI)

Set environment once:

```bash
export SIMPLICITY_CLI_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
export SIMPLICITY_CLI_NETWORK=localtest-liquid
export SIMPLICITY_CLI_ESPLORA_URL=http://127.0.0.1:<esplora-port>
```

All contract/state commands now auto-select required UTXOs from synced wollets:

- signer wallet sync for fee/aux inputs
- contract script sync for covenant inputs

### P2PK/basic

```bash
cargo run -p cli -- contract p2pk transfer-native \
  --to-address <recipient-address> \
  --send-sats 1234 \
  --fee-sats 100 \
  --broadcast
```

```bash
cargo run -p cli -- contract p2pk issue-asset \
  --asset-name test-asset \
  --issue-sats 100000 \
  --fee-sats 100 \
  --broadcast
```

### Options

```bash
cargo run -p cli -- contract options create \
  --start-time 0 \
  --expiry-time 0 \
  --collateral-per-contract 10 \
  --settlement-per-contract 20 \
  --settlement-asset-id-hex-be <asset-id> \
  --collateral-asset-id-hex-be <asset-id> \
  --broadcast
```

```bash
cargo run -p cli -- contract options fund \
  --option-taproot-pubkey-gen <taproot-name> \
  --collateral-amount 100 \
  --expected-asset-amount 10 \
  --broadcast
```

```bash
cargo run -p cli -- contract options exercise \
  --option-taproot-pubkey-gen <taproot-name> \
  --amount-to-burn 10 \
  --broadcast
```

### Option-offer

Import args first:

```bash
cargo run -p cli -- args import \
  --contract option-offer \
  --taproot-pubkey-gen <taproot-name> \
  --encoded-hex <option-offer-args-hex>
```

```bash
cargo run -p cli -- contract option-offer deposit \
  --collateral-amount 10 \
  --premium-amount 30 \
  --option-offer-taproot-pubkey-gen <taproot-name> \
  --broadcast
```

```bash
cargo run -p cli -- contract option-offer exercise \
  --option-offer-taproot-pubkey-gen <taproot-name> \
  --collateral-amount 10 \
  --broadcast
```

```bash
cargo run -p cli -- contract option-offer withdraw \
  --option-offer-taproot-pubkey-gen <taproot-name> \
  --broadcast
```

```bash
cargo run -p cli -- contract option-offer expiry \
  --option-offer-taproot-pubkey-gen <taproot-name> \
  --broadcast
```

### State (SMT)

```bash
cargo run -p cli -- state smt get-storage-address \
  --storage-bytes <64-hex> \
  --path llllllll
```

```bash
cargo run -p cli -- state smt transfer-from-storage-address \
  --storage-bytes <current-64-hex> \
  --changed-bytes <new-64-hex> \
  --path llllllll \
  --broadcast
```
