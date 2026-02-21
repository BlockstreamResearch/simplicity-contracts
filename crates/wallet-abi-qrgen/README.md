# wallet-abi-qrgen

`wallet-abi-qrgen` generates Wallet-ABI `wa_v1` request QR codes for common transaction-create flows.

## What it does

For each request command it produces:

1. A deep link containing `#wa_v1=<base64url(zstd(json))>`.
2. A PNG QR code that can be scanned by the mobile app.
3. A terminal text QR.
4. JSON artifacts for debugging.

## Usage

Simple transfer:

```bash
cargo run -p wallet-abi-qrgen -- simple-transfer \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --amount-sat 1000 \
  --request-id req-demo-1
```

Split transfer (multiple equal outputs):

```bash
cargo run -p wallet-abi-qrgen -- split-transfer \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --split-parts 3 \
  --part-amount-sat 500 \
  --request-id req-demo-split
```

New asset issuance:

```bash
cargo run -p wallet-abi-qrgen -- issue-asset \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --issue-amount-sat 5000 \
  --token-amount-sat 1 \
  --issuance-entropy-hex 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
  --request-id req-demo-issue
```

Asset reissuance:

```bash
cargo run -p wallet-abi-qrgen -- reissue-asset \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --reissue-token-asset-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --reissue-amount-sat 2000 \
  --asset-entropy-hex 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 \
  --token-change-sat 1 \
  --request-id req-demo-reissue
```

Decode copied app response payload (`wa_resp_v1`) back to JSON:

```bash
cargo run -p wallet-abi-qrgen -- parse-payload '<COPIED_WA_RESP_V1_PAYLOAD>'
```

You can also pass a full callback URL:

```bash
cargo run -p wallet-abi-qrgen -- parse-payload 'https://dapp.example/callback#wa_resp_v1=...'
```

Relay-first connect flow (`wa_relay_v1`):

```bash
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  simple-transfer \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --amount-sat 1000 \
  --request-id req-relay-1
```

`relay-connect` behavior:

1. Creates pairing on the relay via `POST /v1/pairings`.
2. Prints a connection QR containing only `#wa_relay_v1=...`.
3. Waits for phone connect (`peer_connected`) then sends encrypted request over websocket.
4. Waits for encrypted response, decrypts it locally, prints pretty JSON, and exits.
5. Best-effort cleanup via `DELETE /v1/pairings/{pairing_id}`.

Relay option-offer create (relay-only):

```bash
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  option-offer create \
  --collateral-asset-id 1111111111111111111111111111111111111111111111111111111111111111 \
  --premium-asset-id 2222222222222222222222222222222222222222222222222222222222222222 \
  --settlement-asset-id 3333333333333333333333333333333333333333333333333333333333333333 \
  --expected-to-deposit-collateral 10000 \
  --expected-to-deposit-premium 500 \
  --expected-to-get-settlement 20000 \
  --expiry-time 1767139200 \
  --user-xonly-pubkey-hex 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  --request-id req-relay-option-create
```

Relay option-offer follow-ups:

```bash
# exercise (auto-resolve covenant balances from Esplora if overrides omitted)
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  option-offer exercise \
  --option-offer-taproot-pubkey-gen '<TAPROOT_HANDLE>' \
  --creation-txid '<CREATION_TXID>' \
  --collateral-amount 1000 \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --request-id req-relay-option-exercise

# withdraw (auto-resolve settlement output from exercise tx if overrides omitted)
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  option-offer withdraw \
  --option-offer-taproot-pubkey-gen '<TAPROOT_HANDLE>' \
  --exercise-txid '<EXERCISE_TXID>' \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --request-id req-relay-option-withdraw

# expiry (auto-resolve collateral/premium from creation tx if overrides omitted)
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  option-offer expiry \
  --option-offer-taproot-pubkey-gen '<TAPROOT_HANDLE>' \
  --creation-txid '<CREATION_TXID>' \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --request-id req-relay-option-expiry
```

Option-offer state import/export (hybrid explicit + local lookup):

```bash
cargo run -p wallet-abi-qrgen -- option-offer-state import \
  --network testnet-liquid \
  --option-offer-taproot-pubkey-gen '<TAPROOT_HANDLE>' \
  --encoded-option-offer-arguments '<HEX_ARGS>'

cargo run -p wallet-abi-qrgen -- option-offer-state export \
  --option-offer-taproot-pubkey-gen '<TAPROOT_HANDLE>'
```

Lifecycle reference:

1. `relay-connect option-offer create` creates request + QR, auto-persists `{taproot_handle -> args}` in local store.
2. App approves and processes create request over relay.
3. Follow with `exercise`, then `withdraw` or `expiry`; each may use explicit `--encoded-option-offer-arguments` or local store lookup.

### Relay E2E (Android)

Emulator (`10.0.2.2`):

```bash
# terminal A
cd /Users/inter/Desktop/Simpl/simplicity-contracts
export WALLET_ABI_RELAYER_BIND_ADDR=0.0.0.0:8787
export WALLET_ABI_RELAYER_PUBLIC_WS_URL=ws://10.0.2.2:8787/v1/ws
cargo run -p wallet-abi-relayer

# terminal B
cd /Users/inter/Desktop/Simpl/simplicity-contracts
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  simple-transfer \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --amount-sat 1000 \
  --request-id req-relay-e2e-emulator
```

Physical device (`adb reverse`):

```bash
adb reverse tcp:8787 tcp:8787

# terminal A
cd /Users/inter/Desktop/Simpl/simplicity-contracts
export WALLET_ABI_RELAYER_BIND_ADDR=0.0.0.0:8787
export WALLET_ABI_RELAYER_PUBLIC_WS_URL=ws://127.0.0.1:8787/v1/ws
cargo run -p wallet-abi-relayer

# terminal B
cd /Users/inter/Desktop/Simpl/simplicity-contracts
cargo run -p wallet-abi-qrgen -- relay-connect \
  --relay-http-url http://127.0.0.1:8787 \
  simple-transfer \
  --to-address tlq1qq02egjncr8g4qn890mrw3jhgupwqymekv383lwpmsfghn36hac5ptpmeewtnftluqyaraa56ung7wf47crkn5fjuhk422d68m \
  --amount-sat 1000 \
  --request-id req-relay-e2e-device
```

Defaults:

- `--network testnet-liquid`
- `--callback-mode qr_roundtrip`
- `--origin https://dapp.example`
- `--base-link https://blockstream.com/walletabi/request`
- `--ttl-ms 120000`
- `--out-dir .cache/wallet-abi-qrgen`
- `relay-connect --relay-http-url http://127.0.0.1:8787`
- `relay-connect --wait-timeout-ms 180000`
- `option-offer-state --store-path .cache/store` (default when omitted)

## Artifacts

For request id `req-demo-1`, files are written to `--out-dir`:

- `req-demo-1.tx_create_request.json`
- `req-demo-1.transport_request.json`
- `req-demo-1.deep_link.txt`
- `req-demo-1.qr.png`

For relay connect request id `req-relay-1`, files are written to `--out-dir`:

- `req-relay-1.tx_create_request.json`
- `req-relay-1.relay_pairing.json`
- `req-relay-1.relay_deep_link.txt`
- `req-relay-1.relay_qr.png`
- `req-relay-1.relay_response.json` (written on successful roundtrip)
- `req-relay-1.option_offer_ref.json` (create flow only: taproot handle + encoded args + derived terms)
