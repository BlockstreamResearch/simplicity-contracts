# @simplicity-contracts/wallet-abi-sdk

TypeScript SDK for building `wallet-create-0.1` request payloads for `wallet-abi`.

## Install

```bash
bun add @simplicity-contracts/wallet-abi-sdk
```

## Usage

```ts
import {
  RuntimeBuilder,
  TX_CREATE_ABI_VERSION,
  TxCreateRequestBuilder,
  toWalletRequestJson,
} from "@simplicity-contracts/wallet-abi-sdk";

const runtime = new RuntimeBuilder()
  .addInput({
    id: "input0",
    utxo_source: {
      wallet: {
        filter: {
          asset: "none",
          amount: "none",
          lock: "none",
        },
      },
    },
    blinder: "wallet",
    sequence: 0xffffffff,
    finalizer: { type: "wallet" },
  })
  .addOutput({
    id: "recipient",
    amount_sat: 1000,
    lock: { type: "script", script: "51" },
    asset: {
      type: "asset_id",
      asset_id: "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
    },
    blinder: "explicit",
  })
  .setFeeRateSatVb(0.1);

const request = new TxCreateRequestBuilder({
  abi_version: TX_CREATE_ABI_VERSION,
  request_id: "request-1",
  network: "testnet-liquid",
  broadcast: false,
})
  .setRuntime(runtime)
  .build();

const walletJson = toWalletRequestJson(request);
```

## Development

```bash
bun install
bun run build
bun test
```

### Quality checks

```bash
bun run lint
bun run lint:fix
bun run format
bun run format:check
bun run check
```

### Regtest integration test

The SDK integration suite includes real generic wallet regtest flows (`bootstrap`, `transfer`, `split`, `issue`, `reissue`) driven from TypeScript.
It builds and submits typed `TxCreateRequest` payloads through a dedicated Rust harness crate
(`wallet-abi-regtest-harness`).

Set these environment variables before running it:

```bash
export ELEMENTSD_EXEC=/path/to/elementsd
export ELECTRS_LIQUID_EXEC=/path/to/electrs
```

Then run:

```bash
bun test test/integration/regtest-flows.test.ts
```
