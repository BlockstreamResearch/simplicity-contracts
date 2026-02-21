# wallet-abi-bindings

Standalone UniFFI bindings for the `wallet-abi` runtime.

## API

- `WalletAbiRuntime.fromMnemonic(mnemonic, network, esploraUrl, walletDataDir)`
- `WalletAbiRuntime.processTxCreateRequestJson(requestJson): String`
- `WalletAbiRuntime.network(): String`
- `defaultEsploraUrl(network): String`
- `extractRequestNetwork(requestJson): String`

Input payload is full `TxCreateRequest` JSON. Output is full `TxCreateResponse` JSON.

Runtime/business failures are returned as ABI error envelopes (`status=error`), while malformed
JSON and initialization failures are raised as `WalletAbiException`.
