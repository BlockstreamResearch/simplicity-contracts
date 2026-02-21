# wallet-abi-relayer

Production-grade local Wallet ABI websocket relayer.

## Endpoints

- `POST /v1/pairings`
- `GET /v1/pairings/{pairing_id}`
- `DELETE /v1/pairings/{pairing_id}`
- `GET /v1/healthz`
- `GET /v1/ws`

## Environment Variables

- `WALLET_ABI_RELAYER_BIND_ADDR` (default: `127.0.0.1:8787`)
- `WALLET_ABI_RELAYER_DB_PATH` (default: `.cache/wallet-abi-relayer/relayer.sqlite3`)
- `WALLET_ABI_RELAYER_PUBLIC_WS_URL` (default: `ws://127.0.0.1:8787/v1/ws`)
- `WALLET_ABI_RELAYER_HMAC_SECRET` (default local-dev fallback)
- `WALLET_ABI_RELAYER_MAX_TTL_MS` (default: `120000`)
- `WALLET_ABI_RELAYER_JANITOR_INTERVAL_MS` (default: `30000`)
- `WALLET_ABI_RELAYER_EVENT_RETENTION_MS` (default: `86400000`)
- `WALLET_ABI_RELAYER_TLS_CERT_PATH` (required for `wss://`)
- `WALLET_ABI_RELAYER_TLS_KEY_PATH` (required for `wss://`)

## Security Policy

- `ws://` is accepted only for local/private hosts.
- `wss://` is required for non-local hosts.
- Tokens are HMAC-SHA256 signed and role-bound.
- Relay stores and routes ciphertext only.
