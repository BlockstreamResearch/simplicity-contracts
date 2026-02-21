# wallet-abi-transport

Shared Wallet ABI transport types and codecs.

## Includes

- `wa_v1` / `wa_resp_v1` transport envelope types and codec helpers.
- `wa_relay_v1` pairing payload types and codec helpers.
- Relay websocket frame models (`auth`, `publish`, `ack`, `deliver`, `status`).
- End-to-end relay crypto helpers:
  - HKDF-SHA256 directional key derivation
  - XChaCha20-Poly1305 encryption/decryption
