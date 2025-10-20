## Simple Storage (Simplicity program)

Minimal stateful asset-based storage using a single covenant UTXO and a reissuance token. 
The covenant enforces that only the bound owner key can update the stored value and that the asset/value transition is valid.

### Contract summary

- **State asset (slot)**: An issued asset representing the storage slot. 
The UTXO at the covenant holds an explicit amount equal to the stored value.
- **Reissuance token**: A token enabling minting additional slot units when increasing the stored value.
- **Owner authorization**: Updates require a Schnorr signature by the bound owner `USER` over `sig_all_hash`.
- **Invariant**: Input and output at the same index must have identical script hashes (enforces staying at the covenant address); output[0] must carry the slot asset with the new value.
- **Burn vs. mint**:
  - Decrease: burns the difference as an OP_RETURN output with the same slot asset.
  - Increase: requires a reissuance input and enforces a second covenant output at the next index.

### Program parameters and witness

- `param::SLOT_ID` (u256): Asset id (explicit) of the slot asset.
- `param::USER` (Pubkey): X-only public key that authorizes updates.
- `witness::NEW_VALUE` (u64): Desired new stored value.
- `witness::USER_SIGNATURE` (Signature): Schnorr signature over `sig_all_hash` by `USER`.

### Output ordering enforced

Given the input index `i` of the covenant UTXO:
1. `output[i]`: covenant UTXO, script unchanged, carries `SLOT_ID` with `NEW_VALUE`.
2. If decreasing (burn path): `output[i+1]`: OP_RETURN carrying `SLOT_ID` with the burned amount.
3. If increasing (mint path): `input[i+1]` is the reissuance token; `output[i+1]` is a covenant output with identical script (reissuance path consistency check).

### CLI flows

Initialization (issue slot asset and reissuance token, bind arguments, deposit fee/change):

```bash
cargo run -p cli -- storage init-state \
  --fee-utxo <txid>:<vout> \
  --account-index 0 \
  --fee-amount 100 \
  --broadcast
```

Update value (mint/burn depending on delta):

```bash
cargo run -p cli -- storage update-state \
  --storage-utxo <txid>:<vout> \
  --reissuance-token-utxo <txid>:<vout> \
  --fee-utxo <txid>:<vout> \
  --account-index 0 \
  --taproot-pubkey-gen <taproot-pubkey-gen> \
  --new-value <u64> \
  --fee-amount 150 \
  --broadcast
```

Notes:
- For decreases, the reissuance token UTXO is not required, and the program enforces a burn OP_RETURN output.
- For increases, a blinded reissuance is performed using the stored entropy and token ABF; the program checks the covenant script for the reissuance output index.
- Transactions are explicit (unblinded) except reissuance token handling which uses standard Elements blinding fields for correctness.

### Sharing data 

Storage import/export of encoded arguments:
```
cargo run -p cli -- storage import  --help
cargo run -p cli -- storage export  --help
```

## Example run 

```bash
cargo run -p cli -- storage init-state \
  --fee-utxo 9d1a2acf1c8c1ca3d04cb748c8df312ef73ba9f1b43fc63bbc6a904c9ce56c69:2 \
  --account-index 0 \
  --fee-amount 100 \
  --broadcast
```

taproot_pubkey_gen: c04071aeac390978291487bc8366f8d472f7313940a66d30b4dd33323ef20aff:02c16e18dc7602f649b5df82a2c56d2c6b1c3bdfc4a966302df4ea3bada155c5d9:tex1p82s73je29drd9pquyc9pp0r8elh0ktwhnxkmnwsvzm0h57g4x6qqrkf3rz
Broadcasted txid: https://liquid.network/testnet/tx/7b329ede411ee585d62829b28d2cb000fd045cdd5ed871e2bcc8172b058cbb52

```bash 
cargo run -p cli -- storage update-state \
  --storage-utxo 7b329ede411ee585d62829b28d2cb000fd045cdd5ed871e2bcc8172b058cbb52:0 \
  --reissuance-token-utxo 7b329ede411ee585d62829b28d2cb000fd045cdd5ed871e2bcc8172b058cbb52:1 \
  --fee-utxo 7b329ede411ee585d62829b28d2cb000fd045cdd5ed871e2bcc8172b058cbb52:2 \
  --account-index 0 \
  --taproot-pubkey-gen c04071aeac390978291487bc8366f8d472f7313940a66d30b4dd33323ef20aff:02c16e18dc7602f649b5df82a2c56d2c6b1c3bdfc4a966302df4ea3bada155c5d9:tex1p82s73je29drd9pquyc9pp0r8elh0ktwhnxkmnwsvzm0h57g4x6qqrkf3rz \
  --new-value 558822 \
  --fee-amount 150 \
  --broadcast
```

Broadcasted txid: https://liquid.network/testnet/tx/045f5fb3c96ebbcbcf72f85374834cf7386cb617b53e0733c816cab93e99897d


```bash 
cargo run -p cli -- storage update-state \
  --storage-utxo 045f5fb3c96ebbcbcf72f85374834cf7386cb617b53e0733c816cab93e99897d:0 \
  --reissuance-token-utxo 045f5fb3c96ebbcbcf72f85374834cf7386cb617b53e0733c816cab93e99897d:1 \
  --fee-utxo 045f5fb3c96ebbcbcf72f85374834cf7386cb617b53e0733c816cab93e99897d:2 \
  --account-index 0 \
  --taproot-pubkey-gen c04071aeac390978291487bc8366f8d472f7313940a66d30b4dd33323ef20aff:02c16e18dc7602f649b5df82a2c56d2c6b1c3bdfc4a966302df4ea3bada155c5d9:tex1p82s73je29drd9pquyc9pp0r8elh0ktwhnxkmnwsvzm0h57g4x6qqrkf3rz \
  --new-value 75 \
  --fee-amount 150 \
  --broadcast
```

Broadcasted txid: https://liquid.network/testnet/tx/42c4da1e2123a47d3a714297f7fc859027101b4e1f25f82373413fda8e0faa50

```bash 
cargo run -p cli -- storage update-state \
  --storage-utxo 42c4da1e2123a47d3a714297f7fc859027101b4e1f25f82373413fda8e0faa50:0 \
  --reissuance-token-utxo 045f5fb3c96ebbcbcf72f85374834cf7386cb617b53e0733c816cab93e99897d:1 \
  --fee-utxo 42c4da1e2123a47d3a714297f7fc859027101b4e1f25f82373413fda8e0faa50:2 \
  --account-index 0 \
  --taproot-pubkey-gen c04071aeac390978291487bc8366f8d472f7313940a66d30b4dd33323ef20aff:02c16e18dc7602f649b5df82a2c56d2c6b1c3bdfc4a966302df4ea3bada155c5d9:tex1p82s73je29drd9pquyc9pp0r8elh0ktwhnxkmnwsvzm0h57g4x6qqrkf3rz \
  --new-value 125 \
  --fee-amount 150 \
  --broadcast
```

Broadcasted txid: https://liquid.network/testnet/tx/c3be143212710ec38a05e1bcf267184b59f2cbe434d22c8d5a5316fa730ab948