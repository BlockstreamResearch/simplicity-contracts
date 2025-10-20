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