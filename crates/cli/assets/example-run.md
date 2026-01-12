## Options and basic commands Testing Status

--- Main key

X Only Public Key: ff81247f6aaac08a0edcd422c89ae4726e1e69fe9f059f3845e017c77999765d
P2PK Address: tex1p9sv7g8tyljjymz4t6zyjpvepw44f9wfjxskvyjlczqjdw7rrykqsl9hwe7
Script hash: c50c741beb17a0decf6feafafc242fe77f3c4c6749e99bab09a5c8b6e2bda6eb

```bash
cargo run -p cli -- basic issue-asset \
  --broadcast \
  --asset-name "test8" \
  --fee-utxo 11c3739232369d16b75042f2be3f471e6a6aeca407ad618b1d46e522ab2e4950:0 \
  --issue-sats 1000000000000000 \
  --fee-sats 50 \
  --account-index 0
```

Asset id: 9ec1fbdafa60888ae667cc7387dcc39337be14cc86a0263b5d4df5b388a748a6,
Reissuance asset: fea85ec0ec4e69193394d70068a86ee170138c008f0c15639a980d7293d75a2f,
Asset entropy: 2f9a1be5962a775e5efd86f62d3bc001468537291a4952dab7d0dc65698108d7
Broadcasted txid: fd7a0240fa56668f644610b6ef8b5b49551d00ec03f86bd1fdcac8af87b86e04


```bash
cargo run -p cli -- basic reissue-asset \
    --broadcast \
    --reissue-asset-utxo fd7a0240fa56668f644610b6ef8b5b49551d00ec03f86bd1fdcac8af87b86e04:0 \
    --fee-utxo c2f0cd45deacea442330fea2f5c6e41725e0de66a233b65bcd576e63ab5bda65:3 \
    --asset-name "test8" \
    --reissue-sats 54321 \
    --fee-sats 100
```

```bash
cargo run -p cli -- basic transfer-native \
  --broadcast \
  --utxo fbf2c06ca35ac6ae48b964c99e93a447a7c432017eee76dc77f2d802f6d30704:2 \
  --to-address tex1p9sv7g8tyljjymz4t6zyjpvepw44f9wfjxskvyjlczqjdw7rrykqsl9hwe7 \
  --send-sats 1234 \
  --fee-sats 100
```

```bash
 cargo run -p cli -- basic transfer-asset \
  --broadcast \
  --asset-utxo fbf2c06ca35ac6ae48b964c99e93a447a7c432017eee76dc77f2d802f6d30704:1 \
  --fee-utxo 92224e5fc99fd7ef525f23e3ca29057f0f5192e4391fd7410789da77af854c58:0 \
  --to-address tex1p9sv7g8tyljjymz4t6zyjpvepw44f9wfjxskvyjlczqjdw7rrykqsl9hwe7 \
  --send-sats 123 \
  --fee-sats 100
```

```bash 
cargo run -p cli -- basic split-native \
    --broadcast \
    --fee-utxo a35f7fc317cf8cf2eec88b1046de046e8c7e186259bf54c01eb0ead391f1505b:4 \
    --split-parts 5 \
    --fee-amount 100
```

Broadcasted txid: 866e9012120260bb2aab86e5585191b2c75b8e4009f65074e92c1c0f63c07452

```bash
cargo run -p cli -- options create \
    --broadcast \
    --first-fee-utxo 866e9012120260bb2aab86e5585191b2c75b8e4009f65074e92c1c0f63c07452:0 \
    --second-fee-utxo 866e9012120260bb2aab86e5585191b2c75b8e4009f65074e92c1c0f63c07452:1 \
    --start-time 1765722750 \
    --expiry-time 1765722750 \
    --collateral-per-contract 10 \
    --settlement-per-contract 25 \
    --settlement-asset-id-hex-be 9ec1fbdafa60888ae667cc7387dcc39337be14cc86a0263b5d4df5b388a748a6 \
    --account-index 0 \
    --fee-amount 100
```

options_taproot_pubkey_gen: f6454c9c47b6e2d3ba8e323e2006e35cef3a435e62d51b765edaa861dc119262:02ba1b8af1e19c95637243a16162a0d8b4b6c72326d40da348841fe12d0eaed6b0:tex1plf03p9jjduz3aumdqalmj0euwuje0luk76592xqj9ruvffaj6rfq2t8amc
Broadcasted txid: aa415c2558f2a67d5f63388d5fb9207d6507c172dccea044902dbc3a94a2ca17

```bash
cargo run -p cli -- options fund \
    --broadcast \
    --option-asset-utxo aa415c2558f2a67d5f63388d5fb9207d6507c172dccea044902dbc3a94a2ca17:0 \
    --grantor-asset-utxo aa415c2558f2a67d5f63388d5fb9207d6507c172dccea044902dbc3a94a2ca17:1 \
    --collateral-and-fee-utxo aa415c2558f2a67d5f63388d5fb9207d6507c172dccea044902dbc3a94a2ca17:2 \
    --option-taproot-pubkey-gen f6454c9c47b6e2d3ba8e323e2006e35cef3a435e62d51b765edaa861dc119262:02ba1b8af1e19c95637243a16162a0d8b4b6c72326d40da348841fe12d0eaed6b0:tex1plf03p9jjduz3aumdqalmj0euwuje0luk76592xqj9ruvffaj6rfq2t8amc \
    --collateral-amount 1000 \
    --account-index 0 \
    --fee-amount 250
```

Broadcasted txid: 873a10b32cf7b7f3d5c48c35907c052e6ed6d0289378f407bf3a8a4a0ccbe528

```bash
cargo run -p cli -- options exercise \
    --broadcast \
    --collateral-utxo 873a10b32cf7b7f3d5c48c35907c052e6ed6d0289378f407bf3a8a4a0ccbe528:2 \
    --option-asset-utxo 873a10b32cf7b7f3d5c48c35907c052e6ed6d0289378f407bf3a8a4a0ccbe528:3 \
    --asset-utxo fd7a0240fa56668f644610b6ef8b5b49551d00ec03f86bd1fdcac8af87b86e04:1 \
    --fee-utxo 873a10b32cf7b7f3d5c48c35907c052e6ed6d0289378f407bf3a8a4a0ccbe528:5 \
    --option-taproot-pubkey-gen f6454c9c47b6e2d3ba8e323e2006e35cef3a435e62d51b765edaa861dc119262:02ba1b8af1e19c95637243a16162a0d8b4b6c72326d40da348841fe12d0eaed6b0:tex1plf03p9jjduz3aumdqalmj0euwuje0luk76592xqj9ruvffaj6rfq2t8amc \
    --amount-to-burn 15 \
    --fee-amount 200 \
    --account-index 0
```

Broadcasted txid: b15803f5d4e0bb228b19d1f856ed0fa8d7eddb2e2da71351d06374b2296867af

```bash
cargo run -p cli -- options settle \
    --broadcast \
    --settlement-asset-utxo b15803f5d4e0bb228b19d1f856ed0fa8d7eddb2e2da71351d06374b2296867af:2 \
    --grantor-asset-utxo 873a10b32cf7b7f3d5c48c35907c052e6ed6d0289378f407bf3a8a4a0ccbe528:4 \
    --fee-utxo b15803f5d4e0bb228b19d1f856ed0fa8d7eddb2e2da71351d06374b2296867af:5 \
    --option-taproot-pubkey-gen f6454c9c47b6e2d3ba8e323e2006e35cef3a435e62d51b765edaa861dc119262:02ba1b8af1e19c95637243a16162a0d8b4b6c72326d40da348841fe12d0eaed6b0:tex1plf03p9jjduz3aumdqalmj0euwuje0luk76592xqj9ruvffaj6rfq2t8amc \
    --grantor-token-amount-to-burn 15 \
    --fee-amount 200 \
    --account-index 0

```

Broadcasted txid: c2f0cd45deacea442330fea2f5c6e41725e0de66a233b65bcd576e63ab5bda65


```bash
cargo run -p cli -- options expire \
    --broadcast \
    --collateral-utxo 39f39306c2f84b6b60b6036de24a421e9cac9d1a533b8040770ddfef2f253108:0 \
    --grantor-asset-utxo 39f39306c2f84b6b60b6036de24a421e9cac9d1a533b8040770ddfef2f253108:5 \
    --fee-utxo 39f39306c2f84b6b60b6036de24a421e9cac9d1a533b8040770ddfef2f253108:6 \
    --option-taproot-pubkey-gen f96a6282708cbf9b4f4db34c82236b29081bd17c01c760a3e510aabfba281104:02024607d3db437ed882b2dfc0c1fe7068bed34e71e3ea0cb5c7c562581b588df3:tex1pws8eu77t4jytanwfwh79s9zqcygn0tamt839mumz3440hy95462sw4j969 \
    --grantor-token-amount-to-burn 10 \
    --fee-amount 150 \
    --account-index 0
```

Broadcasted txid: a35f7fc317cf8cf2eec88b1046de046e8c7e186259bf54c01eb0ead391f1505b

```bash
cargo run -p cli -- options cancel \
    --broadcast \
    --collateral-utxo bd8109755df1708d8cf9a4903acefcee2ebe9c3653909752b389d5ecffdb3b62:2 \
    --option-asset-utxo bd8109755df1708d8cf9a4903acefcee2ebe9c3653909752b389d5ecffdb3b62:3 \
    --grantor-asset-utxo bd8109755df1708d8cf9a4903acefcee2ebe9c3653909752b389d5ecffdb3b62:4 \
    --fee-utxo bd8109755df1708d8cf9a4903acefcee2ebe9c3653909752b389d5ecffdb3b62:5 \
    --option-taproot-pubkey-gen f96a6282708cbf9b4f4db34c82236b29081bd17c01c760a3e510aabfba281104:02024607d3db437ed882b2dfc0c1fe7068bed34e71e3ea0cb5c7c562581b588df3:tex1pws8eu77t4jytanwfwh79s9zqcygn0tamt839mumz3440hy95462sw4j969 \
    --amount-to-burn 10 \
    --fee-amount 150 \
    --account-index 0
```

Broadcasted txid: 39f39306c2f84b6b60b6036de24a421e9cac9d1a533b8040770ddfef2f253108


