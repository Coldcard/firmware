## `wallet` Ownership address check

Address ownership allows to specify particular multisig wallet in which to search, allowing to skip
useless searches in irrelevant wallets. `wallet` query parameter is provided via [BIP-21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)

#### Examples: 
```
tb1q4d67p7stxml3kdudrgkg5mgaxsrgzcqzjrrj4gg62nxtvnsnvqjsxjkej0?wallet=my_wal

'mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?label=coldcard_purchase&amount=50&wallet=multi_wsh',
```