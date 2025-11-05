## Multisig Ownership address check: "wallet"

If the name of the multisig wallet related to an address is provided, address search
can be greatly accelerated. Just provide `wallet=name` parameter in a standard
[BIP-21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) URL
shown in QR code or NFC record. If omitted, search will continue across 
all multisig wallets known by COLDCARD.

### Examples

```
tb1q4d67p7stxml3kdudrgkg5mgaxsrgzcqzjrrj4gg62nxtvnsnvqjsxjkej0?wallet=goldmine

bitcoin:mtHSVByP9EYZmB26jASDdPVm19gvpecb5R?label=coldcard_purchase&amount=50&wallet=Haystack%20Four
```
