# Export wallet file format (Generic JSON)

Coldcard can export data intended for various desktop and mobile
wallet systems, but we also have a file format for general purpose
exports, which we hope future wallet makers will leverage.

It contains master XPUB, XFP for that, and derived values for the top hardened
position of BIP44, BIP84 and BIP49.

The feature can be found here: _Advanced > MicroSD > Export Wallet > Generic JSON_

Please contact us (or better yet, make a pull request), if you need something
more in this file.

# Example JSON file

Here is an example, produced by the Simulator for account number 123.

```javascript
{
    "chain": "XTN",
    "xfp": "0F056943",
    "xpub": "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh",
    "account": 123,
    "bip44": {
        "deriv": "m/44'/1'/123'",
        "first": "n44vs1Rv7T8SANrg2PFGQhzVkhr5Q6jMMD",
        "name": "p2pkh",
        "xfp": "B7908B26",
        "xpub": "tpubDCiHGUNYdRRGoSH22j8YnruUKgguCK1CC2NFQUf9PApeZh8ewAJJWGMUrhggDNK73iCTanWXv1RN5FYemUH8UrVUBjqDb8WF2VoKmDh9UTo"
    },
    "bip49": {
        "_pub": "upub5DMRSsh6mNak9KbcVjJ7xAgHJvbE3Nx22CBTier5C35kv8j7g2q58ywxskBe6JCcAE2VH86CE2aL4MifJyKbRw8Gj9ay7SWvUBkp2DJ7y52",
        "deriv": "m/49'/1'/123'",
        "first": "2N87V39riUUCd4vmXfDjMWAu9gUCiBji5jB",
        "name": "p2wpkh-p2sh",
        "xfp": "CEE1D809",
        "xpub": "tpubDCDqt7XXvhAdy1MpSze5nMJA9x8DrdRaKALRRPasfxyHpiqWWEAr9cbDBQ9BcX7cB3up98Pk97U2QQ3xrvQsi5dNPmRYYhdcsKY9wwEY87T"
    },
    "bip84": {
        "_pub": "vpub5Y5a91QvDT45EnXQaKeuvJupVvX8f9BiywDcadSTtaeJ1VgJPPXMitnYsqd9k7GnEqh44FKJ5McJfu6KrihFXhAmvSWgm7BAVVK8Gupu4fL",
        "deriv": "m/84'/1'/123'",
        "first": "tb1qc58ys2dphtphg6yuugdf3d0kufmk0tye044g3l",
        "name": "p2wpkh",
        "xfp": "78CF94E5",
        "xpub": "tpubDC7jGaaSE66VDB6VhEDFYQSCAyugXmfnMnrMVyHNzW9wryyTxvha7TmfAHd7GRXrr2TaAn2HXn9T8ep4gyNX1bzGiieqcTUNcu2poyntrET"
    }
}
```

## Notes

1. The `first` address is formed by added `/0/0` onto the given derivation, and is assumed
to be the first (non-change) receive address for the wallet.

2. The user may specify any value (up to 9999) for the account number, and it's meant to
segregate funds into sub-wallets. Don't assume it's zero.

3. When making your PSBT files to spend these amounts, remember that the XFP of the master
(`0F056943` in this example) is the root of the subkey paths found in the file, and 
you must include the full derivation path from master. So based on this example,
to spend a UTXO on `tb1qc58ys2dphtphg6yuugdf3d0kufmk0tye044g3l`, the input section
of your PSBT would need to specify `(m=0F056943)/84'/1'/123'/0/0`.

4. The `_pub` value is the [SLIP-132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md) style "ypub/zpub/etc" which some systems might want. It implies
a specific address format.

