# Export wallet file format (Generic JSON)

Coldcard can export data intended for various desktop and mobile
wallet systems, but we also have a file format for general purpose
exports, which we hope future wallet makers will leverage.

It contains master XPUB, XFP for that, and derived values for the top hardened
position of the single-signature schemes BIP44, BIP49 and BIP84, plus the
multisig schemes BIP48 (`bip48_1` = `.../1h` P2SH-P2WSH and `bip48_2` = `.../2h` P2WSH).
When the account number is zero, a BIP45 (`m/45h`) multisig section is also included
(it is omitted for non-zero accounts, as in the example below).

The feature can be found here: _Advanced/Tools > Export Wallet > Generic JSON_

Please contact us (or better yet, make a pull request), if you need something
more in this file.

# Example JSON file

Here is an example, produced by the Simulator for account number 123.

```javascript
{
    "chain": "BTC",
    "xfp": "0F056943",
    "account": 123,
    "xpub": "xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7",
    "bip44": {
        "name": "p2pkh",
        "xfp": "5F898064",
        "deriv": "m/44h/0h/123h",
        "xpub": "xpub6DStQXfAgHuLbMpCf86ruVkF4yT9pSLyWsFiqQTWY9osuinq8Dyee4W5jCjMfyku5LNkRB9oFinrY5ufn9XXEn8Vvzc2jnifKMaQCNV7RBZ",
        "desc": "pkh([0f056943/44h/0h/123h]xpub6DStQXfAgHuLbMpCf86ruVkF4yT9pSLyWsFiqQTWY9osuinq8Dyee4W5jCjMfyku5LNkRB9oFinrY5ufn9XXEn8Vvzc2jnifKMaQCNV7RBZ/<0;1>/*)#4tl8jryn",
        "first": "1GTNtzG5xX2UhdD5e3Nu7i1WPxFdjxQMJt"
    },
    "bip49": {
        "name": "p2sh-p2wpkh",
        "xfp": "A748B1FC",
        "deriv": "m/49h/0h/123h",
        "xpub": "xpub6DDm8WzH5a9qjKkttzqSB3uGofNohU9D3n3UG8WMxkUZzJEMPTYiQRf1dvTFCQR82MjGW4LUMVuTtnW4hF17RpzCqVwhf6Z2fnJPWtjG164",
        "desc": "sh(wpkh([0f056943/49h/0h/123h]xpub6DDm8WzH5a9qjKkttzqSB3uGofNohU9D3n3UG8WMxkUZzJEMPTYiQRf1dvTFCQR82MjGW4LUMVuTtnW4hF17RpzCqVwhf6Z2fnJPWtjG164/<0;1>/*))#5j7t2n2u",
        "_pub": "ypub6Y42SBfCEFhKacx1jMd4P8zmydXFe68hxtZh3XQFLkrT3Q3ae7iH2VK9f8QqCK53Rzr5FXw2pAG1n57dQwR8E4fohqe8F1NWwWN2uVRfBry",
        "first": "3CeBRbJKCpg7BpJME2vM8ZxhCjBnhG4toy"
    },
    "bip84": {
        "name": "p2wpkh",
        "xfp": "2C5207AA",
        "deriv": "m/84h/0h/123h",
        "xpub": "xpub6CaWStGvcXqSW9BzU2vpCoP7aWjz9VfR5DS2nuYWVvKV2nug2dESg3HdFsaWHeoZaxuAhNcPB3TH2gq8MugS3JX1yGuhB4QbC2BneaYqB16",
        "desc": "wpkh([0f056943/84h/0h/123h]xpub6CaWStGvcXqSW9BzU2vpCoP7aWjz9VfR5DS2nuYWVvKV2nug2dESg3HdFsaWHeoZaxuAhNcPB3TH2gq8MugS3JX1yGuhB4QbC2BneaYqB16/<0;1>/*)#yk84tprf",
        "_pub": "zpub6rF34DckutvQCjaE8kW4cya7vT2t2jeQuSUUMhLHFw5F8zY8XwZZvAbuJHVgHU7QQF8nCKoW6NANoG4FoJWTdmtDhxJYLt3ZjUK5RqUSMdF",
        "first": "bc1qhj6avwmp5lhpgqwm6dgxrf3v5lf67rjm99a8an"
    },
    "bip48_1": {
        "name": "p2sh-p2wsh",
        "xfp": "845A3542",
        "deriv": "m/48h/0h/123h/1h",
        "xpub": "xpub6EkcQSTygvxVnBP2X2fM6HY5D7wv46tWbBc54ADaypuCr47vQh1GPdPAZFdx81ou5Rp4vBnzeJT5MDWDZstzijxkHfrofXRycpt1ASfg1La",
        "desc": "sh(wsh(sortedmulti(M,[0f056943/48h/0h/123h/1h]xpub6EkcQSTygvxVnBP2X2fM6HY5D7wv46tWbBc54ADaypuCr47vQh1GPdPAZFdx81ou5Rp4vBnzeJT5MDWDZstzijxkHfrofXRycpt1ASfg1La/0/*,...)))",
        "_pub": "Ypub6kUxqLsLQa4M43jXJ3ux8SyP6t8dD5ZbpZmxkpP1jc7VXLW4RkZ76ouEPAZ1gMgiiXzrYFPfzBC8MfjYaoTxfTm1zUfdeqiTnHDX8raCfeg"
    },
    "bip48_2": {
        "name": "p2wsh",
        "xfp": "2A01C6B0",
        "deriv": "m/48h/0h/123h/2h",
        "xpub": "xpub6EkcQSTygvxVneXmk3ywiS2PFhBdiPxeMxYf6RFxHCHH36NxdcN7DjUpudCppAAxs58CG6DQLjtqZNmyC3MpgVob6wpdeATjpZZ1woX92EF",
        "desc": "wsh(sortedmulti(M,[0f056943/48h/0h/123h/2h]xpub6EkcQSTygvxVneXmk3ywiS2PFhBdiPxeMxYf6RFxHCHH36NxdcN7DjUpudCppAAxs58CG6DQLjtqZNmyC3MpgVob6wpdeATjpZZ1woX92EF/0/*,...))",
        "_pub": "Zpub75KE91YFZFbpup5PMS2AxgZCKRWnozdEWTEmaUKGQysSmUaKuL5WYyf2kk5UNQhhupRnddQe9GzST7crvfLoRTHTg6KtDPZiFjxBJobzcUz"
    }
}
```

## Notes

1. The `first` address is formed by added `/0/0` onto the given derivation, and is assumed
to be the first (non-change) receive address for the wallet. It is only present on the
single-signature sections (`bip44`, `bip49`, `bip84`); multisig sections omit it.

1a. Each section includes a `desc` field: a ready-to-import Bitcoin output descriptor
(with `#checksum`). Single-sig descriptors use the `<0;1>/*` multipath form. Multisig
sections (`bip48_1`, `bip48_2`, and `bip45` when present) emit a `sortedmulti(...)`
template with `M` and a trailing `...` as placeholders, to be completed with your
threshold and the other co-signers' keys.

2. The user may specify any value (up to 9999) for the account number, and it's meant to
segregate funds into sub-wallets. Don't assume it's zero.

3. When making your PSBT files to spend these amounts, remember that the XFP of the master
(`0F056943` in this example) is the root of the subkey paths found in the file, and 
you must include the full derivation path from master. So based on this example,
to spend a UTXO on `bc1qhj6avwmp5lhpgqwm6dgxrf3v5lf67rjm99a8an`, the input section
of your PSBT would need to specify `(m=0F056943)/84'/0'/123'/0/0`.

4. The `_pub` value is the [SLIP-132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md) style "ypub/zpub/etc" which some systems might want. It implies
a specific address format.

