# Miniscript

**COLDCARD<sup>&reg;</sup>** Mk4 experimental `EDGE` versions
support Miniscript and MiniTapscript.

## Import/Export

* `Settings` -> `Miniscript` -> `Import from file`
* only [descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) allowed for import
* `Settings` -> `Miniscript` -> `<name>` -> `Descriptors`
* only [descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) are exported
* export extended keys to participate in miniscript:
    * `Advanced/Tools` -> `Export Wallet` -> `Generic JSON`
    * `Settings` -> `Multisig Wallets` -> `Export XPUB`

## Address Explorer

Same as with basic multisig. After miniscript wallet is imported, 
item with `<name>` is added to `Address Explorer` menu.


## Limitations
* no duplicate keys in miniscript (at least change indexes in subderivation has to be different)
* subderivation may be omitted during the import - default `<0;1>/*` is implied
* only keys with key origin info `[xfp/p/a/t/h]xpub`
* maximum number of keys allowed in segwit v0 miniscript is 20
* check MiniTapscript limitations in `docs/taproot.md`