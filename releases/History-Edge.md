## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

## 6.3.3

## 6.2.2X - 2024-01-18

- New Feature: Miniscript [USB interface](https://github.com/Coldcard/ckcc-protocol/blob/master/README.md#miniscript)
- New Feature: Named miniscript imports. Wrap descriptor in json
  `{"name:"n0", "desc":"<descriptor>"}` with `name` key to use this name instead of the
  filename. Mostly usefull for USB and NFC imports that have no file, in which case name
  was created from descriptor checksum.
- Enhancement: Allow keys with same origin, differentiated only by change index derivation
  in miniscript descriptor.
- Enhancement: HSM `wallet` rule enabled for miniscript
- Enhancement: Add `msas` in to the `share_addrs` HSM [rule](https://coldcard.com/docs/hsm/rules/)
  to be able to check miniscript addresses in HSM mode.
- Enhancement: HW Accelerated AES CTR for BSMS and passphrase saver
- Bugfix: Do not allow to import duplicate miniscript
  wallets (thanks to [AnchorWatch](https://www.anchorwatch.com/))
- Bugfix: Saving passphrase on SD Card caused a freeze that required reboot

## 6.2.1X - 2023-10-26

- New Feature: Enroll Miniscript wallet via USB (requires ckcc `v1.4.0`)
- New Feature: Temporary Seed from COLDCARD encrypted backup
- Enhancement: Add current temporary seed to Seed Vault from within Seed Vault menu.
  If current active temporary seed is not saved yet, `Add current tmp` menu item is 
  present in Seed Vault menu.
- Reorg: `12 Words` menu option preferred on the top of the menu in all the seed menus
- Enhancement: Mainnet/Testnet separation. Only show wallets for current active chain.
- contains all the changes from the newest stable `5.2.0-mk4` firmware

## 6.1.0X - 2023-06-20

- New Feature: Miniscript and MiniTapscript support (`docs/miniscript.md`)
- Enhancement: Tapscript up to 8 leafs
- Address explorer display refined slightly (cosmetic)

## 6.0.0X - 2023-05-12

- New Feature: Taproot keyspend & Tapscript multisig `sortedmulti_a` (tree depth = 0)
- New Feature: Support BIP-0129 Bitcoin Secure Multisig Setup (BSMS).
  Both Coordinator and Signer roles are supported.
- Enhancement: change Key Origin Information export format in multisig `addresses.csv` according to [BIP-0380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions)
  `(m=0F056943)/m/48'/1'/0'/2'/0/0` --> `[0F056943/48'/1'/0'/2'/0/0]`
- Bugfix: correct `scriptPubkey` parsing for segwit v1-v16
- Bugfix: do not infer segwit just by availability of `PSBT_IN_WITNESS_UTXO` in PSBT