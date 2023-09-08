## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

## 6.1.1X - 2023-09-1X

- New Feature: Batch sign multiple PSBT files. `Advanced/Tools -> File Management -> Batch Sign PSBT`
- New Feature: Enroll Miniscript wallet via USB (requires ckcc `v1.4.0`)
- Enhancement: Mainnet/Testnet separation. Only show wallets for current active chain.
- Enhancement: `Sparrow Wallet` added as an individual export option (same file contents)
- Enhancement: change key origin information export format in multisig `addresses.csv` to match
  [BIP-0380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions)
  was `(m=0F056943)/m/48'/1'/0'/2'/0/0` now `[0F056943/48'/1'/0'/2'/0/0]`
- Enhancement: Address explorer UX cosmetics, now with arrows and dots.
- Enhancement: Linked settings (multisig, trick pins, backup password, hsm users and utxo cache)
  separation for new main secret.
- Rename `Unchained Capital` to `Unchained`
- Bugfix: Correct `scriptPubkey` parsing for segwit v1-v16
- Bugfix: Do not infer segwit just by availability of `PSBT_IN_WITNESS_UTXO` in PSBT.
- Bugfix: Remove label from Bitcoin Core `importdescriptors` export as it is no longer supported
  with ranged descriptors in version `24.1` of Core.
- Bugfix: Empty number during BIP-39 passphrase entry could cause crash.
- Bugfix: Signing with BIP39 Passphrase showed master fingerprint as integer. Fixed to show hex.
- Bugfix: Fixed inability to generate paper wallet without secrets
- Bugfix: Activating trick pin duress wallet copied multisig settings from main wallet
- Bugfix: SD2FA setting is cleared when seed is wiped after failed login due to policy SD2FA enforce.
  Prevents infinite seed wipe loop when restoring backup after 2FA MicroSD lost or damaged.
  SD2FA is not backed up and also not restored from older backups. If SD2FA is set up,
  it will not survive restore of backup.
- Bugfix: Terms only presented if main PIN was not chosen already.
- Bugfix: Preserve defined order of Login Countdown settings list.
- Bugfix: Remove unsupported trick pin option `Look Blank` from `if wrong` (not supported by bootrom).

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


