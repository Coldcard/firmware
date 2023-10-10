## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

## 6.2.1X - 2023-10-19

- New Feature: Enroll Miniscript wallet via USB (requires ckcc `v1.4.0`)
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


