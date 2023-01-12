## 5.1.3X - 2023-XX-XX

- New Feature: Taproot keyspend & Tapscript multisig sortedmulti_a (tree depth = 0)
- New Feature: Support BIP-0129 Bitcoin Secure Multisig Setup (BSMS).
  Both Coordinator and Signer roles are supported.
- Enhancement: change Key Origin Information export format in multisig `addresses.csv` according to [BIP-0380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions)
  `(m=0F056943)/m/48'/1'/0'/2'/0/0` --> `[0F056943/48'/1'/0'/2'/0/0]`
- Bugfix: correct `scrptPubkey` parsing for segwit v1-v16
- Bugfix: do not infer segwit just by availability of `PSBT_IN_WITNESS_UTXO` in PSBT