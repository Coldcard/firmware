# Change Log

## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.
```

This lists the changes in the most recent EDGE firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- New Feature: Key Teleport
- New Feature: Spending Policy for Miniscript Wallets
- New Feature: Internal descriptor cache speeding up sequential operation with miniscript wallets.
  To take full advantage of the feature work with miniscript wallets sequentially. First, do all operations 
  needed with `wallet1` before changing to `wallet2`.
- New Feature: Add ability to import/export [BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki) Wallet Policies.
  BIP-388 policies are now also used as our wallet serialization format, which optimized setting storage.
- New Feature: Sign with specific miniscript wallet. `Settings -> Miniscript -> <name> -> Sign PSBT`
- New Feature: Miniscript wallet name can be specified for `sign` USB command
- New Feature: Rename Miniscript wallet via UX. `Settings -> Miniscript -> <wallet> -> Rename`.
- Enhancement: Slightly faster HW accelerated tagged hash
- Enhancement: PSBT class optimizations. Ability to sign bigger txn.
- Enhancement: Signing TXN UI shows Miniscript wallet name.
- Change: Everything is miniscript now. To import multisig wallets go to `Settings -> Miniscript`
- Change: Deprecation of legacy mulitsig import format. Ability to import/export in this format was removed.
  Old functionality - renaming by reimporting descriptor with different name was removed.
  Use descriptors or BIP-388 wallet policies
- Change: Deprecated `p2sh` USB command. Use `miniscript` USB commands to handle multisig wallets.
- Change: Descriptor template was remove from Generic JSON export, and `key_exp` was added
  with BIP-380 extended key expression `[xfp/origin_path]xpub`.
- Bugfix: Disjoint derivation in miniscript wallets
- Bugfix: Disallow P2SH legacy miniscript
- Bugfix: Do not allow to import miniscript with `older(N > 65535)`

# Mk4 Specific Changes

## 6.3.6X - 2025-XX-XX

- synced with master up to `5.4.4`


# Q Specific Changes

## 6.3.6QX - 2025-XX-XX

- synced with master up to `1.3.4Q`


# Release History

- [`History-Edge.md`](History-Edge.md)
