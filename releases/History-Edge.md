## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

## 6.4.1X & 6.4.1QX

-Bugfix: Multisig migration only worked for K of K multisig wallets (those where M is the same as N)


# Shared Improvements - Both Mk4 and Q

### WARNING: 6.4.0X is not backwards-compatible with previous EDGE firmware versions.
#### 6.4.0X stores multisig wallet internally as Miniscript wallets. Newly created multisig wallets won't be visible if you downgrade after creating them on 6.4.0X. Existing multisig wallets will be converted into Miniscript, yet preserved in old format if downgrade is desired.

- New Feature: Key Teleport
- New Feature: Spending Policy for Miniscript Wallets
- New Feature: Internal descriptor cache speeding up sequential operation with miniscript wallets.
  To take full advantage of the feature work with miniscript wallets sequentially. First, do all operations 
  needed with `wallet1` before changing to `wallet2`.
- New Feature: Add ability to import/export [BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki) Wallet Policies.
  BIP-388 policies are now also used as our wallet serialization format, which optimized setting storage.
- New Feature: Sign with specific miniscript wallet. `Settings -> Multisig/Miniscript -> <name> -> Sign PSBT`
- New Feature: Miniscript wallet name can be specified for `sign` USB command
- New Feature: Rename Miniscript wallet via UX. `Settings -> Multisig/Miniscript -> <wallet> -> Rename`.
- New Feature: Export [BIP-380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) extended key expression.
  Navigate to `Advanced/Tools -> Export Wallet -> Key Expression`
- Enhancement: Slightly faster HW accelerated tagged hash
- Enhancement: PSBT class optimizations. Ability to sign bigger txn.
- Enhancement: Signing TXN UI shows Miniscript wallet name.
- Change: Deprecation of legacy mulitsig import format. Ability to import/export in this format was removed.
  Old functionality - renaming by reimporting descriptor with different name was removed.
  Use descriptors or BIP-388 wallet policies
- Change: Deprecated `p2sh` USB command. Use `miniscript` USB commands to handle multisig wallets.
- Change: Descriptor template was remove from Generic JSON export, and `key_exp` was added
  with BIP-380 extended key expression `[xfp/origin_path]xpub`.
- Bugfix: Disjoint derivation in miniscript wallets
- Bugfix: Disallow P2SH legacy miniscript
- Bugfix: Do not allow to import miniscripts with relative lock without consensus meaning.
  Only allow to import block-based in range `older(1 - 65535)` & time-based in range `older(4194305 - 4259839)`

# Mk4 Specific Changes

## 6.4.0X - 2025-11-20

- synced with master up to `5.4.5`
- Enhancement: Show QR of XOR-split seeds


# Q Specific Changes

## 6.4.0QX - 2025-11-20

- synced with master up to `1.3.5Q`


# 6.3.5X & 6.3.5QX Shared Improvements - Both Mk4 and Q

Change: Allow origin-less extended keys in multisig & miniscript descriptors
Change: Static internal keys disallowed - all keys need to be ranged extended keys

# Mk4 Specific Changes

- all updates from `5.4.1`

# Q Specific Changes

- all updates from version `1.3.1Q`


# 6.3.4X & 6.3.4QX Shared Improvements - Both Mk4 and Q

- Bugfix: Complex miniscript wallets with keys in policy that are not in strictly ascending order were incorrectly filled
  upon load from settings. All users on versions `6.2.2X`+ needs to update. 
- Bugfix: Single key miniscript descriptor support
- Enhancement: Hide Secure Notes & Passwords in Deltamode. Wipe seed if notes menu accessed. 
- Enhancement: Hide Seed Vault in Deltamode. Wipe seed if Seed Vault menu accessed.
- Bugfix: Do not allow to enable/disable Seed Vault feature when in temporary seed mode
- Bugfix: Bless Firmware causes hanging progress bar
- Bugfix: Prevent yikes in ownership search
- Change: Do not allow to purge settings of current active tmp seed when deleting it from Seed Vault

# Mk4 Specific Changes

- all updates from `5.4.0`
- Enhancement: Export single sig descriptor with simple QR

# Q Specific Changes

- all updates from version `1.3.0Q`
- Bugfix: Properly re-draw status bar after Restore Master on COLDCARD without master seed.


## 6.3.3X & 6.3.3QX Shared Improvements - Both Mk4 and Q (2024-07-04)

- New Feature: Ranged provably unspendable keys and `unspend(` support for Taproot descriptors
- New Feature: Address ownership for miniscript and tapscript wallets
- Enhancement: Address explorer simplified UI for tapscript addresses
- Bugfix: Constant `AFC_BECH32M` incorrectly set `AFC_WRAPPED` and `AFC_BECH32`.
- Bugfix: Trying to set custom URL for NFC push transaction caused yikes

### Mk4 Specific Changes

- Bugfix: Fix yikes displaying BIP-85 WIF when both NFC and VDisk are OFF
- Bugfix: Fix inability to export change addresses when both NFC and Vdisk id OFF
- Bugfix: In BIP-39 words menu, show space character rather than Nokia-style placeholder
  which could be confused for an underscore.

### Q Specific Changes

- Enhancement: Miniscript and (BB)Qr codes
- Bugfix: Properly clear LCD screen after simple QR code is shown


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