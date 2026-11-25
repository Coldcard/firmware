## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

# Shared Improvements - Both Mk4 and Q

- New Feature: Codex32 (BIP-93) secrets and Shamir secret sharing. Generate or import Codex32
  wallets, split the active wallet into two to nine Shamir shares with **Shamir Split**, and
  restore it with **Shamir Recover**. Word wallets split as `cw1`, raw master seeds as `ms1`,
  and extended-key wallets as `cx1`. CW1 and CX1 are COLDCARD extensions that require
  explicit support in recovery software.
- New Feature: Added USB ncry v3 authenticated encryption with direction-separated keys and replay protection
- Enhancement: Restore Taproot script tree structure in Address Explorer CSV exports.
- Enhancement: Warn before installing firmware signed by an external contributor
  or downgrading from the currently installed firmware. Thanks to Huzaifa Jawaid for suggestion.
- Enhancement: Optionally show Seed Vault names for temporary seed fingerprints
  at the top of the home menu.
- Enhancement: Support per-input required height and time locktimes in PSBTv2 transactions.
- Enhancement: Warn when a transaction's block-height `nLockTime` is more than
  ten years beyond the Bitcoin block height known to the firmware.
- Enhancement: Retain up to 128 UTXO cache entries across restarts.
- Bugfix: Restore Backup now verifies whether a seed write succeeded after a bootloader
  AE_FAIL before aborting, avoiding a half-restored device with seed written but settings
  missing.
- Bugfix: Show outputs to segwit v1+ witness programs other than 32 bytes long
  as their bech32m address, rather than as a raw script.

- Bugfix: Reject conflicting xpub data between a MuSig aggregate and its ordinary
  xpub representation even when derivation suffixes differ, and reject conflicting
  key origins before wallet policy conversion. Thanks to
  [@pythcoiner](https://github.com/pythcoiner).
- Bugfix: Reject descriptors containing extended public keys with the same public key
  but conflicting chain codes or other xpub fields, preventing incorrect Taproot
  addresses. Thanks to [@pythcoiner](https://github.com/pythcoiner).
- Bugfix: Preserve correct scripts and addresses when the same key appears in both
  `pk()` and `pkh()` Taproot leaves.
- Bugfix: Preserve MuSig participant information in policy exports and wallet matching
  when the aggregate key also appears as an ordinary xpub.
- Bugfix: Reject duplicate public keys in BIP-388 policy key lists, as required by
  the specification.
- Bugfix: Fixed signing single-key Taproot leaf spends in wallets with a MuSig2
  internal key. Thanks to [@pythcoiner](https://github.com/pythcoiner) for the report and fix.
- Bugfix: Fix Address Explorer CSV exports for MuSig wallets, including participant
  derivation paths when an aggregate xpub is also present.
- Bugfix: Clear the Set Nickname checkmark when the nickname is removed, including
  empty nicknames saved by earlier firmware. Thanks to [@bonitoman](https://github.com/bonitoman).
- Bugfix: Abort a pending firmware upgrade if its staged image is overwritten before
  approval. Thanks to Huzaifa Jawaid.
- Bugfix: Reject malformed PSBTs containing P2SH-P2WSH inputs with a missing or
  incorrect redeem script, preventing transactions with an unknown fee from
  proceeding to approval.
- Bugfix: Reject foreign inputs from BIP-322 Proof of Reserves, including inputs
  disguised with forged key-path metadata or partial signatures.
- Bugfix: HSM `min_pct_self_transfer` and `EQ_NUM_OWN_INS_OUTS` rules counted
  outputs as ours based on host-supplied PSBT key-path metadata, so a foreign
  output with forged derivation info could satisfy self-transfer requirements.
  Only outputs verified as change are counted now. Thanks to Swaplane for the report.
- Bugfix: Add a block-height reset to Single-Signer Spending Policy's
  **Last Violation** screen after policy bypass, matching CCC.
- Bugfix: Cancelled PSBTs no longer persist claimed input amounts to the UTXO
  cache; amounts are committed only after signing, for inputs actually signed.
- Bugfix: Cache single-sig segwit change amounts at finalize, so understated
  input amounts are caught instead of silently trusted.
- Bugfix: Reject PSBTv2 transactions with an out-of-range transaction version, matching
  the PSBTv0 parser. Previously a v2 PSBT with an invalid `nVersion` could be approved
  and signed, producing a transaction the network will not relay.
- Bugfix: Reject non-ASCII BIP-39 passphrases (USB, saved-passphrase recall, and
  note/password lanes) instead of silently deriving a wallet incompatible with
  BIP-39-normalizing software.
- Bugfix: In Delta Mode, wipe the seed if anyone tries to view or activate a duress
  wallet's secret from the Trick PINs menu, instead of revealing it. Browsing the menu
  itself still works, so Delta Mode continues to look like normal operation.
- Bugfix: Reject firmware images that extend past the world-checksum-covered
  flash region.
- Bugfix: Reject PSRAM virtual-disk files whose FAT metadata is inconsistent with the
  declared file size (oversized cluster chains, oversized fragment counts, spurious
  trailing fragments, final remainders exceeding the final fragment's capacity, or
  filesystems with more than one sector per cluster), fixing an integer underflow in
  `psram_copy_file`/`psram_mmap_file` that allowed out-of-bounds PSRAM writes, reads,
  and mappings from a compromised USB host.
- Bugfix: Fix device crash when message-signing input is valid JSON but not an
  object (NFC / QR / SD `.json` file). Thanks to [@Amiga500](https://github.com/Amiga500).
- Bugfix: Harden PSBTv2 parsing by rejecting key data on singleton fields,
  malformed global input/output count encodings, and files missing the required
  global version.
- Bugfix: Preserve Taproot context while deriving Miniscript policies.
- Bugfix: Correct finalization of presigned segwit inputs. Thanks to Nabeel-javed.
- Bugfix: Keep a signed PSBT when an input lacks a supported, validated script and
  usable signature set, including incomplete taproot, tapscript and MuSig2 spends.
- Bugfix: Avoid recalculating the displayed addresses when returning from file
  export in Address Explorer, eliminating the unnecessary "Wait..." delay.

# Mk4 Specific Changes

## 6.6.2X - 2026-11-17

- all of the above
- synced with master up to and including `5.6.3`


# Q Specific Changes

## 6.6.2QX - 2026-11-17

- all of the above
- synced with master up to and including `1.5.3Q`
- Bugfix: Fix Key Teleport failing to find MuSig participants when an equivalent
  ordinary aggregate xpub hides the MuSig expression in the cached key list.
  Thanks to [@pythcoiner](https://github.com/pythcoiner).
- Bugfix: Prevent unintended master seed replacement when scanning seed words
  or an extended private key from Ready To Sign or the Key Teleport retry screen.


# Shared Improvements - Both Mk4 and Q

- Bugfix: Reject cyclic FAT chains in virtual-disk file imports instead of hanging.
- Bugfix: Abort a pending firmware upgrade if its staged image is overwritten before approval. Thanks to Huzaifa Jawaid.
- Bugfix: Detect and abort transaction signing if a Virtual Disk firmware import overwrites the reviewed PSBT.
  Thanks to Huzaifa Jawaid.
- Enhancement: Allow uncompressed WIF keys in WIF Store.
- Enhancement: Faster multisig address generation and PSBT input verification.
- Enhancement: Use predictable sequential filenames for PSBTs processed multiple times via MicroSD or Virtual Disk.
- Change: Spending Policy mode prevents USB hosts from enrolling, deleting, listing, or exporting
  Multisig/Miniscript wallet configurations.
- Change: The main transaction approval story no longer lists every affected input or output for repeated warnings,
  relative timelocks, or unusual change derivation paths. It now shows compact summaries; use the transaction
  explorer to review individual details.
- Bugfix: Generate distinct MuSig2 nonces for different aggregate-key derivations of the same participant set.
- Bugfix: Harden MuSig2 session handling for PSBTs with foreign MuSig2 inputs or differing witness UTXO data.
- Bugfix: Preserve MuSig2 signing sessions while waiting for cosigner public nonces.
- Bugfix: Prevent PSBT corruption when the same MuSig2 participant performs multiple signing rounds via Key Teleport.
- Bugfix: Track remaining multisig and Tapscript signers independently for each PSBT input.
- Change: Limit MuSig2 participant lists to 32.
- Bugfix: Generate unique names when creating multisig wallets from PSBTs with the same M-of-N parameters.
- Bugfix: Correctly identify consolidations containing zero-value OP_RETURN outputs
  without misclassifying other zero-value external outputs.
- Bugfix: Prevent duplicate WIF Store keys and multisig wallets after restarting.
- Bugfix: Require HSM policies to explicitly allow any path before signing BIP-322 messages with WIF Store keys.
- Bugfix: Reject foreign inputs in BIP-322 Proof of Reserves transactions.
- Bugfix: Fixed PSBT uploads being mistaken for partial firmware uploads.
- Bugfix: Reject BIP388 wallet policy imports with non-ASCII or non-printable names.
- Bugfix: Reject duplicate singleton keys in PSBT maps.
- Bugfix: Restore the ability to view the device-generated seed before adding user
  entropy, which was available in the previous dice-roll workflow but was inadvertently
  removed in 5.6.1/1.5.1Q. The new **View TRNG Words** menu item displays the full
  256-bit seed from the STM32 TRNG, SE1, and SE2 as 24 BIP39 words, allowing independent
  verification of dice-roll or coin-flip mixing.
- Bugfix: Simulator crashed on Bless Firmware, due to a desynced LED pipe. Thanks to
  [@hitechhayekian](https://github.com/hitechhayekian).
- Bugfix: Fixed invalid signatures when signing transactions containing both SegWit v0 and Taproot inputs.
- Bugfix: Hide Change Main PIN while a temporary seed or BIP-39 passphrase wallet is active.
- Bugfix: With an empty master wallet and an active temporary seed, keep imports and backup restores temporary instead of treating them as master-seed changes.
- Bugfix: Do not misidentify future-version SegWit outputs as Taproot change.
- Bugfix: Reject unsupported Taproot leaf versions during PSBT signing (only Tapscript `0xc0` is supported).
- Bugfix: Correctly serialize future even TapLeaf versions.
- Bugfix: Report the correct transaction ID when finalized MuSig transactions contain scriptSigs.
- Security hardening: Remove the unused USB CDC/VCP serial interface from normal
  operation and keyboard emulation.

# Mk4 Specific Changes

## 6.6.1X - 2026-08-31

- all of the above
- synced with master up to and including `5.6.1`


# Q Specific Changes

## 6.6.1QX - 2026-08-31

- all of the above
- synced with master up to and including `5.6.1`


## 2026-07-31 Hotfix Versions: 6.6.0X & 6.6.0QX

**Urgent hotfix to correct a limited entropy bug**

Please regenerate seeds only with this version of the firmware and any
later updates from today onwards.

On **Mk4 and Q**, entropy may be as low as ~72 bits. This is
well below our target of 128 bits.

Follow the steps listed in
[our blog announcement](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
to be safe, and please be careful not to cut corners or rush this process.

### Shared Improvements - Both Mk4 and Q

- Bugfix: Renaming a MiniScript wallet could rename a different stored wallet when wallets from multiple chains were present

# Shared Improvements - Both Mk4 and Q

- New Feature: Ability to sign MuSig2 UTXOs. Read more [here](https://github.com/Coldcard/firmware/blob/new_edge/docs/musig.md)
- New Feature: BIP-322 Proof of Reserves for Miniscript & MuSig2 UTXOs
- Bugfix: PSBT global XPUBs validation when signing with specific wallet
- Bugfix: Do not allow sighash DEFAULT outside taproot context

# Mk4 Specific Changes

## 6.5.0X - 2026-03-24

- synced with master up to `5.5.0`


# Q Specific Changes

## 6.5.0QX - 2026-03-24

- synced with master up to `1.4.0Q`


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
