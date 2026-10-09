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

- New Feature: Codex32 (BIP-93) secrets and Shamir secret sharing. Generate or import Codex32
  wallets, split the active wallet into two to nine Shamir shares with **Shamir Split**, and
  restore it with **Shamir Recover**. Word wallets split as `cw1`, raw master seeds as `ms1`,
  and extended-key wallets as `cx1`. CW1 and CX1 are COLDCARD extensions that require
  explicit support in recovery software.
- Bugfix: Clear the Set Nickname checkmark when the nickname is removed, including
  empty nicknames saved by earlier firmware. Thanks to [@bonitoman](https://github.com/bonitoman).
- Enhancement: Warn before installing firmware signed by an external contributor
  or downgrading from the currently installed firmware. Thanks to Huzaifa Jawaid for suggestion.
- Bugfix: Abort a pending firmware upgrade if its staged image is overwritten before
  approval. Thanks to Huzaifa Jawaid.
- Enhancement: Optionally show Seed Vault names for temporary seed fingerprints
  at the top of the home menu.
- Enhancement: Support per-input required height and time locktimes in PSBTv2 transactions.
- New Feature: Added USB ncry v3 authenticated encryption with direction-separated keys and replay protection
- Enhancement: Warn when a transaction's block-height `nLockTime` is more than
  ten years beyond the Bitcoin block height known to the firmware.
- Bugfix: Reject malformed PSBTs containing P2SH-P2WSH inputs with a missing or
  incorrect redeem script, preventing transactions with an unknown fee from
  proceeding to approval.
- Bugfix: Reject foreign inputs from BIP-322 Proof of Reserves, including inputs
  disguised with forged key-path metadata or partial signatures.
- Bugfix: Add a block-height reset to Single-Signer Spending Policy's
  **Last Violation** screen after policy bypass, matching CCC.
- Enhancement: Retain up to 128 UTXO cache entries across restarts.
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


# Mk4 Specific Changes

## 6.6.2X - 2026-0x-xx

- all of the above
- synced with master up to and including `5.6.2`


# Q Specific Changes

## 6.6.2QX - 2026-0x-xx

- all of the above
- synced with master up to and including `1.5.2Q`
- Bugfix: Prevent unintended master seed replacement when scanning seed words
  or an extended private key from Ready To Sign or the Key Teleport retry screen.



# Release History

- [`History-Edge.md`](History-Edge.md)
