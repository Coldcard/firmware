## July 2026 Security Advisory

- Versions from 2021 to July 2026 had a bug which produced poor entropy.
- Any secrets generated on a COLDCARD in that period should be regenerated and 
  funds moved on chain **immediately**.
- Master seeds can only be trusted from releases **after** these levels:
    - 5.6.0 (Mk4, MK5) 
    - 1.5.0Q (Q1) 
    - 4.2.0 (Mk3)
    - 6.6.0 (Edge Mk/Q)
- [Blog post and updates](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
- [Technical background on the bug](https://blog.coinkite.com/entropy-technical-backgrounder/)

# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

**Keep your COLDCARD up-to-date with each new releases. We are continuously improving!**

# Shared Improvements - Both Mk and Q

- New Feature: Added USB ncry v3 authenticated encryption for our USB communications
  protocol, now with direction-separated keys and replay protection.
- Enhancement: Warn when a transaction's block-height `nLockTime` is more than
  ten years beyond the Bitcoin block height known to the firmware.
- Enhancement: Retain up to 128 UTXO cache entries across restarts.
- Enhancement: Add the ability to view the device-generated seed before adding user
  entropy, which was available in the previous dice-roll workflow but was inadvertently
  removed in 5.6.1/1.5.1Q. The new **View TRNG Words** menu item displays the full
  256-bit seed from the STM32 TRNG, SE1, and SE2 as 24 BIP39 words, allowing independent
  verification of dice-roll or coin-flip mixing which follows.
- Bugfix: Reject duplicate singleton keys in PSBT maps.
- Bugfix: Add a block-height reset to Single-Signer Spending Policy's
  **Last Violation** screen after policy bypass, matching CCC.
- Bugfix: Cancelled PSBTs no longer persist claimed input amounts to the UTXO
  cache; amounts are committed only after signing, for inputs actually signed.
- Bugfix: Cache single-sig segwit change amounts at finalize, so understated
  input amounts are caught instead of silently trusted.
- Bugfix: Reject foreign inputs from BIP-322 Proof of Reserves, including inputs
  disguised with forged key-path metadata or partial signatures.
- Bugfix: Detect and abort transaction signing if a Virtual Disk firmware import
  overwrites the reviewed PSBT. Thanks to Huzaifa Jawaid.
- Bugfix: Reject malformed PSBTs containing P2SH-P2WSH inputs with a missing or
  incorrect redeem script, preventing transactions with an unknown fee from
  proceeding to approval.
- Bugfix: Abort a pending firmware upgrade if its staged image is overwritten before
  approval. Thanks to Huzaifa Jawaid.
- Bugfix: Reject cyclic FAT chains in virtual-disk file imports instead of hanging.
- Bugfix: Simulator crashed on Bless Firmware, due to a desynced LED pipe. Thanks to
  [@hitechhayekian](https://github.com/hitechhayekian).
- Bugfix: With an empty master wallet and an active temporary seed, keep imports and
  backup restores temporary instead of treating them as master-seed changes.
- Bugfix: Reject PSRAM virtual-disk files whose FAT metadata is inconsistent with the
  declared file size (oversized cluster chains, oversized fragment counts, spurious
  trailing fragments, final remainders exceeding the final fragment's capacity, or
  filesystems with more than one sector per cluster), fixing an integer underflow in
  `psram_copy_file`/`psram_mmap_file` that allowed out-of-bounds PSRAM writes, reads,
  and mappings from a compromised USB host.
- Bugfix: Hide Change Main PIN while a temporary seed or BIP-39 passphrase wallet is active.
- Bugfix: Reject PSBTv2 transactions with an out-of-range transaction version, matching
  the PSBTv0 parser. Previously a v2 PSBT with an invalid `nVersion` could be approved
  and signed, producing a transaction the network will not relay.
- Bugfix: Reject firmware images that extend past the world-checksum-covered flash region.
- Security hardening: Remove the unused USB CDC/VCP serial interface from normal
  operation and keyboard emulation mode.
- Bugfix: In Delta Mode, wipe the seed if anyone tries to view or activate a duress
  wallet's secret from the Trick PINs menu, instead of revealing it. Browsing the menu
  itself still works, so Delta Mode continues to look like normal operation.
- Bugfix: Reject non-ASCII BIP-39 passphrases (USB, saved-passphrase recall, and
  note/password lanes) instead of silently deriving a wallet incompatible with
  BIP-39-normalizing software.

# Mk Specific Changes

## 5.6.2 - 2026-09-03

- Bugfix: Require unrestricted HSM message-signing policy when signing BIP-322
  messages with WIF Store keys.


# Q Specific Changes

## 1.5.2Q - 2026-09-03

- All of the above.



# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk.md` (Mk4 and Mk5)](History-Mk.md)
- [`History-Mk3.md`](History-Mk3.md)

