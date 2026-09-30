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

- New Feature: Codex32 (BIP-93) secrets and Shamir secret sharing. Generate or import Codex32
  wallets, split the active wallet into two to nine Shamir shares with **Shamir Split**, and
  restore it with **Shamir Recover**. Word wallets split as `cw1`, raw master seeds as `ms1`,
  and extended-key wallets as `cx1`. CW1 and CX1 are COLDCARD extensions that require
  explicit support in recovery software.
- Enhancement: Support per-input required height and time locktimes in PSBTv2 transactions.
- Enhancement: Warn before installing firmware signed by an external contributor
  or downgrading from the currently installed firmware. Thanks to Huzaifa Jawaid for suggestion.
- Enhancement: Optionally show Seed Vault names for temporary seed fingerprints
  at the top of the home menu.
- Bugfix: Fix device crash when message-signing input is valid JSON but not an
  object (NFC / QR / SD `.json` file). Thanks to [@Amiga500](https://github.com/Amiga500).
- Bugfix: Harden PSBTv2 parsing by rejecting key data on singleton fields,
  malformed global input/output count encodings, and files missing the required
  global version.


# Mk Specific Changes

## 5.6.3 - 2026-09-30

- All of the above.


# Q Specific Changes

## 1.5.3Q - 2026-09-30

- Bugfix: Prevent unintended master seed replacement when scanning seed words
  or an extended private key from Ready To Sign or the Key Teleport retry screen.



# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk.md` (Mk4 and Mk5)](History-Mk.md)
- [`History-Mk3.md`](History-Mk3.md)
