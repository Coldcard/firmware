# Change Log

This lists the new changes that have not yet been published in a normal release.

**In an attempt to avoid constant rebasing, please leave a blank line between
your addition and anything else already in this file.**

# Shared Improvements - Both Mk and Q

- Enhancement: Warn before installing firmware signed by an external contributor
  or downgrading from the currently installed firmware. Thanks to Huzaifa Jawaid for his suggestion.

- Bugfix: Fix device crash when message-signing input is valid JSON but not an
  object (NFC / QR / SD `.json` file). Thanks to [@Amiga500](https://github.com/Amiga500).

- Enhancement: Support per-input required height and time locktimes in PSBTv2 transactions.

- Bugfix: Harden PSBTv2 parsing by rejecting key data on singleton fields,
  malformed global input/output count encodings, and files missing the required
  global version.

- Enhancement: Optionally show Seed Vault names for temporary seed fingerprints
  at the top of the home menu.


# Mk Specific Changes

## 5.6.3 - 2026-09-xx

- tbd


# Q Specific Changes

## 1.5.3Q - 2026-09-xx

- Bugfix: Prevent unintended master seed replacement when scanning seed words
  or an extended private key from Ready To Sign or the Key Teleport retry screen.

- tbd
