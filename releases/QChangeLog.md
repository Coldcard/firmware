# Q Unique Features / Improvements

## Features

- Secure Notes & Passwords: stash text and/or passwords in your Q. 
- Scan Any QR: and the Q will figure something useful to do with it.
- Press QR or NFC key in many contexts and useful things happen (may not be documented)
- QR icon in corner: can paste into text field from QR


## Little Things

- whitens TRNG source for seed generation with double sha256 instead of single


## Secure Notes & Passwords

- store notes (freeform text) and/or passwords
- "note" has a title and freform text
- "password" has title, username, website, and notes.
- detects Google Auth app export QR and provides title
- detects OTP 2FA (RFC ?) QR code and provides nice title
- detects URL in QR, and uses domain name as title

# Releases

## 0.0.3 - 2024-02-08

- first test-only release 

## 0.0.4 - 2024-02-15

- BBQr animation display smoother
- test cases fixed, bugs that were exposed, fixed.
- lots of bugfixes: batch signing, seed XOR, big backups
- "Ready to Sign" messaging improved, slot B support.
- block firmware upgrade when battery very low

## 0.0.5 - 2024-02-16

- fixes and changes from version 5.2.2 of Mk4 encorporated
- bugfix: save bip-39 password to absent SD card
- import multisig wallet via descriptor inside a QR
- too much whitespace in locktime details
- bugfix: cant detect SD card in Ready to Sign...
- WIF private key detected when scaning QR (display only for now)

## 0.0.6 - 2024-02-22

- bugfix: randomize keys for PIN entry
- when picking files, we just skip to showing you the files options (or picking the
  single winner) rather than talking about it first.
- BIP-39 passphrase process completely streamlined
- batch signing now offered when we see two or more signable PSBT's on the card
- bugfix: can now reformat SD card in B slot
- move away from `44'` (prime) for hardened derivation paths, in favour of `44h`; both accepted
  for input, but we are going to display `44h` style going forward.
- bugfix: (QR) or other double-wide chars would be garbled if half off right edge
- cleanups, bugfixes


## 0.0.7 - 2024-02-26

- bugfix: BBQr display of some segwit transactions would sometimes fail with message
  about "non hex digit"
- bugfix: very obscure bug in low level code could cause txid to be miscalculated
  if all the conditions occured just right
- Animated BBQr are shown as chunkier QR's to make them easier for other devices to scan.
- Supports QR export from Wallet Exports: will be either text file (U) or JSON (J)
  BBQr sequence, but only if it cannot fit into normal single QR.

