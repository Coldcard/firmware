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



