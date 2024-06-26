*See ChangeLog.md for more recent changes, these are historic versions*

## 1.2.1Q - 2024-05-09

- _Important Bugfix_: Already imported multisig wallets would show errors when signing. This
  was caused by our internal change in key path notation from `84'` (prime) to `84h` (hardened).
- Enhancement: Add `Nunchuk` and `Zeus` options to `Export Wallet`
- Enhancement: `View Identity` shows temporary seed active at the top
- Enhancement: Can specify start index for address explorer export and browsing
- Enhancement: Allow unlimited index for BIP-85 derivations. Must be enabled first in `Danger Zone` 
- Change: `Passphrase` menu item is no longer offered if BIP39 passphrase
  already in use. Use `Restore Master` with ability to keep or purge current
  passphrase wallet settings.
- Change: Removed ability to add passphrase to master seed if active temporary seed.
- Change: Wipe LFS during `Lock Down Seed` and `Destroy Seed`
- Bugfix: Do not allow non-ascii or ascii non-printable characters in multisig wallet name
- Bugfix: `Brick Me` option for `If Wrong` PIN caused yikes.
- Bugfix: Properly handle and finalize framing error response in USB protocol.
- Bugfix: Handle ZeroSecretException for BIP39 passphrase calculation when on temporary
  seed without master secret
- Bugfix: Saving passphrase on SD Card caused a freeze that required reboot
- Bugfix: Properly verify signed armored message with regtest address
- Bugfix: Create ownership file when generating addresses export CSV
- Recovery SD Card image building moved into its own repo:
  [github.com/Coldcard/recovery-images](https://github.com/Coldcard/recovery-images)
- Bugfix: Reload trick pins before checking for active duress wallet.

- Enhancement: Allow export of multisig XPUBs via BBQr
- Enhancement: Import multisig via QR/BBQr - both legacy COLDCARD export and descriptors supported
- Enhancement: Status bar text is sharper now
- Enhancement: Added ability to write signed PSBT/txn to lower (B) SD slot when both cards inserted
- Bugfix: Fullscreen display of v23 and v24 QRs were too dense and hard to read
- Bugfix: Battery idle timeout also considers last progress bar update
- Bugfix: Allow `Send Password` (keystrokes) of capital letters of alphabet
- Bugfix: Pressing SYM+SHIFT was toggling CAPS continuously. Now toggles once only
- Bugfix: Restrict keys that can be pressed during seed entry after final word inserted

## 1.1.0Q - 2024-04-02

- Enhancement: Scan any QR and report if it is part of a wallet this Coldcard knows
  the key for. Includes Multisig and single sig wallets.
    - searches up to the first 1528 addresses (external and change addresses)
    - stores data as it goes to accelerate future uses
    - worst case, it can take up to 2 minutes to rule out an address, but after that it is fast!
- Enhancement: Calculator login mode. When enabled, the usual PIN entry screen is
  replaced with a functional calculator. Enter your PIN as `12-12` or `12 12` to get it.
  To verify anti-phishing words, use `12-`. 
- Bugfix: Key right of L was giving back quote, should have been single-quote. SYM+E for back quote.
- Bugfix: Constant `AFC_BECH32M` incorrectly set `AFC_WRAPPED` and `AFC_BECH32`.
- Bugfix: Base64 PSBT via QR was not properly decoded.
- Bugfix: Fix inability to activate Duress Wallet as temporary seed when master seed is 12 words.
- Bugfix: Switch to BBQr for larger data exports at a new lower size threshold.
    - Generally, won't show tiny QR anymore with 1:1 pixels.
    - Sparrow wallet export will always be BBQr now.
    - Most other exports fit into a reasonable single QR.
- Bugfix: fixed `Type Passwords` a.k.a emulated keystrokes
- Bugfix: Yikes when using BIP39 passphrase with temporary seed without master seed set.
- Tweak: Default idle timeout when on battery, was reduced to 10 minutes from 30.
- Tweak: Cursor movements wrap around if menu is longer than screen height.
- Tweak: Force default HW settings (USB,NFC,VDisk OFF) after clone/backup is restored.
- Tweak: Cleanup in NFC code: repeated messages, "Unable to find data expectd in NDEF", removed.

## 1.0.1Q - 2024-03-14

- Enhancement: Move dice rolls (for generating master seed) to `Advanced` submenu.
- Cleanup reproducible building / start process of backporting to Mk4.

## 1.0.0Q - 2024-03-10

- Bump major verison number, remove BETA marking.
- Finalize version 1.0.4 bootrom (no real changes).
- Bugfix: Yikes when saving seed words imported by QR.
- Bugfix: Crash w/ blank screen sometimes, either on power-up or after upgrading firmware.
- Testing: Accelerate internal testing by reviving "headless" mode of simulator.

## 0.0.8Q - 2024-03-02

- BBQr display changes: 
    - if less than 12 frames would result, uses simpliest QR that can fit on 
      screen at 3x or 2x size. Result is easier to scan BBQr's.
    - progress bar along bottom drawn differently
    - in some cases, the status bar area (at top) will be used to show QR
    - added: Advanced > Danger Zone > Debug Functions > BBQr Demo
- Says "Loading..." not "Wait..." during login process.
- Many more test cases.

## 0.0.7Q - 2024-02-26

- bugfix: BBQr display of some segwit transactions would sometimes fail with message
  about "non hex digit"
- bugfix: very obscure bug in low level code could cause txid to be miscalculated
  if all the conditions occured just right
- Animated BBQr are shown as chunkier QR's to make them easier for other devices to scan.
- Supports QR export from Wallet Exports: will be either text file (U) or JSON (J)
  BBQr sequence, but only if it cannot fit into normal single QR.

## 0.0.6Q - 2024-02-22

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

## 0.0.5Q - 2024-02-16

- fixes and changes from version 5.2.2 of Mk4 encorporated
- bugfix: save bip-39 password to absent SD card
- import multisig wallet via descriptor inside a QR
- too much whitespace in locktime details
- bugfix: cant detect SD card in Ready to Sign...
- WIF private key detected when scaning QR (display only for now)

## 0.0.4Q - 2024-02-15

- BBQr animation display smoother
- test cases fixed, bugs that were exposed, fixed.
- lots of bugfixes: batch signing, seed XOR, big backups
- "Ready to Sign" messaging improved, slot B support.
- block firmware upgrade when battery very low

## 0.0.3Q - 2024-02-08

- first test-only release 

