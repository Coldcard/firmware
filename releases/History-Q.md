*See ChangeLog.md for more recent changes, these are historic versions*


## 1.3.0Q - 2024-09-12

- New Feature: Opt-in support for unsorted multisig, which ignores BIP-67 policy. Use
  descriptor with `multi(...)`. Disabled by default, Enable in 
  `Settings > Multisig Wallets > Legacy Multisig`. Recommended for existing multisig
  wallets, not new ones.
- New Feature: Named multisig descriptor imports. Wrap descriptor in json:
    `{"name:"ms0", "desc":"<descriptor>"}` to provide a name for the menu in `name`.
  instead of the filename. Most useful for USB and NFC imports which have no filename, 
  (name is created from descriptor checksum in those cases).
- New Feature: XOR from Seed Vault (select other parts of the XOR from seeds in the vault).
- Enhancement: upgrade to latest 
  [libsecp256k1: 0.5.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.5.0) 
- Enhancement: Signature grinding optimizations. Now about 30% faster signing!
- Enhancement: Improve side-channel protection: libsecp256k1 context randomization now happens
  before each signing session.
- Enhancement: Allow JSON files in `NFC File Share`.
- Change: Do not require descriptor checksum when importing multisig wallets.
- Bugfix: Do not allow import of multisig wallet when same keys are shuffled.
- Bugfix: Do not read whole PSBT into memory when writing finalized transaction (performance).
- Bugfix: Prevent user from restoring Seed XOR when number of parts is smaller than 2.
- Bugfix: Fix display alignment of Seed Vault menu.
- Bugfix: Properly handle null data in `OP_RETURN`.
- Bugfix: Do not allow lateral scroll in Address Explorer when showing single address
  from custom path.
- Change: Remove Lamp Test from Debug Options (covered by selftest).
- New Feature: Seed XOR can be imported by scanning SeedQR parts.
- New Feature: Input backup password from QR scan.
- New Feature: (BB)QR file share of arbitrary files.
- New Feature: `Create Airgapped` now works with BBQRs.
- Change: Default brightness (on battery) adjusted from 80% to 95%.
- Bugfix: Properly clear LCD screen after BBQR is shown.
- Bugfix: Writing to empty slot B caused broken card reader.
- Bugfix: During Seed XOR import, display correct letter B if own seed already added to the mix.
- Bugfix: Stop re-wording UX stories using a regular expression.
- Bugfix: Fixed "easy exit" from quiz after split Seed XOR.


## 1.2.3Q - 2024-07-05

- New Feature: PushTX: once enabled with a service provider's URL, you can tap the COLDCARD
  and your phone will open a webpage that transmits your freshly-signed transaction onto
  the blockchain. See `Settings > NFC Push Tx` to enable and select service provider, or your
  own webpage. More at <https://pushtx.org>. You can also use this to broadcast any
  transaction found on the MicroSD card (See `Tools > NFC Tools > Push Transaction`).
- New Feature: Transaction Output Explorer: allows viewing all output details for
  larger txn (10+ output, 20+ change) before signing. Offered for large transactions only
  because we are already showing all the details for typical transactions.
- New Feature: Setting to enable always showing XFP as first item in home menu.
- Enhancement: When signing, show sum of outgoing value at top. Always show number
  of inputs/outputs and total change value.
- Enhancement: Add `Sign PSBT` shortcut to `NFC Tools` menu
- Enhancement: Stricter p2sh-p2wpkh validation checks.
- Enhancement: Show master XFP of BIP-85 derived wallet in story before activation. Only
  words and extended private key cases.
- Enhancement: Add `Theya` option to `Export Wallet`
- Enhancement: Mention the need to remove old duress wallets before locking down temporary seed.
- Bugfix: Fix PSBTv2 `PSBT_GLOBAL_TX_MODIFIABLE` parsing.
- Bugfix: Decrypting Tapsigner backup failed even for correct key.
- Bugfix: Clear any pending keystrokes before PSBT approval screen.
- Bugfix: Display max 20 change outputs in when signing, and max 10 of largest outputs, and
  offer the Transaction Output Explorer if more to be seen.
- Bugfix: Calculate progress bar correctly in Address Explorer after first page.
- Bugfix: Search also Wrapped Segwit single sig addresses if P2SH address provided, not just
  multisig (multisig has precedence for P2SH addresses)
- Bugfix: Address search would not find addresses for non-zero account numbers that had
  been exported but not yet seen in a PSBT.
- (v5.3.3/1.2.3Q) Bugfix: Trying to set custom URL for NFC push transaction caused yikes error.

- Enhancement: Coldcard multisg export/import format detected in `Scan Any QR Code`.
- Enhancement: Support newer-version QR scanner modules.
- Bugfix: Exporting BIP-85 derived entropy via NFC was offered even when NFC disabled,
  leading to a Yikes error.
- Bugfix: Properly clear LCD screen after simple QR code is shown


## 1.2.3Q - 2024-07-05

- Bugfix: Trying to set custom URL for NFC push transaction caused yikes error.
- Bugfix: Properly clear LCD screen after simple QR code is shown

## 1.2.2Q - 2024-06-26

- New Feature: PushTX: once enabled with a service provider's URL, you can tap the COLDCARD
  and your phone will open a webpage that transmits your freshly-signed transaction onto
  the blockchain. See `Settings > NFC Push Tx` to enable and select service provider, or your
  own webpage. More at <https://pushtx.org>. You can also use this to broadcast any
  transaction found on the MicroSD card (See `Tools > NFC Tools > Push Transaction`).
- New Feature: Transaction Output Explorer: allows viewing all output details for
  larger txn (10+ output, 20+ change) before signing. Offered for large transactions only
  because we are already showing all the details for typical transactions.
- New Feature: Setting to enable always showing XFP as first item in home menu.
- Enhancement: When signing, show sum of outgoing value at top. Always show number
  of inputs/outputs and total change value.
- Enhancement: Add `Sign PSBT` shortcut to `NFC Tools` menu
- Enhancement: Stricter p2sh-p2wpkh validation checks.
- Enhancement: Show master XFP of BIP-85 derived wallet in story before activation. Only
  words and extended private key cases.
- Enhancement: Add `Theya` option to `Export Wallet`
- Enhancement: Mention the need to remove old duress wallets before locking down temporary seed.
- Bugfix: Fix PSBTv2 `PSBT_GLOBAL_TX_MODIFIABLE` parsing.
- Bugfix: Decrypting Tapsigner backup failed even for correct key.
- Bugfix: Clear any pending keystrokes before PSBT approval screen.
- Bugfix: Display max 20 change outputs in when signing, and max 10 of largest outputs, and
  offer the Transaction Output Explorer if more to be seen.
- Bugfix: Calculate progress bar correctly in Address Explorer after first page.
- Bugfix: Search also Wrapped Segwit single sig addresses if P2SH address provided, not just
  multisig (multisig has precedence for P2SH addresses)
- Bugfix: Address search would not find addresses for non-zero account numbers that had
  been exported but not yet seen in a PSBT.

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

