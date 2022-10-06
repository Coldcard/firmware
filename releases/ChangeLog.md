## 5.0.8 - 2022-11-??
- Enhancement: Add ability to import multisig wallet via Virtual Disk
- Enhancement: Add ability to import extended private key via Virtual Disk and via NFC
- Enhancement: Offer import/export from/to Virtual Disk in UI
- Enhancement: Ability to import seed in compact/truncated form (max 4 letters of each word)
- Bugfix: allow export of Wasabi skeleton for Bitcoin Regtest

## 5.0.7 - 2022-10-05

- NFC Enhancements: 
    - In older versions, multisig NFC import not offered if a MicroSD card was
      inserted, now this option provided Settings > Multisig Wallets > Import via NFC. NFC has
      to be enabled for this option to be visible in the menu.
    - NFC message signing (Advanced/Tools > NFC Tools > Sign Message). Send message
      in same format as Sign Text File over NFC, approve signing on Coldcard and send signed
      ASCII-armored message back over NFC.
    - Show address over NFC (Advanced/Tools > NFC Tools > Show Address).
    - Bugfix: Improved NFC commands exception handling 
    - Bugfix: Share single address over NFC from address explorer menu.
- HSM Enhancements: 
    - Dynamic HSM Whitelisting. Foreign outputs can be attested-to by signing them with
      private key corresponding to the address specified in HSM policy. Attestation
      signature MUST be provided in PSBT in a new proprietary field.
    - HSM policy hash is now displayed during first activation and in the HSM status
      response. This enables fast comparison against known policy hashes.
    - Thanks to [@straylight-orbit](https://github.com/straylight-orbit) for above items!
    - Now ignores HSM commands over USB, by default. To enable and use HSM features,
      go to Advanced/Tools > Enable HSM > Enable
- New Feature: Ephemeral Seeds: Advanced/Tools > Ephemeral Seed (more info in `docs/ephemeral.md`)
- Enhancement: New menu wraparound settings which allow you to scroll past top and bottom of 
  any menu (Settings > Menu Wrapping).
- Enhancement: Allow import of new descriptor type which specify both internal/external
  in single string (ie. `../<0;1>/..`). We still export in older format.
- Enhancement: add ability to specify address format in text file to be signed (3rd line of file)
- Bugfix: Correct parsing of unknown fields in PSBT: they are now passed through.
- Bugfix: Using lots of trick pins (7+), could lead to a case where the Coldcard would
  not accept the main pin, but trick pins continued to work. This release adds a
  workaround to avoid getting into that situation, and new units from the factory will
  ship with an updated bootrom (version 3.1.5).

## 5.0.6 - 2022-07-29

- Security release: Virtual Disk feature updated with bugfix to address potential security
  concerns and new security hardening changes. Upgrade strongly recommended.

## 5.0.5 - 2022-07-20

- Enhancement: BIP-85 derived passwords. Pick an index number, and COLDCARD will derive
  a deterministic, strong (136 bit) password for you. It will even type the password by
  emulating a USB keyboard. See new areas: Settings > Keyboard EMU and
  Settings > Derive Seed B85 > Passwords.
- Documentation: added `docs/bip85-passwords.md` documenting new BIP-85 passwords and
  keyboard emulation.
- Enhancement: BIP-85 derived values can now be exported via NFC, in addition to QR code.
- Enhancement: Allow signing transaction where foreign UTXO(s) are missing.
  Only applies to cases where partial signatures are being created.
  Thanks to [@straylight-orbit](https://github.com/straylight-orbit)
- Enhancement: QR Codes are now easier to scan in bright light. Thanks
  to [@russeree](https://github.com/russeree) for this useful fix!
- Bugfix: order of multisig wallet registration does NOT matter.
- Enhancement: Support import of multisig wallet from descriptor (only sortedmulti, BIP-67).
  Also support export of multsig wallet as descriptor.
- Enhancement: Address explorer can show "change" addresses for standard derivation paths
  for both single and multisig wallet.
- New tutorial: 2of2 multisig with 2x Coldcard signing device, and bitcoin-qt as
  coordinator, see `docs/bitcoin-core2of2desc.md`
- Enhancement: `OP_RETURN` is now a known script and is displayed in ascii when possible
- Bugfix: allow unknown scripts in HSM mode, with warning.

## 5.0.4 - 2022-05-27

- Enhancement: Optional USB protocol change which binds the ephemeral ECDH encryption 
  keys more tightly. Best used in HSM mode where a single long-term USB connection is
  expected. Thanks to [@DON-MAC-256](https://github.com/DON-MAC-256) for this feature.
- Enhancement: In HSM mode, when more than 1k approvals, handle overflow in display,
  thanks to [@straylight-orbit](https://github.com/straylight-orbit)
- Enhancement: Adds support for "Regtest" which are testnet coins on an isolated blockchain.
  It's only useful for developers, and should not be used otherwise.
- Enhancement: Major rework of test setup to use BitcoinCore on regtest, and support Linux devs.
- Enhancement: Pause waiting for incoming NFC data increased to 3 seconds, from one. Better 
  error reporting for debug purposes.
- Corrects obsolete domain name (`coldcardwallet.com`) in repro build script, thanks to
  [@xavierfiechter](https://github.com/xavierfiechter)
- Documentation: Secure element related fixes from [@lucasmoten](https://github.com/lucasmoten)
- Bugfix: Error if clone (receiving end) started without first inserting SD card, fixed.
- Bugfix: Reproducible build issues corrected, thanks to [@Ademan](https://github.com/Ademan)

## 5.0.3 - 2022-05-04

- Enhancement: Support P2TR outputs (pay to Taproot) in PSBT files. Allows
  on-screen verification of P2TR destination addresses (`bc1p..`) so you can send
  your BTC to them. Does **not** support signing, so you cannot operate a Taproot
  wallet with COLDCARD as the signing device... yet.

## 5.0.2 - 2022-04-19

- Adds NFC support for exporting to all the various wallet-types.
- Multisig wallet specs can be exported via NFC, and new multisig wallet can be imported over NFC.
- Menu re-org: 
    - "Export Wallet" now directly under Advanced Menu and
      duplicate link remains under File Management.
    - "Dump Summary" moved from Backup menu to Export
    - "Advanced" now "Advanced/Tools"
    - shuffled contents of Advanced menu
    - "New Wallet" renamed "New Seed Words"
- Text changes to match reality that writing "files" can happen to SD card or VirtDisk or NFC.
- New users will see some prompts to help them get started, after seed is set.
- 12 word seeds are now an option from the start, either by TRNG or Dice Roll
- Dice rolls (for new seed) moved from Import (a misnomer) to "New Seed Words"
- Duress wallet (from trick pin) will be 12-words if your true seed is 12-words
- Bugfix: allow sending to scripts that we cannot parse, with a warning, to support
  `OP_RETURN` and other outputs we don't understand well (yet).
- Bugfix: sending NFC things into the Coldcard was not working, fixed.


## 5.0.1 - 2022-03-24

- bugfix: red light whenever MCU keys changed or seed installed first time.

## 5.0.0 - 2022-03-14

Mk4 - New hardware

- (Mk3&Mk4) Performance improved: some internal objects cached to reduce delays when
  accessing master secret. Helps address explorer, many USB commands and signing.
- Enhancement: Power-down during the login countdown now resets the time delay to force 
  attacker (or yourself) to start over with full delay time.
- Enhancement: if an XFP of zero is seen in a PSBT file, assume that should be replaced by
  our current XFP value and try to sign the input (same for change outputs and change-fraud
  checks). This makes building a workable PSBT file easier and could be used to preserve
  privacy of XFP value itself. A warning is shown when this happens.
- Enhancement: "Advanced > Export XPUB" provides direct way to show XPUB (or ZPUB/YPUB) for
  BIP-84 / BIP-44 / BIP-49 standard derivations, as a QR. Also can show XFP and master XPUB.
- (Mk4) PSBT files up to 2 megabytes now supported
