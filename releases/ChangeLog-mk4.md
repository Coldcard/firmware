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
