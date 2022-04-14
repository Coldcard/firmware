## 5.0.2 - 2022-04-??

- Adds NFC support for exporting to all the various wallet-types.
- Menu re-org: 
    - "Export Wallet" now directly under Advanced Menu and
      duplicate link remains under File Management.
    - "Dump Summary" moved from Backup menu to Export
    - "Advanced" now "Advanced/Tools"
    - shuffled contents of Advanced menu
    - "New Wallet" renamed "New Seed Words"
- Text changes to cover reality that writing "files" can happen to SD card or VirtDisk or NFC.
- New users will see some prompts to help them get started, after seed is set.
- 12 word seeds are now an option from the start, either by TRNG or Dice Roll
- Dice rools (for new seed) moved from Import (a misnomer) to "New Seed Words"


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
