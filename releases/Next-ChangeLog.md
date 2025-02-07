# Change Log

This lists the new changes that have not yet been published in a normal release.


# Shared Improvements - Both Mk4 and Q

- New signing features:
    - JSON message signing. Use JSON object to pass data to sign in form
        `{"msg":"<required msg>","subpath":"<optional sp>","addr_fmt": "<optional af>"}`
    - Sign message from note text, or password note
    - Sign message with key resulting from positive ownership check. Press (0) and
      enter or scan message text to be signed.
    - Sign message with key selected from Address Explorer Custom Path menu. Press (2) and
      enter or scan message text to be signed.
- Enhancement: New address display format improves address verification on screen (groups of 4).
- Deltamode enhancements:
    - Hide Secure Notes & Passwords in Deltamode. Wipe seed if notes menu accessed. 
    - Hide Seed Vault in Deltamode. Wipe seed if Seed Vault menu accessed. 
    - Catch more DeltaMode cases in XOR submenus. Thanks [@dmonakhov](https://github.com/dmonakhov)
- Enhancement: Add ability to switch between BIP-32 xpub, and obsolete
  SLIP-132 format in `Export XPUB`
- Enhancement: Use the fact that master seed cannot be used as ephemeral seed, to show message 
  about successful master seed verification.
- Enhancement: Allow devs to override backup password.
- Enhancement: Add option to show/export full multisg addresses without censorship. Enable
  in `Settings > Multisig Wallets > Full Address View`.
- Change: If derivation path is omitted during message signing, default is used 
  based on address format (`m/44h/0h/0h/0/0` for p2pkh, and `m/84h/0h/0h/0/0` for p2wpkh). 
  Default is no longer root (m).
- Bugfix: Sometimes see a struck screen after _Verifying..._ in boot up sequence.
  On Q, result is blank screen, on Mk4, result is three-dots screen.
- Bugfix: Do not allow to enable/disable Seed Vault feature when in temporary seed mode.
- Bugfix: Bless Firmware causes hanging progress bar.
- Bugfix: Prevent yikes in ownership search.
- Bugfix: Factory-disabled NFC was not recognized correctly.
- Bugfix: Be more robust about flash filesystem holding the settings.
- Bugfix: Do not include sighash in PSBT input data, if sighash value is `SIGHASH_ALL`.
- Change: Do not purge settings of current active tmp seed when deleting it from Seed Vault.
- Change: Rename Testnet3 -> Testnet4 (all parameters unchanged).


# Mk4 Specific Changes

## 5.4.1 - 2024-??-??

- Enhancement: Export single sig descriptor with simple QR.


# Q Specific Changes

## 1.3.1Q - 2024-??-??

- New Feature: Verify Signed RFC messages via BBQr
- New Feature: Sign message from QR scan (format has to be JSON)
- Enhancement: Sign scanned Simple Text by pressing (0). Next screens query information about key to use. 
- Bugfix: Properly re-draw status bar after Restore Master on COLDCARD without master seed.
