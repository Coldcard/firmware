# Change Log

This lists the new changes that have not yet been published in a normal release.


# Shared Improvements - Both Mk4 and Q

- Enhancement: Hide Secure Notes & Passwords in Deltamode. Wipe seed if notes menu accessed. 
- Enhancement: Hide Seed Vault in Deltamode. Wipe seed if Seed Vault menu accessed. 
- Enhancement: Ability to switch between BIP-32 XPUB and SLIP-132 garbage in `Export XPUB`
- Bugfix: Sometimes see a struck screen after _Verifying..._ in boot up sequence.
  On Q, result is blank screen, on Mk4, result is three-dots screen.
- Bugfix: Do not allow to enable/disable Seed Vault feature when in temporary seed mode
- Bugfix: Bless Firmware causes hanging progress bar
- Bugfix: Prevent yikes in ownership search
- Change: Do not allow to purge settings of current active tmp seed when deleting it from Seed Vault
- Change: Do not include sighash in PSBT input data, if sighash value is SIGHASH_ALL
- Change: Testnet3 -> Testnet4 (all parameters are the same)



# Mk4 Specific Changes

## 5.4.1 - 2024-??-??

- Enhancement: Export single sig descriptor with simple QR


# Q Specific Changes

## 1.3.1Q - 2024-??-??

- Bugfix: Properly re-draw status bar after Restore Master on COLDCARD without master seed.
