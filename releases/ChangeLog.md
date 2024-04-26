# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- Enhancement: Add `Nunchuk` option to `Export Wallet`
- Enhancement: Add `Zeus` option to `Export Wallet`
- Enhancement: `View Identity` shows temporary seed active on the top
- Enhancement: Allow to specify start index for address explorer export and browsing
- Enhancement: Allow unlimited index for BIP-85 derivations. Must be enabled first in `Danger Zone` 
- Change: `Passphrase` menu item is no longer offered if BIP39 passphrase
  already in use. Use `Restore Master` with ability to keep or purge current
  passphrase wallet settings.
- Change: Removed ability to add passphrase to master seed if active temporary seed.
- Change: Wipe LFS during `Lock Down Seed`
- Bugfix: Do not allow non-ascii or ascii non-printable characters in multisig wallet name
- Bugfix: `Brick Me` option for `If Wrong` PIN caused yikes.
- Bugfix: Properly handle and finalize framing error response in USB protocol.
- Recovery SD Card image building moved into its own repo:
  [github.com/Coldcard/recovery-images](https://github.com/Coldcard/recovery-images)


# Mk4 Specific Changes

## 5.3.0 - 2024-05-0X

- Enhancement: When providing 12 or 18 word seed phrase, valid final word choices
  are presented in a new menu.
- Enhancement: Using "Verify Address" in NFC Tools menu, allows entry of a payment address
  and reports if it is part of a wallet this Coldcard knows the key for. Includes Multisig
  and single sig wallets.
    - searches up to the first 1528 addresses (external and change addresses)
    - stores data as it goes to accelerate future uses
    - worst case, it can take up to 2 minutes to rule out an address, but after that it is fast!
- Bugfix: Saving passphrase on SD Card caused a freeze that required reboot
- Bootrom version bump: 3.2.0 released with no functional changes except those shared with Q.

# Q Specific Changes

## 1.2.0Q - 2024-05-0X

- Enhancement: Allow export of multisig XPUBs via BBQr
- Enhancement: Import multisig via QR/BBQr - both legacy COLDCARD export and descriptors supported
- Enhancement: Status bar text sharper now.
- Bugfix: Fullscreen display of v23 and v24 QRs were too dense and hard to read.
- Bugfix: Handle ZeroSecretException for BIP39 passphrase calculation when on temporary
  seed without master secret
- Bugfix: Battery idle timeout also considers last progress bar update
- Bugfix: Allow `Send Password` (keystrokes) of capital letters of alphabet
- Bugfix: Pressing SYM+SHIFT was toggling CAPS continuously. Now toggles once only.


# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

