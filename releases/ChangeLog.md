# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

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
- Recovery SD Card image building moved into its own repo:
  [github.com/Coldcard/recovery-images](https://github.com/Coldcard/recovery-images)


# Mk4 Specific Changes

## 5.3.0 - 2024-05-02

- Enhancement: When providing 12 or 18 word seed phrase, valid final word choices
  are presented in a new menu.
- Enhancement: Move dice rolls (for generating master seed) to `Advanced` submenu.
- Enhancement: Using "Verify Address" in NFC Tools menu, allows entry of a payment address
  and reports if it is part of a wallet this Coldcard knows the key for. Includes Multisig
  and single sig wallets.
    - searches up to the first 1528 addresses (external and change addresses)
    - stores data as it goes to accelerate future uses
    - worst case, it can take up to 2 minutes to rule out an address, but after that it is fast!
- Bugfix: Constant `AFC_BECH32M` incorrectly set `AFC_WRAPPED` and `AFC_BECH32`.
- Bugfix: Fix inability to activate Duress Wallet as temporary seed when master seed is 12 words.
- Bugfix: Yikes when using BIP39 passphrase with temporary seed without master seed set.
- Bugfix: v1 and v2 QRs too small and not readable (fixed)
- Bugfix: Show indexes for full range of addresses we are able to generate during QR display.
- Tweak: Force default HW settings (USB,NFC,VDisk OFF) after clone/backup is restored.
- Tweak: Cleanup in NFC code: repeated messages, "Unable to find data expectd in NDEF", removed.
- Tweak: Function button change from (6) to (0) to view change addresses in `Address Explorer`
- Tweak: Function button change from (2) to (0) to switch to derived secret in `Derive Seed B85`
- Bootrom version bump: 3.2.0 released with no functional changes except those shared with Q.

# Q Specific Changes

## 1.2.0Q - 2024-05-02

- Enhancement: Allow export of multisig XPUBs via BBQr
- Enhancement: Import multisig via QR/BBQr - both legacy COLDCARD export and descriptors supported
- Enhancement: Status bar text is sharper now
- Enhancement: Added ability to write signed PSBT/txn to lower (B) SD slot when both cards inserted
- Bugfix: Fullscreen display of v23 and v24 QRs were too dense and hard to read
- Bugfix: Battery idle timeout also considers last progress bar update
- Bugfix: Allow `Send Password` (keystrokes) of capital letters of alphabet
- Bugfix: Pressing SYM+SHIFT was toggling CAPS continuously. Now toggles once only
- Bugfix: Restrict keys that can be pressed during seed entry after final word inserted


# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

