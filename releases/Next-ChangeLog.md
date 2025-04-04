# Change Log

This lists the new changes that have not yet been published in a normal release.


# Shared Improvements - Both Mk4 and Q

- Huge new feature: CCC - ColdCard Cosign
    - COLDCARD holds a key in a 2-of-3 multisig, in addition to the normal signing key it has.
    - it applies a spending policy like an HSM:
        - velocity and magnitude limits
        - whitelisted destination addresses
        - 2FA authentication using phone app ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238))
    - but will sign its part of a transaction automatically if those condition are met, 
      giving you 2 keys of the multisig and control over the funds
    - spending policy can be exceed with help of the other co-signer (3rd key), when needed
    - cannot view or change the CCC spending policy once set, policy violations are not explained
    - existing multisig wallets can be used by importing the spending-policy-controlled key

- New Feature: Multisig transaction finalization. Allows to use [PushTX](https://pushtx.org/) with multisig wallets.
  Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/limitations.md#p2sh--multisig)
- New Feature: Signing artifacts re-export. Press (0) at the end of signing to re-export with different medium
- New Feature: Signed multisig exports. Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/msg-signing.md#signed-exports)
- Enhancement: NFC export usability upgrade. NFC keeps exporting until CANCEL/X is pressed
- Enhancement: Add `Bitcoin Safe` option to `Export Wallet`
- Enhancement: 10% performance improvement in USB upload speed for large files
- Bugfix: Fix stuck progress bar under `Receiving...` after a USB communications failure
- Bugfix: Showing derivation path in Address Explorer for root key (m) showed double slash (//)
- Bugfix: Enable to restore dev backup with custom password other than 12 words format
- Bugfix: Virtual Disk auto mode ignore already signed PSBTs (with "-signed" in file name)
- Bugfix: Virtual Disk auto mode stuck on "Reading..." screen
- Bugfix: Do not allow to change Main PIN to value already used as Trick PIN even if Trick PIN is hidden
- Change: `Destroy Seed` also removes all Trick PINs from SE2


# Mk4 Specific Changes

## 5.4.2 - 2025-03-??

- tbd


# Q Specific Changes

## 1.3.2Q - 2025-03-??

- Feature: Key Teleport -- Easily and securely move seed phrases, secure notes/passwords and PSBT
  between two Q using QR codes and/or NFC with helper website. See protocol spec in
  [docs/key-teleport.md][https://github.com/Coldcard/firmware/blob/master/docs/key-teleport.md]
    - can send master seed (words, xprv), anything held in seed vault, secure notes/passwords 
      (singular, or all) and PSBT involved in a multisig
    - ECDH to create session key for AES-256-CTR, with another layer of AES-256-CTR using a
      short password (stretched by PBKDF2-SHA512) inside
    - receiver shows sender a QR and a numeric code; sender replies with a QR and 8-char
      password
- Enhancement: Always choose the biggest possible display size for QR
