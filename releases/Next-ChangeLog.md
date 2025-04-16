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
    - spending policy can be exceeded with help of the other co-signer (3rd key), when needed
    - cannot view or change the CCC spending policy once set, policy violations are not explained
    - existing multisig wallets can be used by importing the spending-policy-controlled key

- New Feature: Multisig transactions are finalized. Allows use of [PushTX](https://pushtx.org/)
  with multisig wallets.  Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/limitations.md#p2sh--multisig)
- New Feature: Signing artifacts re-export to various media. Now you have the option of
  exporting the signing products (transaction/PSBT) to different media than the original source.
  Incoming PSBT over QR can be signed and saved to SD card if desired.
- New Feature: Multisig export files are signed now. Read more [here](https://github.com/Coldcard/firmware/blob/master/docs/msg-signing.md#signed-exports)
- Enhancement: NFC export usability upgrade: NFC keeps exporting until CANCEL/X is pressed
- Enhancement: Add `Bitcoin Safe` option to `Export Wallet`
- Enhancement: 10% performance improvement in USB upload speed for large files
- Bugfix: Do not allow change Main PIN to same value already used as Trick PIN, even if
  Trick PIN is hidden.
- Bugfix: Fix stuck progress bar under `Receiving...` after a USB communications failure
- Bugfix: Showing derivation path in Address Explorer for root key (m) showed double slash (//)
- Bugfix: Can restore developer backup with custom password other than 12 words format
- Bugfix: Virtual Disk auto mode ignores already signed PSBTs (with "-signed" in file name)
- Bugfix: Virtual Disk auto mode stuck on "Reading..." screen sometimes
- Bugfix: Finalization of foreign inputs from partial signatures. Thanks Christian Uebber
- Bugfix: Temporary seed from COLDCARD backup failed to load stored multisig wallets
- Change: `Destroy Seed` also removes all Trick PINs from SE2.
- Change: `Lock Down Seed` requires pressing confirm key (4) to execute


# Mk4 Specific Changes

## 5.4.2 - 2025-04-17

- All of the above, but not Key Teleport which requires QR scanner.


# Q Specific Changes

## 1.3.2Q - 2025-04-17

- Feature: Key Teleport -- Easily and securely move seed phrases, secure notes/passwords,
  multisig PSBT files, and even full Coldcard backups, between two Q using QR codes
  and/or NFC with helper website. See protocol spec in
  [docs/key-teleport.md](https://github.com/Coldcard/firmware/blob/master/docs/key-teleport.md)
    - can send master seed (words, xprv), anything held in seed vault, secure notes/passwords 
      (singular, or all) and PSBT involved in a multisig to the other co-signers
    - full COLDCARD backup is possible as well, but receiver must be "unseeded" Q for best result
    - ECDH to create session key for AES-256-CTR, with another layer of AES-256-CTR using a
      short password (stretched by PBKDF2-SHA512) inside
    - receiver shows sender a (simple) QR and a numeric code; sender replies with larger BBQr
      and 8-char password
- Enhancement: Always choose the biggest possible display size for QR
- Bugfix: Only BBQr is allowed to export Coldcard, Core, and pretty descriptor
