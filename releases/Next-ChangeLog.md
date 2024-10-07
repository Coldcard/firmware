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
- Enhancement: NFC export usability upgrade. NFC keeps exporting until CANCEL/X is pressed
- Enhancement: Add `Bitcoin Safe` option to `Export Wallet`
- Enhancement: 10% performance improvement in USB upload speed for large files
- Bugfix: Fix stuck progress bar under `Receiving...` after a USB communications failure
- Bugfix: Showing derivation path in Address Explorer for root key (m) showed double slash (//)
- Bugfix: Enable to restore dev backup with custom password other than 12 words format 


# Mk4 Specific Changes

## 5.4.2 - 2025-03-??

- tbd


# Q Specific Changes

## 1.3.2Q - 2025-03-??

- Enhancement: Always choose the biggest possible display size for QR
