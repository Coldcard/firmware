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

- Enhancement: Add `Bitcoin Safe` option to `Export Wallet` 


# Mk4 Specific Changes

## 5.4.2 - 2024-03-??

- tbd


# Q Specific Changes

## 1.3.2Q - 2024-03-??

- Enhancement: Always choose the biggest possible display size for QR
