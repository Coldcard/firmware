# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Bugfix: Detect RNG_SR_SEIS and RNG_SR_SECS, retry safely, and fail closed on persistent faults.
- Bugfix: Prevent access to Seed Vault entries through Seed XOR restore in Delta Mode. Thanks to
  Rety for reporting this.
- Bugfix: Wipe seed in Delta Mode when saved BIP-39 passphrases are listed, instead of revealing them.
- Bugfix: BIP-322 message signing now rejects non-ASCII and other unsupported
  message text before approval. Thanks to @KirillCherikov for reporting.
- Bugfix: Prevent duplicate WIF Store entries after restarting
- Change: Block `SIGHASH_SINGLE` and `SIGHASH_SINGLE|ANYONECANPAY` by default because they can leave later transaction outputs modifiable after signing. They remain available when Sighash Checks is set to Warn.
  Thanks to [@instagibbs](https://github.com/instagibbs) for reporting this issue.
- Bugfix: Fixed PSBT uploads being mistaken for partial firmware uploads.
- Bugfix: Prevent valid message signatures when using a Delta Mode PIN.

# Mk Specific Changes

## 5.5.x - 2065-09-xx

- tbd


# Q Specific Changes

## 1.4.xQ - 2065-09-xx

- tbd
