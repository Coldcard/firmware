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
- Bugfix: Harden callgate buffer validation against integer overflow and out-of-range access,
  following a finding in the [Karma-X security review](https://karma-x.io/blog/post/75/).
- Bugfix: USB `dwld` allowed readback of arbitrary staged PSRAM content (uploaded
  PSBT, multisig enroll file), also across sessions and over plaintext links.
  Downloads are now limited to the single most recent result produced for
  download (signed txn, visualization, backup), require an encrypted session,
  and are invalidated by any upload, newly staged transaction, or new session.
  Thanks to [@drk1wi](https://github.com/drk1wi).
- Change: When a BIP-39 passphrase is active, View Seed Words now shows only the effective extended private key instead of the underlying seed words.
- Change: Backup System, Clone Coldcard, and Key Teleport’s Full COLDCARD Backup now capture the wallet secret currently in effect, including temporary seeds and BIP-39 passphrase wallets, and warn before export.
- Bugfix: View Seed Words and backup workflows incorrectly treated the master seed as the parent of every BIP-39 passphrase wallet. When a passphrase was applied to a temporary seed, they could not access that immediate parent seed.

# Mk Specific Changes

## 5.5.x - 2065-09-xx

- tbd


# Q Specific Changes

## 1.4.xQ - 2065-09-xx

- tbd
