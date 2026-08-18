# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Improvements to Entropy Generation:
    - Master seed generation mixes entropy from both Secure Elements with
      the STM32 TRNG (previously TRNG only).
    - On every boot, RNG is seeded with the full 256-bit digest of entropy
      from both Secure Elements (previously truncated to 32 bits).
    - libngu now uses a `SHA-256 Hash_DRBG` (NIST SP 800-90A) instead of the Yasmarang PRNG.
    - RNG self-test proves `rng_get()` enters the hardware read path. Brick device otherwise.
    - Makefile compile-time checks, verifying included code is expanded beyond
      those in the Hotfix.
- New master seeds now **require** extra user supplied entropy (dice, coin flips, keyboard mashing):
    - Choose key mashing (based on [Peter Todd's Push-Button RNG](https://petertodd.org/2014/push-button-rng)),
      physical dice rolls or physical coin flips.
    - TRNG, SE1 and SE2 randomness is also mixed into the generated seed.
    - Dice and coin results are checked for obviously bad distribution.
    - Key mashing hashes raw GPIO press timing captured at CPU cycle
      resolution (~8.33ns at 120MHz) before keypad debounce. Releases are ignored,
      repeating one key is valid, and at least 65 presses are required. The first
      press establishes the timing reference; each of the following 64 inter-press
      gaps is conservatively credited with two bits of entropy credit. The full timing
      delta and key identity are mixed in, but key identity receives no entropy credit.
      Users may continue mashing beyond 65 presses to contribute additional timing entropy.
    - Generated Temporary Seeds and generated CCC key C now require extra user supplied entropy.
- Dice-Only Enhancements:
    - Dice-only seed generation now warns that no hardware randomness is
      included and the final hash shown on-screen must be kept secret.
    - Temporary dice-only seeds now use the same warning and mandatory
      entropy checks as master dice-only seeds.
- Delta Mode hardening:
    - Wipe seed in Delta Mode when saved BIP-39 passphrases are listed, instead of revealing them.
    - Block Key Teleport’s secret picker and CCC key-C import from Seed
      Vault in Delta Mode.
    - Prevent access to Seed Vault entries through Seed XOR restore in Delta Mode.
      Thanks to "Rety" for reporting this.
    - Wipe seed before BIP-85 derivation in Delta Mode.
    - Prevent valid message signatures when using a Delta Mode PIN.
- Bugfix: Detect `RNG_SR_SEIS` and `RNG_SR_SECS`, retry safely, and fail closed on persistent faults.
- Bugfix: BIP-322 message signing now rejects non-ASCII and other unsupported
  message text before approval. Thanks to [@KirillCherikov](https://github.com/KirillCherikov) for reporting.
- Bugfix: Prevent duplicate WIF Store entries after restarting
- Change: Block `SIGHASH_SINGLE` and `SIGHASH_SINGLE|ANYONECANPAY` by default because they can
  leave later transaction outputs modifiable after signing. They remain available when Sighash
  Checks is set to Warn.
  Thanks to [@instagibbs](https://github.com/instagibbs) for reporting this issue.
- Bugfix: Fixed PSBT uploads being mistaken for partial firmware uploads.
- Bugfix: Harden callgate buffer validation against integer overflow and out-of-range access,
  following a finding in the [Karma-X security review](https://karma-x.io/blog/post/75/).
- Bugfix: Reject out-of-range firmware highwater timestamps without triggering a
  bootloader assertion.
- Bugfix: USB `dwld` allowed readback of arbitrary staged PSRAM content (uploaded
  PSBT, multisig enroll file), also across sessions and over plaintext links.
  Downloads are now limited to the single most recent result produced for
  download (signed txn, visualization, backup), require an encrypted session,
  and are invalidated by any upload, newly staged transaction, or new session.
  Thanks to [@drk1wi](https://github.com/drk1wi).
- Change: When a BIP-39 passphrase is active, View Seed Words now shows only the effective
  extended private key instead of the underlying seed words.
    - Bugfix: View Seed Words and backup workflows incorrectly treated the master seed as the
      parent of every BIP-39 passphrase wallet. When a passphrase was applied to a temporary seed,
      they could not access that immediate parent seed.
    - Change: Backup System, Clone Coldcard, and Key Teleport’s Full COLDCARD Backup now capture
      the wallet secret currently in effect, including temporary seeds and BIP-39 passphrase
      wallets, and warn before export.
- Bugfix: a compromised USB host could rewrite the staged PSBT after review, but
  before signing, so the signature covered a different transaction than shown.
  Staged bytes are now re-verified before signing; any change aborts with
  "Transaction modified". Thanks to "FreeZ Agent" for the report and PoC.
- Bugfix: Reject duplicate cosigner keys, and cosigner keys the device already holds,
  during multisig wallet enrollment. Thanks to [@drk1wi](https://github.com/drk1wi) for reporting this.
- Bugfix: Separate the SE1 check nonce from the PIN digest. Thanks to
  [@instagibbs](https://github.com/instagibbs) for reporting this issue.
- Enhancement: Clone Coldcard now shows the restored seed's master fingerprint on the receiving
  Coldcard and asks for confirmation before installing it.
- Bugfix: CCC velocity policies created by older firmware now enforce the
  current chain's minimum block height before co-signing.
- Bugfix: USB backup restore now respects the Spending Policy's Related Keys setting.
- Bugfix: Reject overlong Base58Check payloads before decoding beyond the destination buffer.
- Bugfix: Reject SegWit addresses with oversized HRPs instead of returning an unterminated buffer.

# Mk Specific Changes

## 5.6.1 - 2026-08-18

- all of the above.


# Q Specific Changes

## 1.5.1Q - 2026-08-18

- Bugfix: Reject malformed multipart BBQrs that could include stale PSRAM bytes
  in decoded results. Thanks to [@drk1wi](https://github.com/drk1wi) for reporting this.
- Hardening & Defence in depth:
    - Reject control characters in BIP-21 payment metadata before display.
    - Limit multisig coordinator BBQr imports before JSON parsing to prevent memory
      exhaustion.
    - Revoke USB download access before staging PSBT and BBQr data in PSRAM.
