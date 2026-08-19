# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Improvements to Entropy Generation:
    - Master seed generation now combines fresh entropy from the STM32 TRNG,
      SE1, and SE2. Previously, SE1 and SE2 contributed through boot-time RNG
      seeding; they are now also sampled directly for each new master seed.
    - On every boot, RNG is seeded with the full 256-bit digest of entropy
      from both Secure Elements (previously truncated to 32 bits).
    - libngu now uses a `SHA-256 Hash_DRBG` (NIST SP 800-90A) instead of the Yasmarang PRNG.
    - Backup passwords, encryption salt/IV, and 2FA secrets now use libngu's
      Hash_DRBG-based RNG instead of calling the raw TRNG interface directly.
      Remaining direct application uses of the raw TRNG are for non-secret values.
    - RNG self-test proves `rng_get()` enters the hardware read path and stops
      the boot if the check fails.
    - Build-time checks verify that libngu's random-byte path reaches the
      hardware `rng_get()` implementation.
- Newly generated master seeds, Temporary Seeds, and CCC key C now **require**
  extra user-supplied entropy (dice, coin flips, or keyboard mashing):
    - Choose key mashing (based on [Peter Todd's Push-Button RNG](https://petertodd.org/2014/push-button-rng)),
      physical dice rolls or physical coin flips.
    - Entropy supplied by the user is added to randomness from the STM32 TRNG,
      SE1, and SE2. It does not replace those sources.
    - Dice and coin results are checked for obviously bad distributions.
    - Key mashing hashes raw GPIO press timing captured at CPU-cycle
      resolution (~8.33 ns at 120 MHz) before keypad debounce. Releases are ignored,
      repeating one key is valid, and at least 65 presses are required. The first
      press establishes the timing reference; each of the following 64 inter-press
      gaps is conservatively credited with two bits of entropy. The full timing
      delta and key identity are mixed in, but key identity receives no entropy credit.
      Users may continue mashing beyond 65 presses to contribute additional timing entropy.
- Dice-Only Enhancements:
    - Dice-only seed generation now clearly warns: **NO hardware entropy is
      included.** The final hash shown on screen must be kept secret.
    - Temporary dice-only seeds now use the same warning and mandatory
      entropy checks as master dice-only seeds.
    - Held digit keys count as one dice roll, and completion keys now match
      each COLDCARD model.
- Delta Mode hardening:
    - Wipe seed in Delta Mode when saved BIP-39 passphrases are listed, instead of revealing them.
    - Block access to Seed Vault entries through Key Teleport's secret picker,
      CCC key-C import, and Seed XOR restore in Delta Mode. Thanks to "Rety"
      for reporting the Seed XOR issue.
    - Wipe seed before BIP-85 derivation in Delta Mode.
    - Prevent valid message signatures when using a Delta Mode PIN.
- Bugfix: Detect `RNG_SR_SEIS` and `RNG_SR_SECS`, retry safely, and fail closed on persistent faults.
- Bugfix: BIP-322 message signing now rejects non-ASCII and other unsupported
  message text before approval. Thanks to [@KirillCherikov](https://github.com/KirillCherikov) for reporting.
- Bugfix: Prevent duplicate WIF Store entries after restarting.
- Change: Block `SIGHASH_SINGLE` and `SIGHASH_SINGLE|ANYONECANPAY` by default because they can
  leave later transaction outputs modifiable after signing. They remain available when Sighash
  Checks is set to Warn.
  Thanks to [@instagibbs](https://github.com/instagibbs) for reporting this issue.
- Bugfix: Prevent PSBT uploads from being mistaken for partial firmware uploads.
- Bugfix: Harden callgate buffer validation against integer overflow and out-of-range access,
  following a finding in the [Karma-X security review](https://karma-x.io/blog/post/75/).
- Bugfix: Reject firmware update data beyond the signed firmware length.
- Bugfix: Reject out-of-range firmware high-water timestamps without triggering a
  bootloader assertion.
- Bugfix: USB `dwld` allowed readback of arbitrary staged PSRAM content (uploaded
  PSBT, multisig enroll file), also across sessions and over plaintext links.
  Downloads are now limited to the single most recent result produced for
  download (signed txn, visualization, backup), require an encrypted session,
  and are invalidated by any upload, newly staged PSRAM content (including
  Q-specific PSBT and BBQr paths), or new session. Thanks to
  [@drk1wi](https://github.com/drk1wi) for reporting this issue.
- Change: When a BIP-39 passphrase is active, View Seed Words now shows only the effective
  extended private key instead of the underlying seed words.
    - Bugfix: View Seed Words and backup workflows incorrectly treated the master seed as the
      parent of every BIP-39 passphrase wallet. When a passphrase was applied to a temporary seed,
      they could not access that immediate parent seed.
    - Change: Backup System, Clone Coldcard, and Key Teleport’s Full COLDCARD Backup now capture
      the wallet secret currently in effect, including temporary seeds and BIP-39 passphrase
      wallets, and warn before export.
- Bugfix: A compromised USB host could rewrite the staged PSBT after review, but
  before signing, so the signature covered a different transaction than shown.
  Staged bytes are now re-verified before signing; any change aborts with
  "Transaction modified". Thanks to "FreeZ Agent" for the report and proof of concept.
- Bugfix: Reject duplicate cosigner keys and keys the device already holds
  during multisig wallet enrollment. Thanks to [@drk1wi](https://github.com/drk1wi) for reporting this.
- Bugfix: Reject backup files that request excessive password-derivation work.
- Bugfix: Require unique multisig wallet names, generate unique default names,
  and reject ambiguous lookups of legacy duplicate names.
- Change: Multisig wallet names can now be changed with a dedicated `Rename`
  action in the wallet menu. Reimporting an enrollment file or descriptor no
  longer renames an existing wallet.
- Bugfix: Separate the SE1 check nonce from the PIN digest. Thanks to
  [@instagibbs](https://github.com/instagibbs) for reporting this issue.
- Bugfix: Clear volatile PSRAM application data when the seed is wiped.
- Enhancement: Clone Coldcard now shows the restored seed's master fingerprint on the receiving
  Coldcard and asks for confirmation before installing it.
- Bugfix: CCC velocity policies created by older firmware now enforce the
  current chain's minimum block height before co-signing.
- Bugfix: USB backup restore now respects the Spending Policy's Related Keys setting.
- Bugfix: Reject overlong Base58Check payloads before decoding beyond the destination buffer.
- Bugfix: Reject SegWit addresses with oversized HRPs instead of returning an unterminated buffer.

# Mk Specific Changes

## 5.6.1 - 2026-08-20

- all of the above.


# Q Specific Changes

## 1.5.1Q - 2026-08-20

- Security Improvement: Require scrolling to reveal locally entered BIP-39 passphrases.
- Bugfix: Reject malformed multipart BBQrs that could include stale PSRAM bytes
  in decoded results. Thanks to [@drk1wi](https://github.com/drk1wi) for reporting this.
- Defence-in-depth hardening:
    - Sanitize control characters in BIP-21 payment metadata values and
      parameter names before display.
    - Reject oversized multisig coordinator BBQr imports before JSON parsing to prevent memory
      exhaustion.
    - Revoke USB download access before staging PSBT and BBQr data in PSRAM.
- Bugfix: Allow Send Password to temporarily enable USB keyboard emulation when
  USB is disabled in settings.
