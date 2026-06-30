# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk and Q

- Enhancement: Can export WIF Store watch-only descriptor.
- Enhancement: WIF Store address detection without the need
  for `PSBT_IN_BIP32_DERIVATION` (improves Electrum support)
- Enhancement: BIP-322 Proof of Reserves and Message Signing PSBT
  requires `PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE` field
  (read more [BIP-322 Proof of Reserves documentation](../docs/proof-of-reserves-bip-322.md) )
- Bugfix: Fixes legacy input amount spoofing by rejecting witness-utxo-only
  PSBT inputs when Coldcard is expected to sign a non-segwit input.  When both
  UTXO fields are present the full `non_witness_utxo` is now preferred for
  amount/script lookup. Thanks, @Damir!
- Bugfix: Keep NFC export tag alive for repeated probes. Helps NFC tap reliability on iOS.
- Bugfix: Emit warning and do not calculate fee for legacy UTXOs with only witness utxo.
- Bugfix: Disable Virtual Disk and NFC before activating HSM.
- Bugfix: P2PK signing was broken. Now supports both compressed and uncompressed P2PK spend.
- Bugfix: Custom address default menu position was wrong.
- Bugfix: Delta Mode Trick PIN was never restored from backup.
- Bugfix: Proper error message for incorrect 7z headers.
- Bugfix: Exiting nickname entry with nickname already saved deleted previous nickname.
- Bugfix: Incorrect error message caused by error in Verify/Decrypt Backup.
- Bugfix: NFC Verify Address raised incorrect error message.
- Bugfix: CCC key C challenge handled bad BIP-39 checksum by crashing the UX. Now treated
  as a wrong attempt (counts toward 3-strike lockout).
- Bugfix: CCC magnitude reset from CANCEL on empty input.
- Bugfix: `OP_RETURN` in CCC with whitelist enabled caused Yikes.
- Bugfix: TX Explorer crashed on foreign input with non-standard sighash.
- Bugfix: Malformed JSON message-sign request crashed signing UX.
- Bugfix: Reject UI-control bytes in JSON / QR text message-signing.
- Bugfix: Non-standard `OP_RETURN` outputs shown as "null-data", hiding part of the script.
- Bugfix: Over-limit CCC address-whitelist import was rejected but still modified the policy.
- Bugfix: Deleting a file right after renaming it (List Files) blanked the old name,
  leaving the renamed file.
- Bugfix: Reordered `multi(...)` multisig with same keys was misreported as name-only
  change. Now blocked as duplicate.
- Bugfix: Max WIF store capacity limit was ignored if saving via QR WIF visualization.
- Bugfix: Force Seed XOR restore from Temporary Seed menu to remain temporary even when
  master seed is blank.
- Bugfix: Binary signed-transaction (.txn) failed in NFC/QR file share.
- Bugfix: Yikes in transaction explorer for goto index for tx with only one output.
- Bugfix: Sending `signmessage` payload encoded as BBQr caused Yikes.
- Bugfix: CCC/SSSP NFC whitelist import caused Yikes.
- Bugfix: Stricter address ownership validation rejects unrecognized payment
  addresses before wallet search.
- Bugfix: Handle malformed NDEF records robustly. Thanks, @Damir!
- Bugfix: Ignore `bkpw` if added to backup. Thanks, [@dmonakhov](https://github.com/dmonakhov)!
- Bugfix: Fix 1-of-1 multisig signing failure.

# Mk Specific Changes

## 5.5.1 - 2065-06-30

- All bug fixes and enhancements listed above.


# Q Specific Changes

## 1.4.1Q - 2065-06-30

- New Feature: Secure Notes & Passwords UX groups. Thanks, [@Gen6G](https://x.com/Gen6G)!
- New Feature: Apply Secure Note text, or Secure Note password as BIP-39 passphrase.
- New Feature: Standalone encrypted backups for Secure Notes & Passwords.
- Bugfix: Major scanner robustness improvements!
  - Recover scanner setup failures by retrying configuration and reinitializing on
    the next scan when needed.
  - Prevent delayed scanner sleep commands from racing with a newly started scan.
  - Improve scanner shutdown/recovery after scan cancel or command timeout.
  - Bottom line: should be less "stuck" QR scanners, with the light left on.
- Bugfix: Teleporting a multisig PSBT file (without signing it first) sent stale data
  instead of the selected file.
- Bugfix: Fix export message shown after teleport PSBT import & sign.
- Bugfix: BIP-21 QR `amount` rendered with wrong decimal scaling on the Payment Address
  screen (e.g. `amount=1.1` was shown as `1.00000001 BTC`).
- Bugfix: Q1 seed word entry cursor alignment for 12-word seeds and preserve visible words
  after failed QR scans.
- Bugfix: QR scan import (Scan Any QR Code, master/temp seed via QR) now shows a clear
  error message on any parser or seed-loading failure (e.g. wordlist-valid but bad-checksum
  SeedQR) instead of Yikes.
- Bugfix: Yikes when showing "QR too big" for a transaction output alone on
  an output-explorer page.
- Bugfix: Yikes receiving a malformed full-backup via Key Teleport.
- Bugfix: Keyboard debounce could leave a key stuck as "pressed" after release, when another
  key was held (sometimes).
- Bugfix: "Send Password" menu item inside Notes & Passwords visibility reversed.
- Bugfix: Yikes when using "Send Password" on entry with password None field.
- Bugfix: Do not show "Saving..." UX after failed Notes & Passwords import.
- Bugfix: Notes & Passwords bulk import JSON with BBQr encoded as text.



# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk.md` (Mk4 and Mk5)](History-Mk.md)
- [`History-Mk3.md`](History-Mk3.md)

