# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Change: BIP-322 Proof of Reserves & message signing PSBT requires PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE
  (read more [BIP-322 Proof of Reserves documentation](../docs/proof-of-reserves-bip-322.md) )
- Enhancement: WIF Store export watch-only descriptor
- Enhancement: WIF Store address detection without the need for PSBT_IN_BIP32_DERIVATION (Electrum support)
- Enhancement: Improve USB length validation
- Bugfix: Fixes legacy input amount spoofing by rejecting witness-utxo-only PSBT inputs when Coldcard is expected to sign a non-segwit input.
  When both UTXO fields are present the full non_witness_utxo is now preferred for amount/script lookup. Thanks, @Damir
- Bugfix: Emit warning and do not calculate fee for legacy UTXOs with only witness utxo
- Bugfix: Disable Virtual Disk and NFC before activating HSM
- Bugfix: P2PK signing was broken. Now supports both compressed and uncompressed P2PK spend
- Bugfix: Custom address default menu position wrong
- Bugfix: Delta Mode Trick PIN was never restored from backup
- Bugfix: Proper error message for incorrect 7z headers
- Bugfix: Exiting nickname entry with nickname already saved deleted previous nickname
- Bugfix: "Send Password" menu item inside Notes & Passwords visibility reversed
- Bugfix: Yikes when using "Send Password" on entry with password None field
- Bugfix: Do not show "Saving..." UX after failed Notes & Passwords import
- Bugfix: Incorrect error message caused by error in Verify/Decrypt Backup
- Bugfix: NFC Verify Address raised incorrect error message
- Bugfix: Notes & Passwords bulk import JSON with BBQr encoded as text
- Bugfix: CCC key C challenge handled bad BIP-39 checksum by crashing the UX; now treated as a wrong attempt (counts toward 3-strike lockout)
- Bugfix: CCC magnitude reset from CANCEL on empty input
- Bugfix: OP_RETURN in CCC with whitelist enabled caused yikes
- Bugfix: TX Explorer crashed on foreign input with non-standard sighash
- Bugfix: Malformed JSON message-sign request crashed signing UX
- Bugfix: Reject UI-control bytes in JSON / QR text message-signing
- Bugfix: Non-standard OP_RETURN outputs shown as "null-data", hiding part of the script
- Bugfix: Over-limit CCC address-whitelist import was rejected but still modified the policy
- Bugfix: Deleting a file right after renaming it (List Files) blanked the old name, leaving the renamed file
- Bugfix: SSSP bypass PIN alone could complete login into a no-secret session. Second prompt now requires a PIN that loads secrets.
- Bugfix: Reordered `multi(...)` multisig with same keys was misreported as name-only change. Now blocked as duplicate.
- Bugfix: Max WIF store capacity limit was ignored if saving via QR WIF visualization
- Bugfix: Force Seed XOR restore from Temporary Seed menu to remain temporary even when master seed is blank
- Bugfix: Q1 seed word entry cursor alignment for 12-word seeds and preserve visible words after failed QR scans
- Bugfix: Binary signed-transaction (.txn) failed in NFC/QR file share
- Bugfix: yikes in transaction explorer for goto index for tx with only one output
- Bugfix: Sending `signmessage` payload encoded as BBQr caused yikes
- Bugfix: CCC/SSSP NFC whitelist import caused Yikes
- Bugfix: Stricter address ownership validation rejects unrecognized payment addresses before wallet search
- Bugfix: Handle malformed NDEF records robustly. Thanks, @Damir
- Bugfix: Ignore `bkpw` if added to backup. Thanks [@dmonakhov](https://github.com/dmonakhov)
- Bugfix: Keep NFC export tag live for repeated probes
- Bugfix: Fix 1of1 multisig signing failure

# Mk Specific Changes

## 5.5.x - 2065-04-xx

- tbd


# Q Specific Changes

## 1.4.xQ - 2065-04-xx

- New Feature: Secure Notes & Passwords UX groups
- New Feature: Apply Secure Note text, or Secure Note password as BIP-39 passphrase
- Bugfix: Teleporting a multisig PSBT file (without signing it first) sent stale data instead of the selected file
- Bugfix: Fix export UX message after teleport PSBT import & sign
- Bugfix: BIP-21 QR `amount` rendered with wrong decimal scaling on the Payment Address screen (e.g. `amount=1.1` was shown as `1.00000001 BTC`)
- Bugfix: QR scan import (Scan Any QR Code, master/temp seed via QR) now surfaces a clean error story on any parser or seed-loading failure (e.g. wordlist-valid but bad-checksum SeedQR) instead of yikesing the menu task
- Bugfix: Yikes when showing "QR too big" for a transaction output alone on an output-explorer page
- Bugfix: Yikes receiving a malformed full-backup via Key Teleport
- Bugfix: Keyboard debounce could leave a key stuck as "pressed" after release when another key was held
- Bugfix: Scanner robustness
  - Avoid holding the QR scanner reset line low; reset is now only pulsed and then left deasserted.
  - Recover scanner setup failures by retrying configuration and reinitializing on the next scan when needed.
  - Prevent delayed scanner sleep commands from racing with a newly started scan.
  - Improve scanner shutdown/recovery after scan cancel or command timeout.
