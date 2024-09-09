# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- New Feature: PushTX: once enabled with a service provider's URL, you can tap the COLDCARD
  and your phone will open a webpage that transmits your freshly-signed transaction onto
  the blockchain. See `Settings > NFC Push Tx` to enable and select service provider, or your
  own webpage. More at <https://pushtx.org>. You can also use this to broadcast any
  transaction found on the MicroSD card (See `Tools > NFC Tools > Push Transaction`).
- New Feature: Transaction Output Explorer: allows viewing all output details for
  larger txn (10+ output, 20+ change) before signing. Offered for large transactions only
  because we are already showing all the details for typical transactions.
- New Feature: Setting to enable always showing XFP as first item in home menu.
- Enhancement: When signing, show sum of outgoing value at top. Always show number
  of inputs/outputs and total change value.
- Enhancement: Add `Sign PSBT` shortcut to `NFC Tools` menu
- Enhancement: Stricter p2sh-p2wpkh validation checks.
- Enhancement: Show master XFP of BIP-85 derived wallet in story before activation. Only
  words and extended private key cases.
- Enhancement: Add `Theya` option to `Export Wallet`
- Enhancement: Mention the need to remove old duress wallets before locking down temporary seed.
- Bugfix: Fix PSBTv2 `PSBT_GLOBAL_TX_MODIFIABLE` parsing.
- Bugfix: Decrypting Tapsigner backup failed even for correct key.
- Bugfix: Clear any pending keystrokes before PSBT approval screen.
- Bugfix: Display max 20 change outputs in when signing, and max 10 of largest outputs, and
  offer the Transaction Output Explorer if more to be seen.
- Bugfix: Calculate progress bar correctly in Address Explorer after first page.
- Bugfix: Search also Wrapped Segwit single sig addresses if P2SH address provided, not just
  multisig (multisig has precedence for P2SH addresses)
- Bugfix: Address search would not find addresses for non-zero account numbers that had
  been exported but not yet seen in a PSBT.
- (v5.3.3/1.2.3Q) Bugfix: Trying to set custom URL for NFC push transaction caused yikes error.

# Mk4 Specific Changes

## 5.3.3 - 2024-07-05

- Bugfix: Displaying change address in Address Explorer fails if NFC and Vdisk not enabled.
- Bugfix: Fix yikes displaying BIP-85 WIF when both NFC and VDisk are disabled.
- Bugfix: Fix inability to export change addresses when both NFC and Vdisk are disabled.
- Bugfix: In BIP-39 words menu, show space character rather than Nokia-style placeholder
  which could be confused for an underscore (reported by `tobo@600.wtf`).


# Q Specific Changes

## 1.2.3Q - 2024-07-05

- Enhancement: Coldcard multisg export/import format detected in `Scan Any QR Code`.
- Enhancement: Support newer-version QR scanner modules.
- Bugfix: Exporting BIP-85 derived entropy via NFC was offered even when NFC disabled,
  leading to a Yikes error.
- Bugfix: Properly clear LCD screen after simple QR code is shown
- Change in default brightness (on battery) from 80% to 95%.


# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

