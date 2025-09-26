# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

## Spending Policy Feature

Spending policies for "Single Signers" adds new spending policy options:

- limit your Coldcard so it refuses to sign transactions that are "too big"
- require 2FA authentication before signing any transaction (NFC+web)
- velocity limits can restrict how often new transactions can be signed
- see `docs/spending-policy.md` for more details
- "Enable HSM" and "User Management" have moved into `Advanced > Spending Policy`.
- Old "CCC" feature has been renamed and moved into that menu as well: "Co-Sign Multisig"

## Other Improvements

- Added `Bull Bitcoin` export to `Export Wallet` menu.
- Enhancement: Added warning for zero value outputs if not `OP_RETURN`.
- Enhancement: Show QR codes of output addresses in transaction output explorer. Explorer is
  now offered for transactions of all sizes, not just complex ones.
- Enhancement: Added file rename, when listing contents of SD card.
- Enhancement: Added ability to restore Coldcard backup via USB (needs latest of ckcc version)
- Enhancement: Address ownership allows to specify particular multisig wallet in which to search,
  if `wallet` query parameter is provided via trival extension to
  [BIP-21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki).
  Example: `tb1q4d67p7stxml3kdudrgkg5mgaxsrgzcqzjrrj4gg62nxtvnsnvqjsxjkej0?wallet=Haystack`
- Bugfix: If all change outputs have `nValue=0`, they were not shown in UX.
- Bugfix: Disallow negative input/output amounts in PSBT.
- Bugfix: Fix filesystem initialization after Wife LFS or Destroy Seed.
- Bugfix: Fix MicroSD selftest code.
- Bugfix: NFC loop exporting secrets would not work after first value exported.
- Bugfix: Multisig address format handling.
- Bugfix: Ownership check failing to find addresses near max (~760), needed to be re-run to succeed

# Mk4 Specific Changes

## 5.4.4 - 2025-09-25

- Bugfix: Part of extended keys (xpubs) were not always visible.
- Change: Mk4 default menu wrap-around lowered from 16 to 10 items.


# Q Specific Changes

## 1.3.4Q - 2025-09-25

- Enhancement: Enters "forever calculator" mode when Q would otherwise be electronic waste
  (ie. after 13 PIN failures). Always enabled, regardless of "login calculator" setting.
- Bugfix: Correct line positioning when 24 seed words displayed.


# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

