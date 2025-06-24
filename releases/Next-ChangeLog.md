# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk4 and Q

- Added `Bull Bitcoin` export to `Export Wallet` menu
- Enhancement: Add warning for zero value outputs if not `OP_RETURN`
- Enhancement: Show QR codes of output addresses in transaction output explorer. Explorer is
  now offered for transactions of all sizes, not just complex ones.
- Bugfix: If all change outputs have `nValue=0` they were not shown in UX.
- Bugfix: Disallow negative input/output amounts in PSBT.
- Bugfix: Fix filesystem initialization after Wife LFS or Destroy Seed.
- Bugfix: Fix MicroSD selftest
- Bugfix: NFC loop exporting secrets pre-mature wipe

## Spending Policy Feature

- new feature: Spending policies for "Single Signer" adds spending policy options:
    - limit your Coldcard so it refuses to sign transactions that are "too big"
    - require 2FA authentication before signing any transaction (NFC+web)
    - velocity limits can restrict how often new transactions can be signed
    - see `docs/spending-policy.md` for details
- "Enable HSM" and "User Management" have moved into Advanced > Spending Policy
- old "CCC" feature has been renamed and moved into that menu as well

# Mk4 Specific Changes

## 5.4.4 - 2025-09-1x

- Bugfix: Part of extended keys in stories were not always visible.


# Q Specific Changes

## 1.3.4Q - 2025-09-1x

- Bugfix: Correct line positioning when 24 seed words displayed.


