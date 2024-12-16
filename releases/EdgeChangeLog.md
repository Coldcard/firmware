# Change Log

## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.  DO NOT use for large Bitcoin amounts.
```

This lists the changes in the most recent EDGE firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- Bugfix: Complex miniscript wallets with keys in policy that are not in strictly ascending order were incorrectly filled
  upon load from settings. All users on versions `6.2.2X`+ needs to update. 
- Bugfix: Single key miniscript descriptor support
- Enhancement: Hide Secure Notes & Passwords in Deltamode. Wipe seed if notes menu accessed. 
- Enhancement: Hide Seed Vault in Deltamode. Wipe seed if Seed Vault menu accessed. 
- Bugfix: Sometimes see a struck screen after _Verifying..._ in boot up sequence.
  On Q, result is blank screen, on Mk4, result is three-dots screen.
- Bugfix: Do not allow to enable/disable Seed Vault feature when in temporary seed mode
- Bugfix: Bless Firmware causes hanging progress bar
- Bugfix: Prevent yikes in ownership search
- Change: Do not allow to purge settings of current active tmp seed when deleting it from Seed Vault


# Mk4 Specific Changes

## 6.3.4X - 2024-07-04

- all updates from `5.4.0`
- Enhancement: Export single sig descriptor with simple QR


# Q Specific Changes

## 6.3.4QX - 2024-07-04

- all updates from version `1.3.0Q`
- Bugfix: Properly re-draw status bar after Restore Master on COLDCARD without master seed.


# Release History

- [`History-Edge.md`](History-Edge.md)
