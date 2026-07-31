# Change Log

## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.
```

This lists the changes in the most recent EDGE firmware, for each hardware platform.

## 2026-07-31 Hotfix Versions: 6.5.1X & 6.5.1QX

**Urgent hotfix to correct a limited entropy bug**

Please regenerate seeds only with this version of the firmware and any
later updates from today onwards.

**Mk3 users must regenerate any seeds** made on version 4.0.1 or
later as their entropy is critically low at just ~40 bits.  We are
not planning to update Mk3 firmware at this time, so please use
newer hardware or add a BIP-39 passphrase as a stopgap.

On **Mk4, Mk5 and Q entropy** may be as low as ~72 bits. This is
well below our target of 128 bits.

Follow the steps listed in 
[our blog announcement](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
to be safe, and please be careful not to cut corners or rush this process.

# Shared Improvements - Both Mk4 and Q

- Bugfix: Renaming a MiniScript wallet could rename a different stored wallet when wallets from multiple chains were present

# Mk4 Specific Changes

## 6.5.1X - 2026-xx-xx

- todo


# Q Specific Changes

## 6.5.1QX - 2026-xx-xx

- todo


# Release History

- [`History-Edge.md`](History-Edge.md)
