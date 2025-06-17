# Change Log

## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.
```

This lists the changes in the most recent EDGE firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- Bugfix: If all change outputs have `nValue=0` they're not shown in UX
- Bugfix: Disallow negative input/output amounts in PSBT
- Enhancement: Add warning for zero value outputs if not OP_RETURNs
- Enhancement: Show QR codes of output addresses in Txn output explorer. Output explorer is offered for txns of all sizes.

# Mk4 Specific Changes

## 6.3.6X - 2025-XX-XX

- Bugfix: Part of extended keys in stories were not always visible.
- all updates from `5.4.3`


# Q Specific Changes

## 6.3.6QX - 2025-XX-XX

- all updates from version `1.3.3Q`


# Release History

- [`History-Edge.md`](History-Edge.md)
