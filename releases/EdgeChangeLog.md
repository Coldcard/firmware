# Change Log

## Warning: Edge Version

```diff
- This preview version of firmware has not yet been qualified
- and tested to the same standard as normal Coinkite products.
- It is recommended only for developers and early adopters
- for experimental use.
```

This lists the changes in the most recent EDGE firmware, for each hardware platform.

## 2026-07-31 Hotfix Versions: 6.6.0X & 6.6.0QX

**Urgent hotfix to correct a limited entropy bug**

Please regenerate seeds only with this version of the firmware and any
later updates from today onwards.

On **Mk4 and Q**, entropy may be as low as ~72 bits. This is
well below our target of 128 bits.

Follow the steps listed in 
[our blog announcement](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
to be safe, and please be careful not to cut corners or rush this process.

# Shared Improvements - Both Mk4 and Q

- Enhancement: Faster multisig address generation and PSBT input verification
- Bugfix: Renaming a MiniScript wallet could rename a different stored wallet when wallets from multiple chains were present
- Bugfix: Generate unique names when creating multisig wallets from PSBTs with the same M-of-N parameters

- [`History-Edge.md`](History-Edge.md)
