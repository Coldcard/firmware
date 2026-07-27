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

- New Feature: Allow uncompressed WIF keys in WIF Store
- Enhancement: Faster multisig address generation and PSBT input verification
- Enhancement: Use predictable sequential filenames for PSBTs processed multiple times via MicroSD or Virtual Disk
- Change: Spending Policy mode prevents USB hosts from enrolling, deleting, listing, or exporting
  Multisig/Miniscript wallet configurations
- Change: The main transaction approval story no longer lists every affected input or output for repeated warnings,
  relative timelocks, or unusual change derivation paths. It now shows compact summaries; use the transaction
  explorer to review individual details.
- Bugfix: Generate distinct MuSig2 nonces for different aggregate-key derivations of the same participant set
- Bugfix: Renaming a MiniScript wallet could rename a different stored wallet when wallets from multiple chains were present
- Bugfix: Generate unique names when creating multisig wallets from PSBTs with the same M-of-N parameters
- Bugfix: Correctly identify consolidations containing zero-value OP_RETURN outputs without misclassifying other zero-value external outputs

- [`History-Edge.md`](History-Edge.md)
