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

- New Feature: Allow uncompressed WIF keys in WIF Store
- Enhancement: Faster multisig address generation and PSBT input verification
- Enhancement: Use predictable sequential filenames for PSBTs processed multiple times via MicroSD or Virtual Disk
- Change: Spending Policy mode prevents USB hosts from enrolling, deleting, listing, or exporting
  Multisig/Miniscript wallet configurations
- Change: The main transaction approval story no longer lists every affected input or output for repeated warnings,
  relative timelocks, or unusual change derivation paths. It now shows compact summaries; use the transaction
  explorer to review individual details.
- Bugfix: Generate distinct MuSig2 nonces for different aggregate-key derivations of the same participant set
- Bugfix: Generate unique names when creating multisig wallets from PSBTs with the same M-of-N parameters
- Bugfix: Correctly identify consolidations containing zero-value OP_RETURN outputs without misclassifying other zero-value external outputs
- Bugfix: Prevent duplicate WIF Store keys and multisig wallets after restarting
- Bugfix: Fixed PSBT uploads being mistaken for partial firmware uploads
- Bugfix: Reject BIP388 wallet policy imports with non-ASCII or non-printable names
- Bugfix: Reject duplicate singleton keys in PSBT maps

# Mk4 Specific Changes

## 6.6.xX - 2026-0x-xx

- tbd


# Q Specific Changes

## 6.6.xQX - 2026-0x-xx

- tbd


# Release History

- [`History-Edge.md`](History-Edge.md)
