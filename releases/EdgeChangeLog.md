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

- Enhancement: Allow uncompressed WIF keys in WIF Store
- Enhancement: Faster multisig address generation and PSBT input verification
- Enhancement: Use predictable sequential filenames for PSBTs processed multiple times via MicroSD or Virtual Disk
- Change: Spending Policy mode prevents USB hosts from enrolling, deleting, listing, or exporting
  Multisig/Miniscript wallet configurations
- Change: The main transaction approval story no longer lists every affected input or output for repeated warnings,
  relative timelocks, or unusual change derivation paths. It now shows compact summaries; use the transaction
  explorer to review individual details.
- Bugfix: Generate distinct MuSig2 nonces for different aggregate-key derivations of the same participant set
- Bugfix: Prevent PSBT corruption when the same MuSig2 participant performs multiple signing rounds via Key Teleport
- Change: Limit MuSig2 participant lists to 32
- Bugfix: Generate unique names when creating multisig wallets from PSBTs with the same M-of-N parameters
- Bugfix: Correctly identify consolidations containing zero-value OP_RETURN outputs without misclassifying other zero-value external outputs
- Bugfix: Prevent duplicate WIF Store keys and multisig wallets after restarting
- Bugfix: Require HSM policies to explicitly allow any path before signing BIP-322 messages with WIF Store keys
- Bugfix: Fixed PSBT uploads being mistaken for partial firmware uploads
- Bugfix: Reject BIP388 wallet policy imports with non-ASCII or non-printable names
- Bugfix: Reject duplicate singleton keys in PSBT maps
- Bugfix: Restore the ability to view the device-generated seed before adding user
  entropy, which was available in the previous dice-roll workflow but was inadvertently
  removed in 5.6.1/1.5.1Q. The new **View TRNG Words** menu item displays the full
  256-bit seed from the STM32 TRNG, SE1, and SE2 as 24 BIP39 words, allowing independent
  verification of dice-roll or coin-flip mixing.
- Bugfix: Simulator crashed on Bless Firmware, due to a desynced LED pipe. Thanks to
  [@hitechhayekian](https://github.com/hitechhayekian).
- Security hardening: Remove the unused USB CDC/VCP serial interface from normal
  operation and keyboard emulation.

# Mk4 Specific Changes

## 6.6.1X - 2026-0x-xx

- all of the above.


# Q Specific Changes

## 6.6.1QX - 2026-0x-xx

- all of the above.


# Release History

- [`History-Edge.md`](History-Edge.md)
