# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Bugfix: Restore the ability to view the device-generated seed before adding user
  entropy, which was available in the previous dice-roll workflow but was inadvertently
  removed in 5.6.1/1.5.1Q. The new **View TRNG Words** menu item displays the full
  256-bit seed from the STM32 TRNG, SE1, and SE2 as 24 BIP39 words, allowing independent
  verification of dice-roll or coin-flip mixing.
- Bugfix: Simulator crashed on Bless Firmware, due to a desynced LED pipe. Thanks to
  [@hitechhayekian](https://github.com/hitechhayekian).
- Enhancement: Support the unified opt-in signature hash. A PSBT can now ask for hash
  types 0x21, 0x22, 0x23, 0xa1, 0xa2 and 0xa3, and the resulting signature commits to
  every spent amount and scriptPubKey rather than only the one being signed, which
  removes CVE-2013-2292 and CVE-2020-14199 for the inputs that opt in. Because the
  message differs from every existing one, an opted-in transaction is also protected
  against replay onto any chain that does not implement the rule. Signing is unaffected
  unless a PSBT asks for it. Covers bare, P2SH and segwit v0 inputs; this
  tree does not sign taproot, so the rule's taproot script types are not reached.

# Mk Specific Changes

## 5.6.x - 2026-0x-xx

- tbd


# Q Specific Changes

## 1.5.xQ - 2026-0x-xx

- tbd
