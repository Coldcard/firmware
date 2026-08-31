# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Bugfix: Reject foreign inputs from BIP-322 Proof of Reserves, including inputs
  disguised with forged key-path metadata or partial signatures.
- Bugfix: Restore the ability to view the device-generated seed before adding user
  entropy, which was available in the previous dice-roll workflow but was inadvertently
  removed in 5.6.1/1.5.1Q. The new **View TRNG Words** menu item displays the full
  256-bit seed from the STM32 TRNG, SE1, and SE2 as 24 BIP39 words, allowing independent
  verification of dice-roll or coin-flip mixing.
- Bugfix: Simulator crashed on Bless Firmware, due to a desynced LED pipe. Thanks to
  [@hitechhayekian](https://github.com/hitechhayekian).
- Bugfix: With an empty master wallet and an active temporary seed, keep imports and backup restores temporary instead of treating them as master-seed changes.

# Mk Specific Changes

## 5.6.x - 2026-0x-xx

- Bugfix: Require unrestricted HSM message-signing policy when signing BIP-322
  messages with WIF Store keys.


# Q Specific Changes

## 1.5.xQ - 2026-0x-xx

- tbd
