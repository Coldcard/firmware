# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Security Improvement: Master seed generation mixes entropy from both Secure
  Elements with the STM32 TRNG (previously TRNG only).
- Security Improvement: RNG is seeded with the full 256-bit digest of entropy
  from both Secure Elements (previously truncated to 32 bits).
- Change: New master seeds now require extra user supplied entropy.
    - Choose key mashing, physical dice rolls or physical coin flips.
    - TRNG, SE1 and SE2 randomness is also mixed into the generated seed.
    - Dice, coin and key mash results are checked for obviously bad distribution.
- Enhancement: Dice-only seed generation now warns that no hardware randomness is
  included and the final hash shown on-screen must be kept secret.
- Bugfix: Detect RNG_SR_SEIS and RNG_SR_SECS, retry safely, and fail closed on persistent faults.

# Mk Specific Changes

## 5.5.x - 2065-09-xx

- tbd


# Q Specific Changes

## 1.4.xQ - 2065-09-xx

- tbd
