# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Security Improvement: Master seed generation mixes entropy from both Secure
  Elements with the STM32 TRNG (previously TRNG only).
- Security Improvement: RNG is seeded with the full 256-bit digest of entropy
  from both Secure Elements (previously truncated to 32 bits).
- Bugfix: Detect RNG_SR_SEIS and RNG_SR_SECS, retry safely, and fail closed on persistent faults.

# Mk Specific Changes

## 5.5.x - 2065-09-xx

- tbd


# Q Specific Changes

## 1.4.xQ - 2065-09-xx

- tbd
