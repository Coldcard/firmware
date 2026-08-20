# Change Log

This lists the new changes that have not yet been published in a normal release.

# Shared Improvements - Both Mk and Q

- Bugfix: Reject PSRAM virtual-disk files whose FAT cluster chain covers more bytes than the
  file size, fixing an integer underflow in `psram_copy_file`/`psram_mmap_file` that allowed
  out-of-bounds PSRAM writes from a compromised USB host.

# Mk Specific Changes

## 5.6.x - 2026-0x-xx

- tbd


# Q Specific Changes

## 1.5.xQ - 2026-0x-xx

- tbd
