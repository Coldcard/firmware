# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sram2.py - Jam some larger, long-lived objects into the SRAM2 area, which isn't used enough.
#
# Cautions/Notes: 
# - mpy heap does not include SRAM2, so doing manual memory alloc here.
# - top 8k reserved for bootloader, which will wipe it on each entry
#   - top page of that is specially marked to cause reset if any attempt to change
# - 2k at bottom reserved for code in `flashbdev.c` to use as cache data for flash writing
# - keep this file in sync with simulated version 
# - none of the above is true anymore on mk4 and later!
#
import uctypes, ckcc
from version import mk_num

if mk_num < 4:
    # see stm32/COLDCARD/layout.ld where this is effectively defined
    SRAM2_START = const(0x10000800)
    SRAM2_LENGTH = const(0x5800)

    _start = SRAM2_START

    def _alloc(ln):
        global _start
        rv = uctypes.bytearray_at(_start, ln)
        _start += ln
        return rv
else:
    # Mk4 has tons of memory, so just use it
    def _alloc(ln):
        return bytearray(ln)

nvstore_buf = _alloc(4096-32)
display_buf = _alloc(1024)
display2_buf = _alloc(1024)
usb_buf = _alloc(2048+12)       # 2060 @ 0x10001be0
tmp_buf = _alloc(1024)
psbt_tmp256 = _alloc(256)

if mk_num < 4:
    assert _start <= 0x10006000

    # observed: about 22k on Mk2
    ckcc.stack_limit(SRAM2_LENGTH - (_start - SRAM2_START))

# EOF
