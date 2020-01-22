# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# sram2.py - Jam some larger, long-lived objects into the SRAM2 area, which isn't used enough.
#
# Cautions/Notes: 
# - mpy heap does not include SRAM2, so doing manual memory alloc here.
# - top 8k reserved for bootloader, which will wipe it on each entry
#   - top page of that is specially marked to cause reset if any attempt to change
# - 2k at bottom reserved for code in `flashbdev.c` to use as cache data for flash writing
# - keep this file in sync with simulated version 
#
import uctypes, ckcc

# see stm32/COLDCARD/layout.ld where this is effectively defined
SRAM2_START = const(0x10000800)
SRAM2_LENGTH = const(0x5800)

_start = SRAM2_START

def _alloc(ln):
    global _start
    rv = uctypes.bytearray_at(_start, ln)
    _start += ln
    return rv

nvstore_buf = _alloc(4096-32)
display_buf = _alloc(1024)
usb_buf = _alloc(2048+12)       # 2060 @ 0x10001be0
tmp_buf = _alloc(1024)
psbt_tmp256 = _alloc(256)
screen_buf = _alloc(1024)

assert _start <= 0x10006000

# observed: about 14k
ckcc.stack_limit(SRAM2_LENGTH - (_start - SRAM2_START))

# EOF
