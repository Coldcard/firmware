#!/usr/bin/env python3
#
# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Capture build time and version number into a number used as the timestamp on
# all created files for that Coldcard version.
#
import os, sys, time, datetime

out_fname, version = sys.argv[1:]

assert out_fname.endswith('.c'), out_fname

# return ((2000 + date.Year - 1980) << 25) | ((date.Month) << 21) | ((date.Date) << 16) | ((time.Hours) << 11) | ((time.Minutes) << 5) | (time.Seconds / 2);
today = datetime.date.today()
value = ((today.year - 1980) << 25) | (today.month << 21) | (today.day << 16) 

h, m, s = [int(x) for x in version.split('.')]
value |= (h << 11) | (m << 5) | s;

with open(out_fname, 'wt') as fd:
    fd.write('''
// (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// AUTO-generated.
//
//   built: %s
// version: %s
//
#include <stdint.h>

// this overrides ports/stm32/fatfs_port.c
uint32_t get_fattime(void) {
    return 0x%08xUL;
}
''' % (today.isoformat(), version, value))
