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

if os.path.exists(out_fname):
    # to help deterministic builds, don't replace the file from git if verison # is right
    with open(out_fname, 'rt') as fd:
        if ('// version: %s\n' % version) in fd.read():
            print("==> %s already version %s; not changing it" % (out_fname, version))
            sys.exit(0)

# DWORD contains date+time w/ 2-second resolution
today = datetime.date.today()
value = ((today.year - 1980) << 25) | (today.month << 21) | (today.day << 16) 

# only 2second resolution for times, so can only support minor verion up to x.x.5 and hard to see
# anyway, let's omit ... worst case, use the date instead
ver = ''.join(v for v in version if v in '0123456789.')     # strip letter codes from end
h, m, _ = [int(x) for x in ver.split('b')[0].split('.')]
value |= (h << 11) | (m << 5)

with open(out_fname, 'wt') as fd:
    fd.write('''\
// (c) Copyright 2020-%d by Coinkite Inc. This file is covered by license found in COPYING-CC.
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
''' % (today.year, today.isoformat(), version, value))
