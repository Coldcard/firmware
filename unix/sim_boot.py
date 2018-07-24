# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Code for the simulator to run, to get it to the point where main.py is called
# on real system. Equivilent to few lines of code found in stm32/COLDCARD/initfs.c

#import ffilib
#libc = ffilib.libc()
#libc.func("i", "chdir", "s")('../shared')

import machine, pyb, sys, os

if sys.argv[-1] != '-q':
    from main import go
    go()

# EOF
