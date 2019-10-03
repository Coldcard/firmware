# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Code for the simulator to run, to get it to the point where main.py is called
# on real system. Equivilent to a few lines of code found in stm32/COLDCARD/initfs.c

import machine, pyb, sys, os

if '--metal' in sys.argv:
    # next in argv will be two open file descriptors to use for serial I/O to a real Coldcard
    import bare_metal
    _n = sys.argv.index('--metal')+1
    bare_metal.start(*(int(sys.argv[a]) for a in [_n, _n+1]))
    del _n, bare_metal

if sys.argv[-1] != '-q':
    from main import go
    go()

# EOF
