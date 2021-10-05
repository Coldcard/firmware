# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
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

if '--sflash' not in sys.argv:
    import nvstore
    from sim_settings import sim_defaults
    nvstore.SettingsObject.default_values = lambda _: dict(sim_defaults)
    nvstore.settings.current = dict(sim_defaults)

if sys.argv[-1] != '-q':
    import main     # must be last, does not return

# EOF
