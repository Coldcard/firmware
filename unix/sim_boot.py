# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Code for the simulator to run, to get it to the point where main.py is called
# on real system. Equivilent to a few lines of code found in stm32/COLDCARD/initfs.c
#

import machine, pyb, sys

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

    # not best place for this
    nvstore.MK4_WORKDIR = './settings/'
    nvstore.SettingsObject._deny_slot = lambda *a:None

    if '--eff' in sys.argv:
        # ignore files ondisk from previous runs, and also dont write any
        nvstore.SettingsObject.load = lambda *a:None
        nvstore.SettingsObject.save = lambda *a:None
        # limitation: pre-login values arent stored even during operation

        #glob.settings.current = dict(sim_defaults)

if '--early-usb' in sys.argv:
    from usb import enable_usb
    enable_usb()

# Install various hacks and workarounds
import mk4
import sim_mk4
import sim_battery
import sim_psram
import sim_vdisk

if sys.argv[-1] != '-q':
    import main     # must be last, does not return

# EOF
