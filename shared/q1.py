# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# q1.py - Q1 specific code, not needed on earlier devices.
#
# NOTE: Lots of hardware overlap with Mk4, so see mk4.py too!
#
import os, sys, pyb, ckcc, version, glob, uctypes

# value must exist in battery_idle_timeout_chooser() choices
DEFAULT_BATT_IDLE_TIMEOUT = const(30*60)

# 0..255 brightness value for when on batteries
DEFAULT_BATT_BRIGHTNESS = const(200)

def init0():
    # called very early
    from mk4 import init0 as mk4_init0

    # replace drawing code.
    import lcd_display as display
    sys.modules['display'] = display

    mk4_init0()

    # XXX do not ship like this XXX
    ckcc.vcp_enabled(True); print("REPL enabled")

    # Setup various hardware features of the Q1
    # - try to continue in case of errors/hardware faults
    try:
        from scanner import QRScanner
        glob.SCAN = QRScanner()
    except: pass

    try:
        import battery
        battery.setup_battery()
        #print('Batt volt: %s' % get_batt_level())
    except: pass

# EOF
