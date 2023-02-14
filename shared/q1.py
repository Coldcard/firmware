# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# q1.py - Q1 specific code, not needed on earlier devices.
#
# NOTE: Lots of hardware overlap with Mk4, so see mk4.py too!
#
import os, sys, pyb, ckcc, version, glob

def init0():
    # called very early
    from mk4 import init0 as mk4_init0

    # replace drawing code.
    import lcd_display as display
    sys.modules['display'] = display

    mk4_init0()

    from scanner import QRScanner
    glob.SCAN = QRScanner()

# EOF
