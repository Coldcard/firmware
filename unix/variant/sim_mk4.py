# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_mk4.py - Simulate Mk4 specific code, not needed on earlier devices.
#
# - just replace/override a few things.
#
import sys, uos, pyb, glob, mk4

def mff_noop():
    print("Skip FS rebuild (simulator)")
mk4.make_flash_fs = mff_noop
mk4.make_psram_fs = mff_noop

def _init0():
    # called very, very early
    
    # install (fake) NFC interface code
    import sim_nfc
    sys.modules['nfc'] = sim_nfc

    # Q1: install (fake) QR scanner interface code
    import sim_scanner
    sys.modules['scanner'] = sim_scanner

    mk4.rng_seeding()

mk4.init0 = _init0
mk4.make_flash_fs = lambda: print("Would rebuild /flash")


# EOF
