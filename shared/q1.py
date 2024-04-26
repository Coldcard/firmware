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

async def scan_and_bag(*a):
    # Mk4 took a bag number over USB from a prod test station,
    # but on Q we can scan the barcode ourselves.
    from pincodes import pa
    from glob import dis, settings
    import callgate
    from ux import ux_show_story
    from ux_q1 import QRScannerInteraction
    from uasyncio import sleep

    try:
        assert settings.get('tested', False), 'Not tested yet'
        assert pa.is_blank() or version.is_factory_mode, 'Bad mode'
    except Exception as exc:
        await ux_show_story(str(exc), 'Cannot Bag')
        return

    zz = QRScannerInteraction()
    while 1: 
        # Get our bag number
        got = await zz.scan_text('Scan barcode on new bag.')

        if not got:
            return

        if not got.isdigit() or not (8 <= len(got) <= 32):
            # bad scan/not a bag
            await ux_show_story(got, "Bad Scan")
            continue

        break
    
    bag_num = got

    # do the change
    failed = callgate.set_bag_number(bag_num.encode())
    assert not failed

    # lock down bootrom against further changes.
    callgate.set_rdp_level(2)

    # set genuine light
    pa.greenlight_firmware()

    # we are done.
    dis.real_clear()
    dis.text(None, 3, bag_num, invert=1)
    dis.text(None, 6, "Put into bag and seal now.")
    dis.show()

    # lockup but keep the power btn working...
    while 1:
        await sleep(10)

# EOF
