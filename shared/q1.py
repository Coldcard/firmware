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
DEFAULT_BATT_BRIGHTNESS = const(180)

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
        setup_adc()
        #print('Batt volt: %s' % get_batt_level())
    except: pass

def setup_adc():
    # configure VREF source as internal 2.5v 
    VREF_LAYOUT = {
        "CSR": 0 | uctypes.UINT32,
        "CCR": 4 | uctypes.UINT32,
    }
    VREFBUF_CSR = 0x40010030

    vref = uctypes.struct(VREFBUF_CSR, VREF_LAYOUT)
    vref.CSR = 0x01     # VRS=0, HIZ=0, ENVR=1

    # could delay here until reads back as 0x9 (VRR==1)
    # but no need 

def get_batt_level():
    # return voltage from batteries, as a float
    # - will only work on battery power, else return None
    try:
        from machine import ADC, Pin
    except ImportError:
        # simulator
        return 2.99

    if Pin('NOT_BATTERY')() == 1:
        # not getting power from batteries, so don't know level
        return None

    adc = ADC(Pin('VIN_SENSE'))
    avg = sum(adc.read_u16() for i in range(10)) / 10.0

    return round((avg / 65535.0) * 2.5 * 2, 2)
    
def get_batt_threshold():
    # return 0=empty, 1=low, 2=75% 3=full or None if no bat
    # TODO check these ranges
    volts = get_batt_level()
    if volts is None:
        return None
    if volts <= 3.0:
        return 0
    if volts <= 3.5:
        return 1
    return 3 if volts > 4.5 else 2

def brightness_chooser():
    from glob import settings, dis

    bright = settings.get('bright', DEFAULT_BATT_BRIGHTNESS)        # as %?

    ch = [ '25%', '50%', '60%', '70% (default)', '80%', '100%']
    va = [ 64, 128, 153, DEFAULT_BATT_BRIGHTNESS, 200, 255]

    try:
        which = va.index(bright)
    except ValueError:
        which = DEFAULT_BATT_BRIGHTNESS

    def _set(idx, text):
        settings.set('bright', va[idx])
        dis.set_lcd_brightness()

    def _preview(idx):
        dis.set_lcd_brightness(tmp_override=va[idx])

    return which, ch, _set, _preview

def battery_idle_timeout_chooser():
    from glob import settings

    timeout = settings.get('batt_to', DEFAULT_BATT_IDLE_TIMEOUT)        # in seconds

    ch = [  
            ' 30 seconds',
            ' 60 seconds',
            ' 2 minutes',
            ' 5 minutes',
            '10 minutes',
            '15 minutes',
            '30 minutes',
            ' 1 hour',
            ' 4 hours',
            ' Never' ]
    va = [ 30, 60, 2*60, 5*60, 10*60, 15*60, 30*60,
              3600, 4*3600, 0 ]

    try:
        which = va.index(timeout)
    except ValueError:
        which = 0

    def _set(idx, text):
        settings.set('batt_to', va[idx])

    return which, ch, _set


async def batt_idle_logout():
    # long-running task to power down when idle too long.
    # - even before login
    import glob
    from uasyncio import sleep_ms
    from glob import settings
    import utime

    while not glob.hsm_active:
        await sleep_ms(5000)

        if get_batt_level() == None:
            # on USB power
            continue

        last = glob.numpad.last_event_time
        if not last:
            continue

        dt = utime.ticks_diff(utime.ticks_ms(), last)

        # they may have changed setting recently
        timeout = settings.get('batt_to', DEFAULT_BATT_IDLE_TIMEOUT)*1000        # ms

        if timeout and dt > timeout:
            # user has been idle for too long: do a logout (and powerdown)
            print("Batt Idle!")

            from actions import logout_now
            await logout_now()
            return              # not reached


# EOF
