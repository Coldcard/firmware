# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# battery.py - Q-specific code related to batteries, their settings, and monitoring them.
#
from imptask import IMPT
import uasyncio as asyncio
from machine import Pin

# value must exist in battery_idle_timeout_chooser() choices
DEFAULT_BATT_IDLE_TIMEOUT = const(30*60)

# 0..255 brightness value for when on batteries
DEFAULT_BATT_BRIGHTNESS = const(200)

# had to move this pin in RevD
# - TODO: remove this support once rev D's are around
rev_d_later = not Pin('REV_D', mode=Pin.IN, pull=Pin.PULL_UP)
nbat_pin = Pin('NOT_BATTERY_OLD' if not rev_d_later else 'NOT_BATTERY',
                            mode=Pin.IN, pull=Pin.PULL_UP)

def setup_battery():
    # setup and monitor things.
    setup_adc()

    IMPT.start_task('battery', batt_monitor_task())
    

async def batt_monitor_task():
    # Long-lived task to watch battery level and USB vs. battery power source
    # TODO: be a class
    from glob import dis

    def maybe_update(unused_arg=None, last_lvl=-100):
        lvl = get_batt_threshold()
        if lvl != last_lvl:
            dis.draw_status(bat=lvl)
        return lvl

    if rev_d_later:
        nbat_pin.irq(maybe_update, Pin.IRQ_FALLING|Pin.IRQ_RISING)

    last_lvl = None
    while 1:
        # slowly track battery level
        await asyncio.sleep(30 if rev_d_later else 5)

        last_lvl = maybe_update(last_lvl=last_lvl)

def setup_adc():
    # configure VREF source as internally generated
    import uctypes

    VREF_LAYOUT = {
        "CSR": 0 | uctypes.UINT32,
        "CCR": 4 | uctypes.UINT32,
    }
    VREFBUF_CSR = 0x40010030

    vref = uctypes.struct(VREFBUF_CSR, VREF_LAYOUT)
    vref.CSR = 0x05     # VRS=1, HIZ=0, ENVR=1  2.5v ref

    # could delay here until reads back as 0x9 (VRR==1)
    # but no need 

def get_batt_level():
    # return voltage from batteries, as a float
    # - will only work on battery power, else return None
    try:
        from machine import ADC, Pin
    except ImportError:
        # simulator
        return 3.3

    if nbat_pin() == 1:
        # not getting power from batteries, so don't know level
        return None

    adc = ADC(Pin('VIN_SENSE'))
    avg = sum(adc.read_u16() for i in range(13)) / 13.0

    return round((avg / 65535.0) * 2.5 * 2, 1)
    
def get_batt_threshold():
    # return 0=empty, 1=low, 2=75% 3=full or None if no bat
    volts = get_batt_level()
    if volts is None:
        return None
    if volts <= 2.9:
        return 0
    if volts <= 3.5:
        return 1
    if volts <= 4.0:
        return 2
    return 3

def brightness_chooser():
    from glob import settings, dis

    bright = settings.get('bright', DEFAULT_BATT_BRIGHTNESS)

    ch = [ '25%', '50%', '60%', '70%', '80% (default)', '90%','100%']
    va = [ 64, 128, 153, 180, DEFAULT_BATT_BRIGHTNESS, 230, 255]

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
