# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# main.py
#
# - main.loop is imported and "run forever" by boot.py, forced into place by COLDCARD/initfs code
# - cannot be changed by /flash/lib overrides, because already imported before that.
#

# see RAM_HEADER_BASE, and coldcardFirmwareHeader_t in sigheader.h
import pyb, sys, version, gc

# this makes the GC run when larger objects are free in an attempt to reduce fragmentation.
gc.threshold(4096)

if 0:
    # useful for debug: keep this stub!
    import ckcc
    ckcc.vcp_enabled(True)
    #pyb.usb_mode('VCP+MSC')            # handy but annoying disk issues
    pyb.usb_mode('VCP')
    raise SystemExit

# what firmware signing key did we boot with? are we in dev mode?
is_devmode = version.is_devmode()

if is_devmode:
    # For devs only: allow code in this directory to overide compiled-in stuff. Dangerous!
    # - using relative paths here so works better on simulator
    # - you must boot w/ non-production-signed firmware to get here
    sys.path.insert(0, 'flash/lib')

    # Give external devs a way to start stuff early
    try:
        import boot2
    except: pass

import ckcc
import uasyncio.core as asyncio

loop = asyncio.get_event_loop()

print("---\nColdcard Wallet from Coinkite Inc. (c) 2018.\n")

# Setup OLED and get something onto it.
from display import Display
dis = Display()
dis.splash()

if version.has_membrane:
    # Setup membrane numpad (mark 2+)
    from mempad import MembraneNumpad
    numpad = MembraneNumpad(loop)
else:
    # Setup touch numpad (mark 1 hardware)
    from touchpad import TouchNumpad
    numpad = TouchNumpad(loop)

# Serial Flash memory
from sflash import SPIFlash
sf = SPIFlash()

# NV settings
from nvstore import SettingsObject
settings = SettingsObject(loop)

# important default/restore preference
numpad.sensitivity = settings.get('sens', numpad.sensitivity)


async def done_splash2():
    # Boot up code; after splash screen is done.
                
    # MAYBE: check if we're a brick and die again? Or show msg?

    if version.is_factory_mode():
        # in factory mode, turn on USB early to allow debug/setup
        from usb import enable_usb
        enable_usb(loop, True)

        # always start the self test.
        if not settings.get('tested', False):
            from actions import start_selftest
            await start_selftest()

    else:
        # force them to accept terms (unless marked as already done)
        from actions import accept_terms
        await accept_terms()

    # Prompt for PIN and then pick appropriate top-level menu,
    # based on contents of secure chip (ie. is there
    # a wallet defined)
    from actions import start_login_sequence
    await start_login_sequence()

    loop.create_task(mainline())

async def mainline():
    # Mainline of program, after startup
    #
    # - Do not add to this function, its vars are
    #   in memory forever; instead, extend done_splash2 above.
    from ux import the_ux

    gc.collect()
    #print("Free mem: %d" % gc.mem_free())

    while 1:
        await the_ux.interact()

# Setup to start the splash screen.
dis.splash_animate(loop, done_splash2, numpad.capture_baseline)

# Some background "tasks"
#
from dev_helper import monitor_usb
loop.create_task(monitor_usb())

from files import CardSlot
CardSlot.setup()

# This "pa" object holds some state shared w/ bootloader about the PIN
try:
    from pincodes import PinAttempt

    pa = PinAttempt()
    pa.setup(b'')       # just to see where we stand.
except RuntimeError as e:
    print("Problem: %r" % e)

def go():
    # Wrapper for better error handling/recovery at top level.
    #
    try:
        loop.run_forever()
    except BaseException as exc:
        from usb import is_vcp_active
        is_debug = is_vcp_active()

        if is_debug and isinstance(exc, KeyboardInterrupt):
            # preserve GUI state, but want to see where we are
            print("KeyboardInterrupt")
            raise
        elif isinstance(exc, SystemExit):
            # Ctrl-D and warm reboot cause this, not bugs
            raise
        else:
            # show stacktrace for debug photos
            try:
                import uio, ux
                tmp = uio.StringIO()
                sys.print_exception(exc, tmp)
                msg = tmp.getvalue()
                del tmp
                print(msg)
                ux.show_fatal_error(msg)
            except: pass

            # securely die (wipe memory)
            if not is_debug:
                try:
                    import callgate
                    callgate.show_logout(1)
                except: pass

if is_devmode:
    # Give external devs a way to start semi-early.
    try:
        import main2
    except: pass

# EOF
