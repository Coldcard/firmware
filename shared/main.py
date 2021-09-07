# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# main.py
#
# - importing this file starts the system, see "go()"
# - NO: main.loop is imported and "run forever" by boot.py, forced into place by COLDCARD/initfs code
# - cannot be changed by /flash/lib overrides, because already imported before that.
#

# see RAM_HEADER_BASE, and coldcardFirmwareHeader_t in sigheader.h
import pyb, sys, gc, glob
from imptask import IMPT, die_with_debug

assert not glob.dis, "main reimport"

# this makes the GC run when larger objects are free in an attempt to reduce fragmentation.
gc.threshold(4096)

if 1:
    # useful for debug: keep this stub!
    import ckcc
    ckcc.vcp_enabled(True)
    #pyb.usb_mode('VCP+MSC')            # handy but annoying disk issues
    #pyb.usb_mode('VCP')
if 0:
    raise SystemExit

print("---\nColdcard Wallet from Coinkite Inc. (c) 2018-2021.\n")

from version import get_mpy_version
datestamp,vers,_ = get_mpy_version()
print("Version: " + vers + " / " + datestamp)

# Setup OLED and get something onto it.
from display import Display
dis = Display()
dis.splash()
glob.dis = dis

# slowish imports, some with side-effects
import version, ckcc, uasyncio

if version.mk_num == 4:
    # early setup code needed on Mk4
    try:
        import mk4
        mk4.init0()

        from psram import PSRAMWrapper
        glob.PSRAM = PSRAMWrapper()

    except BaseException as exc:
        sys.print_exception(exc)
        # continue tho
else:
    # Serial Flash memory
    from sflash import SF

if version.is_devmode:
    # For devs only: allow code in this directory to overide compiled-in stuff. Dangerous!
    # - using relative paths here so works better on simulator
    # - you must boot w/ non-production-signed firmware to get here
    sys.path.insert(0, 'flash/lib')

    # Give external devs a way to start stuff early
    try:
        import boot2
    except: pass


# Setup membrane numpad (mark 2+)
from mempad import MembraneNumpad
numpad = MembraneNumpad()
glob.numpad = numpad

# NV settings
from nvstore import SettingsObject
settings = SettingsObject(glob.dis)
glob.settings = settings

async def more_setup():
    # Boot up code; splash screen is being shown
                
    # MAYBE: check if we're a brick and die again? Or show msg?
    
    try:
        # Some background "tasks"
        #
        from dev_helper import monitor_usb
        IMPT.start_task('vcp', monitor_usb())

        from files import CardSlot
        CardSlot.setup()

        # This "pa" object holds some state shared w/ bootloader about the PIN
        try:
            from pincodes import pa
            pa.setup(b'')       # just to see where we stand.
        except RuntimeError as e:
            print("Problem: %r" % e)

        if version.is_factory_mode:
            print("factory mode")
            # in factory mode, turn on USB early to allow debug/setup
            from usb import enable_usb
            enable_usb()

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
    except BaseException as exc:
        die_with_debug(exc)

    IMPT.start_task('mainline', mainline())

async def mainline():
    # Mainline of program, after startup
    #
    # - Do not add to this function, its vars are
    #   in memory forever; instead, extend more_setup above.
    from actions import goto_top_menu
    from ux import the_ux

    goto_top_menu()

    gc.collect()
    print("Free mem: %d" % gc.mem_free())

    while 1:
        await the_ux.interact()


def go():
    # Wrapper for better error handling/recovery at top level.
    #
    try:
        uasyncio.get_event_loop().run_forever()
        raise RuntimeError('main.stop')     # not expected
    except BaseException as exc:
        die_with_debug(exc)

if version.is_devmode:
    # Give external devs a way to start semi-early.
    try:
        import main2
    except: pass

uasyncio.create_task(more_setup())
go()

# EOF
