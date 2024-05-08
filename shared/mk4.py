# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# mk4.py - Mk4 specific code, not needed on earlier devices.
#
#
import os, sys, pyb, ckcc, version, glob

def make_flash_fs():
    # create our fav filesystem, and mount it
    fl = pyb.Flash(start=0)
    os.VfsLfs2.mkfs(fl)

    os.mount(fl, '/flash')

    os.mkdir('/flash/settings')

def make_psram_fs():
    # Filesystem is wiped and rebuilt on each boot before this point, but
    # add some more files.
    ps = ckcc.PSRAM()
    os.mount(ps, '/psram')

    # need DOS-style newlines for best compatibility
    open('/psram/README.txt', 'wt').write('''
COLDCARD Virtual Disk

1) copy your PSBT file here.
2) select from Coldcard menu & approve transaction.
3) signed transaction file(s) will be saved here.

'''.replace('\n', '\r\n'))

    date, ver, *_ = version.get_mpy_version()
    open('/psram/ident/version.txt', 'wt').write('\r\n'.join([ver, date, '']))

    # generally, leave it unmounted
    os.umount('/psram')

def rng_seeding():
    # seed our RNG with entropy from secure elements
    import callgate, ngu, ustruct

    a = callgate.read_rng(1)        # SE1
    b = callgate.read_rng(2)        # SE2

    n = ngu.hash.sha256d(a+b)
    n, = ustruct.unpack('I', n[0:4])

    ngu.random.reseed(n)
        

def init0():
    # called very early
    try:
        os.statvfs('/flash')
    except OSError:
        make_flash_fs()

    try:
        make_psram_fs()
    except BaseException as exc:
        sys.print_exception(exc)

    if version.is_devmode:
        try:
            # need to import this early so it can monkey-patch itself in place
            import sim_display
        except: pass

    # seed RNGs with entropy from secure elements
    rng_seeding()

async def dev_enable_repl(*a):
    # Mk4: Enable serial port connection. You'll have to break case open.
    from ux import ux_show_story

    wipe_if_deltamode()

    # allow REPL access
    ckcc.vcp_enabled(True)

    print("REPL enabled.")
    await ux_show_story("""\
The serial port has now been enabled.\n\n3.3v TTL on Tx/Rx/Gnd pads @ 115,200 bps.""")

def wipe_if_deltamode():
    # If in deltamode, give up and wipe self rather do
    # a thing that might reveal true master secret...

    from pincodes import pa

    if not pa.is_deltamode():
        return

    callgate.fast_wipe()

# EOF
