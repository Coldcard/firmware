# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# mk4.py - Mk4 specific code, not needed on earlier devices.
#
#
import os, sys, pyb, ckcc, version, glob

def make_flash_fs():
    print("Rebuild /flash")

    # create our fav filesystem, and mount it
    fl = pyb.Flash(start=0)
    os.VfsLfs2.mkfs(fl)

    os.mount(fl, '/flash')

    open('/flash/README.txt', 'wt').write("LFS Virt disk")
    os.mkdir('/flash/settings')

def make_psram_fs():
    # Filesystem is wiped and rebuild on each boot before this point, but
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

async def dev_enable_repl(*a):
    # Enable serial port connection. You'll have to break case open.
    from ux import ux_show_story

    # allow REPL access
    ckcc.vcp_enabled(True)

    print("REPL enabled.")
    await ux_show_story("""\
The serial port has now been enabled.\n\n3.3v TTL on Tx/Rx/Gnd pads @ 115,200 bps.""")

# EOF
