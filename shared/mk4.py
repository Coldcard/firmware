# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# mk4.py - Mk4 specific code, not needed on earlier devices.
#
#
import os, sys, pyb, ckcc, version

def make_flash_fs():
    print("Rebuild /flash")

    # create our fav filesystem, and mount it
    fl = pyb.Flash(start=0)
    os.VfsLfs2.mkfs(fl)

    os.mount(fl, '/flash')

    open('/flash/README.txt', 'wt').write("LFS Virt disk")
    os.mkdir('/flash/lib')
    os.mkdir('/flash/settings')

def make_psram_fs():
    # ALWAYS remake this, because PSRAM does not forget old state during quick
    # resets and such.
    print("Mount /psram")

    # Low level code has wipe and created filesystem already, but
    # add some more files?
    ps = ckcc.PSRAM()
    os.mount(ps, '/psram')

    # need DOS-style newlines for best compatibility
    open('/psram/README.txt', 'wt').write('''
COLDCARD Virtual Disk

1) copy your .PSBT file to be signed here.
2) select from Coldcard menu, approve transaction.
3) signed transaction file(s) are created here.

'''.replace('\n', '\r\n'))

    date, ver, *_ = version.get_mpy_version()
    open('/psram/version.txt', 'wt').write('\r\n'.join([ver, date, '']))
    

def init0():
    # called very early
    try:
        os.statvfs('/flash')
    except OSError:
        make_flash_fs()

    try:
        make_psram_fs()
        os.statvfs('/psram')
    except BaseException as exc:
        sys.print_exception(exc)
    


# EOF
