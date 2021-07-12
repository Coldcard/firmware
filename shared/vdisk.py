# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# vdisk.py - Share a virtual RAM disk with a USB host.
#
#
import os, sys, pyb, ckcc, version, glob, uasyncio
from sigheader import FW_MIN_LENGTH
from public_constants import MAX_UPLOAD_LEN

VD = ckcc.PSRAM()
        
MAX_PSRAM_FILE = const(2<<20)           # 2 megs

def _host_done_cb(_psram):
    # back into the singleton
    glob.VD.host_done_handler()

class VirtDisk:
    def __init__(self):
        VD.callback(_host_done_cb)

        self.contents = self.sample()
        self.ignore = set()

        glob.VD = self

    def sample(self):
        # Peek at the contents of the disk right now
        # - only root directory
        # - only files, and capture their sizes
        try:
            os.mount(VD, '/tmp', readonly=True)

            return list(sorted((fn, sz) for (fn,ty,_,sz) in os.ilistdir('/tmp') if ty == 0x8000))
        except BaseException as exc:
            sys.print_exception(exc)

            return []
        finally:
            os.umount('/tmp')

    def import_file(self, filename, sz):
        # copy file into another area of PSRAM where rest of system can use it
        assert sz < MAX_PSRAM_FILE       # too big

        # I could not resist doing this in C... since we already have the
        # data in memory, why mess around with file concepts?
        actual = VD.copy_file(0, filename)

        assert actual == sz

        return actual

    def new_psbt(self, filename, sz):
        print("new PSBT: " + filename)

    def new_firmware(self, filename, sz):
        # potential new firmware file detected
        self.import_file(filename, sz)
        uasyncio.create_task(psram_upgrade(filename, sz))

    def host_done_handler(self):
        now = self.sample()
        if now == self.contents:
            # no-op change, common, ignore
            return

        self.contents = now

        # Look for files we want to taste; assume they have
        # been fully written-out because we are called after a 
        # fairly long timeout
        print(repr(now))
        for fn, sz in now:

            if fn in self.ignore:
                continue

            if sz >= MAX_PSRAM_FILE: 
                print("%s: too big" % fn)
                self.ignore.add(fn)
                continue

            lfn = fn.lower()

            if lfn.endswith('.psbt') and sz > 100:
                self.new_psbt(fn, sz)

            if lfn.endswith('.dfu') and sz > FW_MIN_LENGTH:
                self.ignore.add(fn)     # in case they decline it
                self.new_firmware(fn, sz)
                

async def psram_upgrade(filename, size):
    # Upgrade to firmware image already in PSRAM at offset zero.
    from glob import dis, PSRAM
    from files import dfu_parse
    from sigheader import FW_HEADER_OFFSET, FW_HEADER_SIZE
    from ux import ux_show_story, the_ux
    from sffile import SFFile

    if PSRAM.read_at(0, 3) == b'Dfu':
        with SFFile(0, size) as fp:
            offset, size = dfu_parse(fp)
    else:
        # handle raw binary file
        offset = 0

    # pull out firmware header
    hdr = PSRAM.read_at(offset+FW_HEADER_OFFSET, FW_HEADER_SIZE)

    if filename == 'dev.dfu' and version.is_devmode:
        # skip the checking and display for us devs and "just do it"
        # - the bootrom still does the checks, you just can't see useful errors
        from pincodes import pa
        pa.firmware_upgrade(offset, size)
        print("dev.dfu being installed")
        return

    # get user buy-in and approval of the change.
    from auth import authorize_upgrade
    authorize_upgrade(hdr, size, hdr_check=True, psram_offset=offset)


# EOF
