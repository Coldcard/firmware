# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# vdisk.py - Share a virtual RAM disk with a USB host.
#
#
import os, sys, pyb, ckcc, version, glob, uasyncio, utime
from sigheader import FW_MIN_LENGTH
from version import MAX_UPLOAD_LEN, is_devmode
from usb import enable_usb, disable_usb
from uasyncio import sleep_ms

MIN_QUIET_TIME = 250            # (ms) delay after host writes disk, before we look at it.

def _host_done_cb(_psram):
    # get back into the singleton
    assert glob.VD
    if glob.VD:
        glob.VD.host_done_handler()

# singleton: block device implemented on half of the PSRAM
VBLKDEV = ckcc.PSRAM()

class VirtDisk:
    def __init__(self):
        # Feature is enabled, altho USB might be off.
        glob.VD = self

        self.ignore = set()
        self.contents = self.sample()

        assert ckcc.PSRAM
        VBLKDEV.callback(_host_done_cb)
        VBLKDEV.set_inserted(True)

    def shutdown(self):
        # we've been disabled, stop
        VBLKDEV.set_inserted(False)
        VBLKDEV.callback(None)
        glob.VD = None

    def unmount(self, written_files, readonly=False):
        # just unmount; ignore errors
        try:
            os.umount('/vdisk')
        except:
            pass

        # ignore the files we write ourselves
        for fn in written_files:
            if fn.startswith('/vdisk/'):
                self.ignore.add(fn)

        # allow host to change again
        if not readonly:
            enable_usb()
            if glob.VD:
                VBLKDEV.set_inserted(True)

    def mount(self, readonly=False):
        # Prepare to read the filesystem. Block host. Return mount pt.
        for _ in range(10):
            # wait until it's been idle for a little bit
            host = VBLKDEV.get_time()
            if utime.ticks_diff(utime.ticks_ms(), host) > MIN_QUIET_TIME:
                break
            utime.sleep_ms(MIN_QUIET_TIME//5)
        else:
            print("busy disk?")

        try:
            if not readonly:
                disable_usb()
                VBLKDEV.set_inserted(False)
            os.mount(VBLKDEV, '/vdisk', readonly=readonly)
            st = os.statvfs('/vdisk')

            return '/vdisk'
        except OSError as exc:
            # corrupt or unformated?
            # XXX incomplete error handling here; needs work
            VBLKDEV.set_inserted(True)
            sys.print_exception(exc)

            return None

    def sample(self):
        # Peek at the contents of the disk right now
        # - only root directory
        # - only files, and capture their sizes
        try:
            os.mount(VBLKDEV, '/vdisk', readonly=True)

            return list(sorted(('/vdisk/'+fn, sz) for (fn,ty,_,sz) in os.ilistdir('/vdisk') 
                                                        if ty == 0x8000))
        except BaseException as exc:
            sys.print_exception(exc)

            return []
        finally:
            os.umount('/vdisk')

    def import_file(self, filename, sz):
        # copy file into another area of PSRAM where rest of system can use it
        assert sz <= MAX_UPLOAD_LEN       # too big

        # I could not resist doing this in C... since we already have the
        # data in memory, why mess around with file concepts?
        actual = VBLKDEV.copy_file(0, filename.split('/')[-1])

        assert actual == sz

        return actual

    def new_psbt(self, filename):
        # New incoming PSBT has been detected, start to sign it.
        from auth import sign_psbt_file
        uasyncio.create_task(sign_psbt_file(filename, force_vdisk=True, abort=True))

    def new_firmware(self, filename, sz):
        # potential new firmware file detected
        # - copy to start of PSRAM, begin upgrade confirm
        self.import_file(filename, sz)
        uasyncio.create_task(psram_upgrade(filename, sz))

    def host_done_handler(self):
        from glob import settings

        if settings.get('vidsk', 0) != 2:
            # auto mode not enabled, so ignore changes
            return

        now = self.sample()
        if now == self.contents:
            # no-op change, common, ignore
            # - timestamp changes, hidden files, MacOS BS, etc.
            return

        # clear ignored items once they are deleted
        self.ignore.intersection_update(fn for fn,_ in now)

        self.contents = now

        # Look for files we want to taste; assume they have
        # been fully written-out because we are called after a 
        # fairly long timeout
        for fn, sz in now:

            if fn in self.ignore:
                continue

            if fn[0] == '.' or not sz:
                continue

            if sz > MAX_UPLOAD_LEN:             # == MAX_UPLOAD_LEN_MK4, see version.py
                #print("%s: too big" % fn)
                continue

            lfn = fn.lower()

            if lfn.endswith('.psbt') and sz > 100 and ("-signed" not in lfn):
                self.ignore.add(fn)
                self.new_psbt(fn)
                break

            if lfn.endswith('.dfu') and sz > FW_MIN_LENGTH:
                self.ignore.add(fn)     # in case they decline it
                self.new_firmware(fn, sz)
                break

    async def wipe_disk(self):
        # Reformat. Near instant.
        from glob import dis
        from mk4 import make_psram_fs

        dis.fullscreen('Formatting...')
        dis.progress_bar_show(0.1)

        disable_usb()
        VBLKDEV.wipe()
        make_psram_fs()
        enable_usb()

        await sleep_ms(50)
        dis.progress_bar_show(1)
        await sleep_ms(250)
                

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

    if filename == '/vdisk/dev.dfu' and is_devmode:
        # skip the checking and display for us devs and "just do it"
        # - the bootrom still does the checks, you just can't see useful errors
        from pincodes import pa
        assert pa.is_successful()
        print("dev.dfu being installed")
        dis.bootrom_takeover()
        pa.firmware_upgrade(offset, size)
        return

    # get user buy-in and approval of the change.
    from auth import authorize_upgrade
    authorize_upgrade(hdr, size, hdr_check=True, psram_offset=offset)


# EOF
