# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# files.py - MicroSD and related functions.
#
import pyb, ckcc, os, sys, utime
from uerrno import ENOENT


def _try_microsd(bad_fs_ok=False):
    # Power up, mount the SD card, return False if we can't for some reason.
    #
    # If we're about to reformat, we don't need a working filesystem

    sd = pyb.SDCard()

    if not sd.present():
        return False

    if ckcc.is_simulator():
        return True

    try:
        # already mounted and ready?
        st = os.statvfs('/sd')
        return True
    except OSError:
        pass

    try:
        sd.power(1)
        os.mount(sd, '/sd', readonly=0, mkfs=0)
        st = os.statvfs('/sd')

        return True

    except OSError as exc:
        # corrupt or unformated SD card (or something)
        if bad_fs_ok: return True
        #sys.print_exception(exc)
        return False


def wipe_flash_filesystem():
    # erase and re-format the flash filesystem (/flash/)
    import ckcc, pyb
    from main import dis, settings
    
    dis.fullscreen('Erasing...')
    os.umount('/flash')

    # from extmod/vfs.h
    BP_IOCTL_SEC_COUNT = (4)
    BP_IOCTL_SEC_SIZE  = (5)

    # block-level erase
    fl = pyb.Flash()
    bsize = fl.ioctl(BP_IOCTL_SEC_SIZE, 0)
    assert bsize == 512
    bcount = fl.ioctl(BP_IOCTL_SEC_COUNT, 0)

    blk = bytearray(bsize)
    ckcc.rng_bytes(blk)
    
    # trickiness: actual flash blocks are offset by 0x100 (FLASH_PART1_START_BLOCK)
    # so fake MBR can be inserted. Count also inflated by 2X, but not from ioctl above.
    for n in range(bcount):
        fl.writeblocks(n + 0x100, blk)
        ckcc.rng_bytes(blk)

        dis.progress_bar_show(n*2/bcount)
        
    # rebuild and mount /flash
    dis.fullscreen('Rebuilding...')
    ckcc.wipe_fs()

    # re-store settings
    settings.save()

def wipe_microsd_card():
    # Erase and re-format SD card. Not secure erase, because that is too slow.
    import ckcc, pyb
    from main import dis
    
    try:
        os.umount('/sd')
    except:
        pass

    sd = pyb.SDCard()
    assert sd

    if not sd.present(): return

    # power cycle so card details (like size) are re-read from current card
    sd.power(0)
    sd.power(1)

    dis.fullscreen('Part Erase...')
    cutoff = 1024       # arbitrary
    blk = bytearray(512)

    for  bnum in range(cutoff):
        ckcc.rng_bytes(blk)
        sd.writeblocks(bnum, blk)
        dis.progress_bar_show(bnum/cutoff)

    dis.fullscreen('Formating...')

    # remount, with newfs option
    os.mount(sd, '/sd', readonly=0, mkfs=1)

    # done, cleanup
    os.umount('/sd')

    # important: turn off power
    sd = pyb.SDCard()
    sd.power(0)

def dfu_parse(fd):
    # do just a little parsing of DFU headers, to find start/length of main binary
    # - not trying to support anything but what ../stm32/Makefile will generate
    # - see external/micropython/tools/pydfu.py for details
    # - works sequentially only
    import struct
    from ucollections import namedtuple

    fd.seek(0)

    def consume(xfd, tname, fmt, names):
        # Parses the struct defined by `fmt` from `data`, stores the parsed fields
        # into a named tuple using `names`. Returns the named tuple.
        size = struct.calcsize(fmt)
        here = xfd.read(size)
        ty = namedtuple(tname, names.split())
        values = struct.unpack(fmt, here)
        return ty(*values)

    dfu_prefix = consume(fd, 'DFU', '<5sBIB', 'signature version size targets')

    #print('dfu: ' + repr(dfu_prefix))

    assert dfu_prefix.signature == b'DfuSe', "Not a DFU file (bad magic)"

    for idx in range(dfu_prefix.targets):

        prefix = consume(fd, 'Target', '<6sBI255s2I', 
                                   'signature altsetting named name size elements')

        #print("target%d: %r" % (idx, prefix))

        for ei in range(prefix.elements):
            # Decode target prefix
            #   <   little endian
            #   I   uint32_t    element address
            #   I   uint32_t    element size
            elem = consume(fd, 'Element', '<2I', 'addr size')

            #print("target%d: %r" % (ei, elem))

            # assume bootloader at least 32k, and targeting flash.
            assert elem.addr >= 0x8008000, "Bad address?"

            return fd.tell(), elem.size


class CardMissingError(RuntimeError):
    pass

class CardSlot:
    # Touch interface must be disabled during any SD Card usage!
    last_change = None
    active_led = None

    @classmethod
    def setup(cls):
        # Watch the SD card-detect signal line... but very noisy
        # - this is called a few seconds after system startup

        from pyb import Pin, ExtInt

        def card_change(_):
            # Careful: these can come fast and furious!
            cls.last_change = utime.ticks_ms()

        cls.last_change = utime.ticks_ms()

        cls.irq = ExtInt(Pin('SD_SW'), ExtInt.IRQ_RISING_FALLING, Pin.PULL_UP, card_change)

        # mark 2+ boards have a light for SD activity.
        import version
        from machine import Pin

        cls.active_led = Pin('SD_ACTIVE', Pin.OUT)

    def __init__(self):
        self.active = False

    def __enter__(self):
        # Get ready!
        if self.active_led:
            self.active_led.on()

        # turn off touch scanning
        from main import numpad
        numpad.stop()

        # busy wait for card pin to debounce/settle
        while 1:
            since = utime.ticks_diff(utime.ticks_ms(), self.last_change)
            if since > 50:
                break
            utime.sleep_ms(5)

        # attempt to use micro SD
        ok = _try_microsd()

        if not ok:
            self.recover()

            raise CardMissingError

        self.active = True

        return self

    def __exit__(self, *a):
        self.recover()
        return False
        
    def recover(self):
        # done using the microSD -- unpower it
        from main import numpad

        if self.active_led:
            self.active_led.off()

        self.active = False

        try:
            os.umount('/sd')
        except: pass

        # important: turn off power so touch can work again
        sd = pyb.SDCard()
        sd.power(0)

        numpad.start()

    def get_sd_root(self):
        # get the path to the SD card
        if ckcc.is_simulator():
            return ckcc.get_sim_root_dirs()[1]
        else:
            return '/sd'

    def get_paths(self):
        # (full) paths to check on the card
        root = self.get_sd_root()

        return [root]

    def pick_filename(self, pattern, path=None):
        # given foo.txt, return a full path to filesystem, AND
        # a nice shortened version of the filename for display to user
        # - assuming we will write to it, so cannot exist
        # - return None,None if no SD card or can't mount, etc.
        # - no UI here please
        import ure

        assert self.active      # used out of context mgr

        # prefer SD card if we can
        path = path or (self.get_sd_root() + '/')

        assert '/' not in pattern
        assert '.' in pattern

        basename, ext = pattern.rsplit('.', 1)
        ext = '.' + ext

        # try w/o any number first
        fname = path + basename + ext
        try:
            os.stat(fname)
        except OSError as e:
            if e.args[0] == ENOENT:
                # file doesn't exist, done
                return fname, basename+ext
            pass

        # look for existing numbered files, even if some are deleted, and pick next
        # highest filename
        highest = 1
        pat = ure.compile(basename + r'-(\d+)' + ext)

        for fn in os.listdir(path):
            m = pat.match(fn)
            if not m: continue
            highest = max(highest, int(m.group(1)))
                
        fname = path + basename + ('-%d'% (highest+1)) + ext

        return fname, fname[len(path):]

# EOF
