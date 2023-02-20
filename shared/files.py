# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# files.py - MicroSD and related functions.
#
import pyb, ckcc, os, sys, utime, glob
from uerrno import ENOENT

async def needs_microsd():
    # Standard msg shown if no SD card detected when we need one.
    from ux import ux_show_story
    return await ux_show_story("Please insert a MicroSD card before attempting this operation.")

def _is_ejected():
    sd = pyb.SDCard()
    return not sd.present()

def is_dir(fname):
    if os.stat(fname)[0] & 0x4000:
        return True
    return False

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
    # erase and re-format the flash filesystem (/flash/**)
    import ckcc, pyb
    from glob import dis
    from version import mk_num
    
    dis.fullscreen('Erasing...')
    os.umount('/flash')

    # from extmod/vfs.h
    BP_IOCTL_SEC_COUNT = (4)
    BP_IOCTL_SEC_SIZE  = (5)

    # block-level erase
    fl = pyb.Flash(start=0)         # start=0 does magic things
    bsize = fl.ioctl(BP_IOCTL_SEC_SIZE, 0)
    assert bsize == 512
    bcount = fl.ioctl(BP_IOCTL_SEC_COUNT, 0)

    blk = bytearray(bsize)
    ckcc.rng_bytes(blk)

    for n in range(bcount):
        fl.writeblocks(n, blk)
        ckcc.rng_bytes(blk)
        dis.progress_bar_show(n/bcount)
        
    # rebuild and mount /flash
    dis.fullscreen('Rebuilding...')
    
    if mk_num == 4:
        # no need to erase, we just put new FS on top
        import mk4
        mk4.make_flash_fs()
    else:
        ckcc.wipe_fs()

        # remount it
        os.mount(fl, '/flash')

    # re-store current settings
    from glob import settings
    settings.save()

def wipe_microsd_card():
    # Erase and re-format SD card. Not secure erase, because that is too slow.
    import ckcc, pyb
    from glob import dis
    
    try:
        os.umount('/sd')
    except:
        pass

    sd = pyb.SDCard()
    assert sd

    if not sd.present():

        return

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

    dis.fullscreen('Formatting...')

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
    # Manage access to the SDCard h/w resources
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
        from machine import Pin
        cls.active_led = Pin('SD_ACTIVE', Pin.OUT)

    @classmethod
    def is_inserted(cls):
        # debounce?
        return not _is_ejected()

    def __init__(self, force_vdisk=False, readonly=False):
        self.mountpt = None
        self.force_vdisk = force_vdisk
        self.readonly = readonly
        self.wrote_files = set()

    def __enter__(self):
        # Mk4: maybe use our virtual disk in preference to SD Card
        if glob.VD and (_is_ejected() or self.force_vdisk):
            self.mountpt = glob.VD.mount(self.readonly)
            return self

        # Get ready!
        self.active_led.on()

        # busy wait for card pin to debounce/settle
        while 1:
            since = utime.ticks_diff(utime.ticks_ms(), self.last_change)
            if since > 50:
                break
            utime.sleep_ms(5)

        # attempt to use micro SD
        ok = _try_microsd()

        if not ok:
            self._recover()

            raise CardMissingError

        self.mountpt = self.get_sd_root()       # probably /sd

        return self

    def __exit__(self, *a):
        if self.mountpt == '/sd':
            self._recover()
        elif glob.VD:
            glob.VD.unmount(self.wrote_files)

        self.mountpt = None
        return False

    def open(self, fname, mode='r', **kw):
        # open a file for read/write
        # - track new files for virtdisk case
        if 'w' in mode:
            assert not self.readonly
            self.wrote_files.add(fname)

        return open(fname, mode, **kw)
        
    def _recover(self):
        # done using the microSD -- unpower it
        self.active_led.off()

        try:
            assert self.mountpt == '/sd'
            os.umount('/sd')
        except: pass

        # previously important: turn off power so touch can work again (Mk1)
        sd = pyb.SDCard()
        sd.power(0)

    def get_sd_root(self):
        # get the path to the SD card
        if ckcc.is_simulator():
            return ckcc.get_sim_root_dirs()[1]
        else:
            return '/sd'

    def get_paths(self):
        # (full) paths to check on the card
        #root = self.get_sd_root()
        #return [root]
        return [self.mountpt]

    def is_dir(self, fname):
        return is_dir(self.abs_path(fname))

    def abs_path(self, fname):
        return self.mountpt + "/" + fname

    def get_id_hash(self):
        # hash over card config and serial # details
        # - stupidly it's over the repr of a functions' result
        import ngu

        info = pyb.SDCard().info()
        assert info 

        if len(info) == 3:
            # expected in v4
            csd_cid = pyb.SDCard().ident()
            info = tuple(list(info) + list(csd_cid))

        return ngu.hash.sha256s(repr(info))

    @staticmethod
    def exists(fname):
        try:
            os.stat(fname)
        except OSError as e:
            if e.args[0] == ENOENT:
                return False
        return True

    def pick_filename(self, pattern, path=None, overwrite=False):
        # given foo.txt, return a full path to filesystem, AND
        # a nice shortened version of the filename for display to user
        # - assuming we will write to it, so cannot exist
        # - return None,None if no SD card or can't mount, etc.
        # - no UI here please
        import ure

        assert self.mountpt      # else: we got used out of context mgr

        # put it back where we found it
        path = path or (self.mountpt + '/')

        assert '/' not in pattern
        assert '.' in pattern

        basename, ext = pattern.rsplit('.', 1)
        ext = '.' + ext

        # try w/o any number first
        fname = path + basename + ext

        if overwrite or not self.exists(fname):
            return fname, basename + ext

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

    def securely_blank_file(self, full_path):
        # input PSBT file no longer required; so delete it
        # - blank with zeros
        # - rename to garbage (to hide filename after undelete)
        # - delete 
        # - ok if file missing already (card maybe have been swapped)
        #
        # NOTE: we know the FAT filesystem code is simple, see 
        #       ../external/micropython/extmod/vfs_fat.[ch]

        self.wrote_files.discard(full_path)

        path, basename = full_path.rsplit('/', 1)

        try:
            blk = bytes(64)

            with open(full_path, 'r+b') as fd:
                size = fd.seek(0, 2)
                fd.seek(0)

                # blank it
                for i in range((size // len(blk)) + 1):
                    fd.write(blk)

                assert fd.seek(0, 1) >= size

            # probably pointless, but why not:
            os.sync()

        except OSError as exc:
            # missing file is okay
            if exc.args[0] == ENOENT: return
            raise

        # rename it and delete
        new_name = path + '/' + ('x'*len(basename))
        os.rename(full_path, new_name)
        os.remove(new_name)

# EOF
