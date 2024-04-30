# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_vdisk.py -- SIMULATED virtual disk, using a directory on unix FS
#
import ckcc, version, os
import uasyncio as asyncio

SIMDIR_PATH = ckcc.get_sim_root_dirs()[0] + '/VirtDisk/'

class SimBlockDev:
    # replace ckcc.PSRAM block device that's implemented in C

    def __init__(self):
        self.cb = None
        self.inserted = False

    def callback(self, cb):
        print("sim-virtdisk: callback %s" % bool(cb))
        self.cb = cb
        if cb:
            self.task = asyncio.create_task(self.monitor_task(self))
        else:
            self.task.cancel()

    def set_inserted(self, en):
        print("sim-virtdisk: " + "inserted" if en else "ejected")
        self.inserted = bool(en)

    def wipe(self):
        print("sim-virtdisk: wipe (not implemented)")

    @classmethod
    async def monitor_task(cls, self):
        # works, but hard to manage the atask
        # long-lived task; watch for additions to our directory
        was = repr(os.listdir(SIMDIR_PATH))

        while 1:
            await asyncio.sleep_ms(250)

            now = repr(os.listdir(SIMDIR_PATH))

            if now != was and self.cb and self.inserted:
                print("sim-virtdisk: change detected")
                self.cb(self)

            was = now

ckcc.PSRAM = SimBlockDev

import vdisk

class SimulatedVirtDisk(vdisk.VirtDisk):

    def __init__(self):
        super().__init__()
        self.ignore.update(fn for fn,sz in self.contents)
        print("ignore init = %r" % self.ignore)
    
    def sample(self):
        # Peek at the contents of the disk right now
        from utils import get_filesize

        return list(sorted((SIMDIR_PATH+fn, get_filesize(SIMDIR_PATH+fn)) 
                                for (fn,ty,_) in os.ilistdir(SIMDIR_PATH) if ty == 0x8000))

    def mount(self, readonly=False):
        return SIMDIR_PATH[:-1]

    def unmount(self, written_files, readonly=False):
        #print("sim-virtdisk: CC unmounted; ready to view")
        for fn in written_files:
            self.ignore.add(fn.split('/')[-1])

    def import_file(self, filename, sz):
        # copy file into another area of PSRAM where rest of system can use it
        print("sim-virtdisk: read %s" % filename)
        contents = open(SIMDIR_PATH+filename, 'rb').read(sz)
        from glob import PSRAM
        PSRAM.write_at(0, sz)[:] = contents
        return sz

vdisk.VirtDisk = SimulatedVirtDisk

# EOF
