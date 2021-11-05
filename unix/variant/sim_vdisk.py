# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sim_vdisk.py -- SIMULATED virtual disk, using a directory on unix FS
#
import vdisk, version, os, ckcc

_EJECTED = True

class SimBlockDev:
    # replace ckcc.PSRAM block device implemented in C

    def callback(self, cb):
        print("sim-virtdisk: callback %s" % bool(cb))

    def set_inserted(self, en):
        global _EJECTED
        print("sim-virtdisk: " + "inserted" if en else "ejected")
        _EJECTED = bool(en)

    def wipe(self):
        return

vdisk.VBLKDEV = SimBlockDev()

class SimulatedVirtDisk(vdisk.VirtDisk):
    
    def sample(self):
        # Peek at the contents of the disk right now
        assert _EJECTED     # don't read while host might update
        from utils import get_filesize

        path = ckcc.get_sim_root_dirs()[0] + '/VirtDisk'

        return list(sorted((fn, get_filesize(fn)) for (fn,ty,_) in os.ilistdir(path) 
                                            if ty == 0x8000))

    def mount(self, readonly=False):
        rv= ckcc.get_sim_root_dirs()[0] + '/VirtDisk'
        print(rv)
        return rv

    def unmount(self):
        #print("sim-virtdisk: CC unmounted; ready to view")
        pass

    def import_file(self, filename, sz):
        # copy file into another area of PSRAM where rest of system can use it
        print("sim-virtdisk: read %s" % filename)
        contents = open(filename, 'rb').read(sz)
        from glob import PSRAM
        PSRAM.write_at(0, sz)[:] = contents
        return sz

vdisk.VirtDisk = SimulatedVirtDisk

# EOF
