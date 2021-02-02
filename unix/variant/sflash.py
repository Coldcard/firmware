# replacement for serial flash stuff, just enough to pass selftest
#
# see real deal at ../shared/sflash.py

_SIZE = 1024*1024        

class SPIFlash:
    PAGE_SIZE = 256
    SECTOR_SIZE = 4096
    BLOCK_SIZE = 65536

    array = bytearray(_SIZE)

    def read(self, address, buf, **kw):
        # random read
        buf[0:len(buf)] = self.array[address:address+len(buf)]

    def write(self, address, buf):
        # 'page program', must already be erased
        assert 1 <= len(buf) <= 256, "max 256"
        assert address & ~0xff == (address+len(buf)-1) & ~0xff, \
                    "page aligned only: addr=0x%x len=0x%x" % (address, len(buf))

        #self.array[address:address+len(buf)] = buf
        # emulate flash memory: can only go from 1=>0
        for i in range(len(buf)):
            self.array[address+i] &= buf[i]

    def is_busy(self):
        # always instant
        return False

    def wait_done(self):
        return

    def chip_erase(self):
        for i in range(_SIZE):
            self.array[i] = 0xff

    def sector_erase(self, address):
        for i in range(self.SECTOR_SIZE):
            self.array[address+i] = 0xff

    def block_erase(self, address):
        # erase 64k at once
        assert address % 65536 == 0, "not block start"
        for i in range(self.BLOCK_SIZE):
            self.array[address+i] = 0xff

    def wipe_most(self):
        # XXX ux here is bad
        # erase everything except settings: takes 5 seconds at least
        from nvstore import SLOTS
        end = SLOTS[0]

        from main import dis
        dis.fullscreen("Cleanup...")

        for addr in range(0, end, self.BLOCK_SIZE):
            self.block_erase(addr)
            dis.progress_bar_show(addr/end)

            while self.is_busy():
                pass

# EOF
