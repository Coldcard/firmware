# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# sflash.py - SPI Flash on rev D and up boards. Simple serial SPI flash on SPI2 port.
#
# see also ../external/micropython/drivers/memory/spiflash.c
# but not using that, because:
# - not exposed as python objects
# - it wants to waste 4k on a buffer
#
# Layout for project:
#   - 384k PSBT incoming (MAX_TXN_LEN)
#   - 384k PSBT outgoing (MAX_TXN_LEN)
#   - 128k nvram settings (32 slots of 4k each)
#
# During firmware updates, entire flash, starting at zero may be used.
#
import machine
from version import mk_num

CMD_WRSR        = const(0x01)
CMD_WRITE       = const(0x02)
CMD_READ        = const(0x03)
CMD_FAST_READ   = const(0x0b)
CMD_RDSR        = const(0x05)
CMD_WREN        = const(0x06)
CMD_RDCR        = const(0x35)
CMD_RD_DEVID    = const(0x9f)
CMD_SEC_ERASE   = const(0x20)       # 4k unit, 40-200ms
CMD_BLK_ERASE   = const(0xd8)       # 64k, 0.4 - 2s
CMD_CHIP_ERASE  = const(0xc7)       # 1MB, 3.5 - 6s
CMD_C4READ      = const(0xeb)

class SPIFlash:
    # must write with this page size granulatity
    PAGE_SIZE = 256
    # must erase with one of these size granulatity!
    SECTOR_SIZE = 4096
    BLOCK_SIZE = 65536

    def __init__(self):
        from machine import Pin

        # chip can do 80Mhz, but very limited prescaler-only baudrate generation, so
        # sysclk/2 or /4 will happen depending on Mk3 vs. 4
        # - Mk4: 120Mhz => 60Mhz result (div 2)
        # - Mk3: 80Mhz => 40Mhz result (div 2)
        self.spi = machine.SPI(2, baudrate=80_000_000)
        self.cs = Pin('SF_CS', Pin.OUT)

    def cmd(self, cmd, addr=None, complete=True, pad=False):
        if addr is not None:
            buf = bytes([cmd, (addr>>16) & 0xff, (addr >> 8) & 0xff, addr & 0xff])
        else:
            buf = bytes([cmd])

        if pad:
            buf = buf + b'\0'

        self.cs.low()
        self.spi.write(buf)
        if complete:
            self.cs.high()

    def read(self, address, buf, cmd=CMD_FAST_READ):
        # random read (fast mode, because why wouldn't we?!)
        self.cmd(cmd, address, complete=False, pad=True)
        self.spi.readinto(buf)
        self.cs.high()

    def write(self, address, buf):
        # 'page program', must already be erased
        assert 1 <= len(buf) <= 256     #  "max 256"
        assert address & ~0xff == (address+len(buf)-1) & ~0xff      #  "page boundary"

        self.cmd(CMD_WREN)
        self.cmd(CMD_WRITE, address, complete=False)
        self.spi.write(buf)
        self.cs.high()

    def read_reg(self, cmd, length=3):
        # read register
        rv = bytearray(length)
        self.cmd(cmd, 0, complete=False)
        self.spi.readinto(rv)
        self.cs.high()

        return rv

    def is_busy(self):
        # return status of WIP = Write In Progress bit
        r = self.read_reg(CMD_RDSR, 1)
        return bool(r[0] & 0x01)

    def wait_done(self):
        # wait until write done; could be fancier
        while 1:
            if not self.is_busy():
                return

    def chip_erase(self):
        # can take up to 6 seconds, so poll is_busy()
        self.cmd(CMD_WREN)
        self.cmd(CMD_CHIP_ERASE)

    def sector_erase(self, address):
        # erase 4k. 40-200ms delay; poll is_busy()
        assert address % 4096 == 0      # "not sector start"

        self.cmd(CMD_WREN)
        self.cmd(CMD_SEC_ERASE, address)

    def block_erase(self, address):
        # erase 64k at once
        assert address % 65536 == 0     # "not block start"
        self.cmd(CMD_WREN)
        self.cmd(CMD_BLK_ERASE, address)

    def wipe_most(self):
        # erase everything except settings: takes 5 seconds at least
        from glob import dis
        dis.fullscreen("Cleanup...")

        assert mk_num <= 3      # obsolete in mk4

        from nvstore import SLOTS
        end = SLOTS[0]

        for addr in range(0, end, self.BLOCK_SIZE):
            self.block_erase(addr)
            dis.progress_bar_show(addr/end)

            while self.is_busy():
                pass

# singleton
SF = SPIFlash()

# EOF
