# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# gpu.py - GPU co-processor access and support.
#
# - see notes in misc/gpu/README.md
# - bl = Bootloader, provided by ST Micro in ROM of chip
# - useful: import gpu; g=gpu.GPUAccess(); g.enter_bl()
#
import utime, struct
import uasyncio as asyncio
from utils import B2A
from machine import Pin

# boot loader ROM response to this I2C address
BL_ADDR = const(0x64)

BL_ACK = b'y'       # 0x79
BL_NACK = b'\x1f'
BL_BUSY = b'v'      # 0x76

def add_xor_check(lst):
    # byte-wise xor over list of bytes (used as a very weak checksum in BL)
    rv = 0x0
    for b in lst:
        rv ^= b
    return bytes(lst + bytes([rv]))

class GPUAccess:
    def __init__(self):
        # much sharing/overlap in these pins!
        self.g_reset = Pin('G_RESET', mode=Pin.OPEN_DRAIN, pull=Pin.PULL_UP)
        #self.g_boot0 = Pin('G_SWCLK_B0', mode=Pin.OPEN_DRAIN, pull=Pin.PULL_NONE)
        self.g_boot0 = Pin('G_SWCLK_B0', mode=Pin.IN)
        self.g_ctrl = Pin('G_CTRL', mode=Pin.IN)

        from machine import I2C
        self.i2c = I2C(1, freq=400000)      # same bus & speed as nfc.py

    def bl_cmd_read(self, cmd, expect_len, addr=None, arg2=None, no_final=False):
        # send a one-byte command to bootloader ROM and get response
        # - need len to expect, because limitations of hard i2c on this setup
        i2c = self.i2c

        self._send_cmd(cmd)

        if addr is not None:
            if isinstance(addr, int):
                # write 4 bytes of address
                qq = add_xor_check(struct.pack('>I', addr))
            else:
                qq = bytes(addr)

            print('wr ' + B2A(qq))
            i2c.writeto(BL_ADDR, qq)

            resp = i2c.readfrom(BL_ADDR, 1)
            if resp != BL_ACK:
                raise ValueError('bad addr ' + B2A(resp))

        if arg2 is not None:
            # XXX tbd
            # write 1 bytes of address
            i2c.writeto(BL_ADDR, bytes([arg2, 0xff ^ arg2]))
            resp = i2c.readfrom(BL_ADDR, 1)
            if resp != BL_ACK:
                raise ValueError('bad arg2')

        # for some commands, first byte of response is length and it can vary
        # - however, they are inconsistent on how they count that and not
        #   all commands use it, etc.
        # - tried and failed to check/handle the length here; now caller's problem
        rv = i2c.readfrom(BL_ADDR, expect_len) 

        if not no_final:
            # final ack/nack
            resp = i2c.readfrom(BL_ADDR, 1)
            if resp != BL_ACK:
                raise ValueError(resp)

        return rv

    def _wait_done(self):
        for retry in range(100):
            try:
                resp = self.i2c.readfrom(BL_ADDR, 1)
            except OSError:     # ENODEV
                print('recover')
                utime.sleep_ms(50)
                continue

            if resp != BL_BUSY:
                break

            print('busy')
            utime.sleep_ms(50)

        return resp

    def _send_cmd(self, cmd):
        # do just the cmd + ack part
        self.i2c.writeto(BL_ADDR, bytes([cmd, 0xff ^ cmd]))
        resp = self.i2c.readfrom(BL_ADDR, 1)
        if resp != BL_ACK:
            raise ValueError('unknown command')

    def bl_doit(self, cmd, arg):
        # send a one-byte command and and argument, wait until done
        self._send_cmd(cmd)

        i2c.writeto(BL_ADDR, add_xor_check(arg))

        return self._wait_done()

    def bl_double_ack(self, cmd):
        # some commands need two acks because they do stuff during that time?
        self._send_cmd(cmd)
        resp = self._wait_done()
        if resp == BL_ACK:
            return self._wait_done()
        return resp

    def reset(self):
        # pulse reset and let it run
        self.g_reset(0)
        self.g_reset(1)

    def enter_bl(self):
        # get it into bootloader
        self.g_reset(0)
        self.g_boot0.init(mode=Pin.OPEN_DRAIN, pull=Pin.PULL_UP)
        self.g_reset(1)
        self.g_boot0.init(mode=Pin.IN)

    def get_version(self):
        # assume already in bootloader
        return self.bl_cmd_read(0x0, 20)

    def bulk_erase(self):
        # "No-Stretch Erase Memory" with 0xFFFF arg = "global mass erase"
        return self.bl_doit(0x45, b'\xff\xff') == BL_ACK

    def readout_unprotect(self):
        # "No-Stretch Readout Unprotect" -- may wipe chip in process?
        return self.bl_double_ack(0x93)

    def readout_protect(self):
        # "No-Stretch Readout Protect" 
        return self.bl_double_ack(0x83)

    def read_at(self, addr=0x0800_0000, ln=16):
        # read memory, but address must be "correct" and mapped, which is undocumented
        # - need not be aligned, up to 255
        # - 0x1fff0cd0 also fun
        # - some weird trailing byte, it's not an ACK/NACK/xor but needs reading
        assert ln < 256
        return self.bl_cmd_read(0x11, ln+1, addr=addr, arg2=ln, no_final=True)[0:ln]


# EOF
