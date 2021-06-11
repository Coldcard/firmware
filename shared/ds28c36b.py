# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ds28c36b.py -- Talk to DS28C36B Secure Element (SE2) on Mk4
#
'''
About this chip.

- 32 pages, 16 general purpose, others are keys: all 32 bytes wide
- up to 3 keys
- SHA-256 (HMAC) auth or ECC (P256) auth via ECDH
- RNG, one useless dec counter
- pages individually lockable (nice)
- slow: 1ms to read page, 15ms to write, 50-150 for ECC ops, 3ms for HMAC

Challenges:
- reading auth'd data via SHA method is insecure against replay by emulated device
- HMAC+SHA auth methods do not allow us to inject nonce/random values, but rely on
  device serial number and 8 bytes picked by the device (or the attacker/mitm)
- concerned it can sign/HMAC user-provided value in a way that might be used to
  fake other responses, but I'm probably missing something

Plan:
- in factory, random privkey/pubkey generated on-device, locked.
- bootrom stores pubkey
- use ECDH to generate S value when we need to get auth data in/out
'''
from utime import sleep_ms
from utils import B2A
import ngu

# i2c address (7-bits)
SE2_ADDR = const(0x1b)

# page numbers (Table 1)
PGN_PUBKEY_A = const(16)        # also +1
PGN_PUBKEY_B = const(18)        # also +1
PGN_PUBKEY_C = const(20)        # also +1
PGN_PRIVKEY_A = const(22)
PGN_PRIVKEY_B = const(23)
PGN_PRIVKEY_C = const(24)
PGN_SECRET_A = const(25)
PGN_SECRET_B = const(26)
PGN_DEC_COUNTER = const(27)
PGN_ROM_OPTIONS = const(28)
PGN_GPIO = const(29)
PGN_PUBKEY_S = const(30)        # also 31, volatile

# page protection bitmask (Table 11)
PROT_RP = const(0x01)
PROT_WP = const(0x02)
PROT_EM = const(0x04)
PROT_APH = const(0x08)
PROT_EPH = const(0x10)
PROT_AUTH = const(0x20)
PROT_ECH = const(0x40)
PROT_ECW = const(0x80)

class SE2Handler:
    def __init__(self):
        from machine import I2C
        self.i2c = I2C(2, freq=500000)

        try:
            self.read_ident()
            self.verify_page(1, 0, bytes(32), b'a'*32)
        except: pass

    def _write(self, cmd, data=None):
        # chip will not ack bytes that are past end of command+args, etc.
        # data can be one int (a byte, will be prefixed w/1) or a sequence of bytes/ints
        if data is not None:
            if isinstance(data, int):
                b = bytes([cmd, 1, data])
            else:
                b = bytearray([cmd, len(data)])
                b.extend(data)
        else:
            b = bytes([cmd])

        txl = self.i2c.writeto(SE2_ADDR, b)
        assert txl == len(b), 'chip nak'

        # all commands need at least tRM recovery time
        sleep_ms(2)     # tRM*2

    def _read(self, num):
        # responses usually have length in first byte, then status byte, then data
        # - chip provides 0xff when reading past end of response (does not nak)
        rx = self.i2c.readfrom(SE2_ADDR, num)
        assert len(rx) == num, 'short read'
        return rx

    def _read1(self):
        # when expecting a single-byte status byte back
        rx = self._read(2)
        assert rx[0] == 1
        return rx[1]

    def _check_result(self, rv):
        if rv == 0xAA: return
        raise RuntimeError("bad response: 0x%x" % rv)

    def write_buffer(self, data):
        # write up to 80 bytes into a RAM buffer on device
        # - remainder of buffer is set to 0xff, valid length is remembered
        assert 1 <= len(data) <= 80
        self._write(0x87, data)

    def read_buffer(self):
        # length implied from previous write buffer (1..80)
        self._write(0x5a)
        rx = self._read(81)
        assert 0 < rx[0] <= 80
        assert len(rx) >= rx[0]+1
        return rx[1:1+rx[0]]

    def read_rng(self, num):
        # Read RNG, and allow any MiTM to modulate as needed.
        # - do not use for any purpose
        assert 1 <= num <= 63
        self._write(0xd2, num)
        sleep_ms(3)         # tCMP
        rx = self._read(1+num)
        return rx[1:]

    def load_thash(self, buf):
        # Perform SHA256 and store result into THASH register of chip
        assert 1<= len(buf) <= 64         # zero not supported by chip, this code only 64
        tmp = bytes([0xc0]) + bytes(buf)

        self._write(0x33, tmp)
        sleep_ms(3)         # tCMP
        self._check_result(self._read1())

    def page_protection(self, page):
        # return active page protection for page
        assert 0 <= page < 32
        self._write(0xaa, page)
        return self._read1()

    def set_page_protection(self, page, bitmap):
        # set the protection for one page
        assert 0 <= page < 32
        self._write(0xc3, bytes([page, bitmap]))
        sleep_ms(3)         # tCMP?
        self._check_result(self._read1())

    def read_page(self, page):
        # unauth version, mitm vulerable, no encryption
        assert 0 <= page < 32
        self._write(0x69, page)
        if page in {28, 29}:
            sleep_ms(3)     # +tCMP
        rx = self._read(34)
        if rx[1] == 0x55:
            raise RuntimeError('read protected')
        self._check_result(rx[1])

        return rx[2:]

    def write_page(self, page, value):
        # unauth version, mitm vulerable
        assert 0 <= page < 32
        assert len(value) == 32
        self._write(0x96, bytes([page])+bytes(value))
        sleep_ms(16)
        if self._read1() != 0xAA:
            raise RuntimeError('write fail')

    def read_enc_page(self, page_num, secret_num, secret):
        # Use secret key, and read encrypted contents of page (XOR w/ HMAC output)
        # - key for HMAC is pre-shared secret, either key A, B or secret S established by ECDH
        # - EPH for keys A/B, ECH forces key S
        # - IMPORTANT: not secure against simple replay, so always verify
        assert 0 <= page_num <= 32
        assert 0 <= secret_num <= 2
        self._write(0x4b, (secret_num << 6) | page_num)
        sleep_ms(3)     # tCMP

        rx = self._read(42)
        self._check_result(rx[1])

        # do decryption
        chal = rx[2:2+8]
        enc = rx[2+8:]
        assert len(enc) == 32

        msg = chal + self.rom_id + bytes([page_num]) + self.manid
        assert len(msg) == 19

        chk = ngu.hmac.hmac_sha256(secret, msg)
        readback =  bytes(a^b for a,b in zip(chk, enc))

        # Must always verify the response because it can be replayed w/o
        # knowing any secrets
        # - also catches wrong decryption if key/secret wrong
        ok = self.verify_page(page_num, secret_num, readback, secret)
        if not ok:
            raise RuntimeError("wrong key/MitM")

        return readback

    def write_enc_page(self, page_num, secret_num, secret, data):
        # Authenticated write to a page.
        assert 0 <= page_num <= 32
        assert 0 <= secret_num <= 2
        assert len(data) == 32

        args = bytearray([(secret_num << 6) | page_num])
        args.extend(data)

        self._write(0x99, args)
        sleep_ms(15 + (2*3))     # tWM + (2*tCMP)

        result = self._read1()
        self._check_result(result)

    def read_ident(self):
        # identity details needed for auth setup
        b = self.read_page(28)
        self.rom_id = b[24:24+8]
        self.manid = b[22:22+2]
        assert self.rom_id[0] == 0x4c       # for this device family

    def pick_keypair(self, kn):
        # use device RNG to pick a keypair
        assert 0 <= kn <= 2         # A,B, or C
        
    def verify_page(self, page_num, secret_num, expected, secret, hmac=True):
        # See if chip is holding expected value in a page.
        # - if this fails, you have the secret wrong, or the data is wrong
        assert 0 <= secret_num <= 2         # Secret A,B, or S (or PrivkeyA/B/C)
        assert 0 <= page_num < 32
        assert len(expected) == 32
        assert len(secret) == 32

        chal = ngu.random.bytes(32)
        self.write_buffer(chal)

        arg = (secret_num << 5) | page_num
        if not hmac:
            arg |= 0x80

        self._write(0xa5, arg)
        sleep_ms(200)
        if hmac:
            rx = self._read(2+32)
        else:
            rx = self._read(2+64)

        if rx[1] != 0xaa:
            raise RuntimeError(hex(rx[1]))

        msg = self.rom_id + expected + chal + bytes([page_num]) + self.manid
        assert len(msg) == 75

        if hmac:
            # response will be HMAC-SHA256 output
            chk = ngu.hmac.hmac_sha256(secret, msg)
            return rx[2:] == chk
        else:
            # response will be signature over SHA256(msg)
            # - would need p256r1 code to verify here
            return rx[2:], chal, msg

    def first_time(self):
        # reset and lock the ANON flag == 0, so request/responses require serial number
        prot = self.page_protection(PGN_ROM_OPTIONS)
        b = bytearray(self.read_page(PGN_ROM_OPTIONS))
        if prot == PROT_WP:
            # after first run, should be protected and in right state.
            assert b[1] == 0x0
        else:
            b[1] = 0x00     # same as default
            self.write_page(PGN_ROM_OPTIONS, b)

        self.read_ident()
        assert self.manid[1] & 0xc0 == 0x80, 'not B rev?'
        assert self.rom_id != b'\xff\xff\xff\xff\xff\xff\xff\xff'

        if prot != PROT_WP:
            # set write lock
            self.set_page_protection(PGN_ROM_OPTIONS, PROT_WP)

        # pick a keypair for communications (key C, no choice)
        #self.pick_keypair(kn=2) 

        self.write_page(PGN_SECRET_A, b'a'*32)
        self.write_page(PGN_SECRET_B, b'b'*32)

        

# EOF
