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
import ngu, ckcc

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

# random example
T_pubkey = b'\xf0\xa5\xba6A\xe1\xd5/\n\xed\xbc8b\xfe\xca\xfe7\xe0\xdd\xbd\xad\x1f\xfb%\xb2cL\xd9>\x13\xfd5 &8\xe0l$/\x14\x94dLT,\x92X.;\x95\xe4\x13\xc3\x03\xc7\n\xc6\x15\xa6\xd2\xfd\x8a\xbe\xba'
T_privkey = b'\x8ev\xa4\xce\xb5B\xe2\x90\x06\x925\xa9\xc3\x90\xe61s^\xa9\x10q\x17\x82\\r$\xc0\xbe\xb7\xfc\xa5>'


class SE2Handler:
    def __init__(self):
        from machine import I2C
        self.i2c = I2C(2, freq=500000)

        try:
            self.read_ident()
            #self.verify_page(1, 0, bytes(32), b'a'*32)
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
        # - poll until it starts responding again, might take >200ms
        for retry in range(200):
            try:
                rx = self.i2c.readfrom(SE2_ADDR, num)
                assert len(rx) == num, 'short read'

                return rx
            except OSError:
                # expect OSError: [Errno 19] ENODEV
                pass
            sleep_ms(2)
        raise RuntimeError('se2 timeout')

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
        rx = self._read(1+num)
        return rx[1:]

    def load_thash(self, buf):
        # Perform SHA256 and store result into THASH register of chip
        assert 1<= len(buf) <= 64         # zero not supported by chip, this code only 64
        tmp = bytes([0xc0]) + bytes(buf)

        self._write(0x33, tmp)
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
        self._check_result(self._read1())

    def read_page(self, page):
        # unauth version, mitm vulnerable, no encryption
        assert 0 <= page < 32
        self._write(0x69, page)
        rx = self._read(34)
        if rx[1] == 0x55:
            raise RuntimeError('read protected')
        self._check_result(rx[1])

        return rx[2:]

    def write_page(self, page, value):
        # unauth version, mitm vulnerable
        assert 0 <= page < 32
        assert len(value) == 32
        self._write(0x96, bytes([page])+bytes(value))
        self._check_result(self._read1())

    def read_enc_page(self, page_num, secret_num, secret=None):
        # Use secret key, and read encrypted contents of page (XOR w/ HMAC output)
        # - key for HMAC is pre-shared secret, either key A, B or secret S established by ECDH
        # - EPH for keys A/B, ECH forces key S
        # - IMPORTANT: not secure against simple replay, so we always verify
        assert 0 <= page_num <= 32
        if secret_num == 2:
            secret = self.shared_secret
        else:
            assert 0 <= secret_num <= 1
        self._write(0x4b, (secret_num << 6) | page_num)

        rx = self._read(42)
        self._check_result(rx[1])

        # do decryption
        chal = rx[2:2+8]
        enc = rx[2+8:]
        assert len(enc) == 32

        msg = chal + self.rom_id + bytes([page_num]) + self.manid
        assert len(msg) == 19

        chk = ngu.hmac.hmac_sha256(secret, msg)
        readback = bytes(a^b for a,b in zip(chk, enc))

        # Must always verify the response because it can be replayed w/o
        # knowing any secrets
        # - also catches wrong decryption if key/secret wrong
        ok = self.verify_page(page_num, secret_num, readback, secret)
        if not ok:
            raise RuntimeError("wrong key/MitM")

        return readback

    def write_enc_page(self, page_num, secret_num, secret, old_data, new_data):
        # Authenticated write to a page.
        # - only for pages with APH or EPH
        # - assume EPH here, with encrypted data tx
        assert 0 <= page_num <= 32
        assert 0 <= secret_num <= 2
        assert len(new_data) == len(old_data) == 32

        PGDV = bytes([page_num | 0x80])

        # This is used for encryption: hmac w/ nonce we pick
        chal = ngu.random.bytes(8)
        msg = chal + self.rom_id + PGDV + self.manid
        assert len(msg) == 19
        otp = ngu.hmac.hmac_sha256(secret, msg)

        # Must know old data to authenticate change.
        msg2 = self.rom_id + old_data + new_data + PGDV + self.manid
        assert len(msg2) == 75
        auth_chk = ngu.hmac.hmac_sha256(secret, msg2)

        # write that + our nonce into buffer
        self.write_buffer(auth_chk + chal)

        # encrypt new data
        args = bytearray(33)
        args[0] = (secret_num << 6) | page_num
        for i in range(32):
            args[i+1] = otp[i] ^ new_data[i]

        self._write(0x99, args)
        self._check_result(self._read1())

    def read_ident(self):
        # identity details needed for auth setup
        b = self.read_page(28)
        self.rom_id = b[24:24+8]
        self.manid = b[22:22+2]
        assert self.rom_id[0] == 0x4c       # for this device family

    def pick_keypair(self, kn, lock=False):
        # use device RNG to pick a EC keypair
        assert 0 <= kn <= 2         # A,B, or C
        wpe = 0x1 if lock else 0x0
        self._write(0xcb, (wpe<<6) | kn)
        self._check_result(self._read1())
        
    def verify_page(self, page_num, secret_num, expected, secret=None, hmac=True):
        # See if chip is holding expected value in a page.
        # - if this fails, you have the secret wrong, or the data is wrong
        assert 0 <= secret_num <= 2         # Secret A,B, or S (or PrivkeyA/B/C)
        assert 0 <= page_num < 32
        assert len(expected) == 32
        assert not secret or len(secret) == 32

        chal = ngu.random.bytes(32)
        self.write_buffer(chal)

        if hmac:
            arg = (secret_num << 5) | page_num
        else:
            assert 0 <= secret_num <= 1         # privkey A,B only
            arg = ((0x3 + secret_num) << 5) | page_num

        self._write(0xa5, arg)
        if hmac:
            rx = self._read(2+32)
        else:
            rx = self._read(2+64)

        self._check_result(rx[1])

        msg = self.rom_id + expected + chal + bytes([page_num]) + self.manid
        assert len(msg) == 75

        if hmac:
            # response will be HMAC-SHA256 output
            chk = ngu.hmac.hmac_sha256(secret, msg)
            return rx[2:] == chk
        else:
            # response will be signature over SHA256(msg)
            # - need p256r1 code to be able to verify here
            md = ngu.hash.sha256s(msg)

            pn = PGN_PUBKEY_A + (2*secret_num)
            pubkey = self.read_page(pn) + self.read_page(pn+1)
            # R and S are swapped in the new signature
            sig = rx[2+32:2+32+32] + rx[2:2+32]

            args = bytearray(pubkey + md + sig)
            rv = ckcc.gate(130, args, 0)

            return rv == 0

    def setup_auth(self, ecdh_kn=0):
        # do "Authenticate ECDSA Public Key" proving we know the privkey for
        # pubkey held in slot C. Set volatile state: AUTH and maybe W_PUB_KEY and S
        # - must enable ECDH because we want to read using this authority
        # - lengths/offsets are all messed in spec
        # - only supporting READ; we will do our writes before locking page(s)

        # this is remembered in SRAM, but needed in general
        self.write_page(PGN_PUBKEY_S+0, T_pubkey[:32])
        self.write_page(PGN_PUBKEY_S+1, T_pubkey[32:])

        chal = ngu.random.bytes(32+32)
        self.write_buffer(chal)

        cs_offset = 32      # very confusing, might be implied by buffer length?

        md = ngu.hash.sha256s(T_pubkey + chal[0:32])

        # sign md with our privkey
        args = bytearray(T_privkey + md + bytes(64))
        rv = ckcc.gate(132, args, 0)
        assert rv == 0

        sig = bytes(args[-64:])

        args = bytearray()
        args.append( ((cs_offset-1) << 3) | (ecdh_kn << 2) | 0x2 )
        args.extend(sig)

        self._write(0xa8, args)
        self._check_result(self._read1())

        print('auth ok')

        # ecdh multi
        pubkey_pn = PGN_PUBKEY_A + (ecdh_kn*2)
        their_pubkey = self.read_page(pubkey_pn) + self.read_page(pubkey_pn+1)

        args = bytearray(their_pubkey + T_privkey + bytes(32))
        rv = ckcc.gate(133, args, 0)
        assert rv == 0
        x = args[-32:]

        # shared secret S will be SHA over X of shared ECDH point + chal[32:]
        s = ngu.hash.sha256s(x + chal[32:])

        self.shared_secret = s

        return True

    def load_s(self, s):
        # take string dumped by ROM
        self.shared_secret = bytes(int(s[i:i+2], 16) for i in range(0, 64, 2))

    def clear_state(self):
        # No command to reset the volatile state on this chip! Could
        # be sensitive at times. 608 has a watchdog for this!!
        self.write_page(PGN_PUBKEY_S+0, bytes(32))
        self.write_page(PGN_PUBKEY_S+1, bytes(32))

        chal = ngu.random.bytes(32)
        self.write_buffer(chal)

        # rotate the secret S ... not ideal but only way I've got to change it
        # - also clears ECDH_SECRET_S flag
        self._write(0x3c, bytes([ (2<<6), 0 ]))
        self._read1()

    


    def selftest_sig(self):
        # SELFTEST
        # make sig, check on device
        md = b'm'*32
        args = bytearray(T_privkey + md + bytes(64))
        rv = ckcc.gate(132, args, 0)
        assert rv == 0

        sig = bytes(args[-64:])

        # check we like our own work
        args = bytearray(T_pubkey + md + sig)
        rv = ckcc.gate(130, args, 0)
        assert rv == 0

        # try against the chip
        self.write_page(PGN_PUBKEY_S+0, T_pubkey[:32])
        self.write_page(PGN_PUBKEY_S+1, T_pubkey[32:])

        self.write_buffer(md)

        b = bytearray([0x03])
        b.extend(sig)
        self._write(0x59, b)
        self._check_result(self._read1())

    def first_time(self):
        # reset and lock the ANON flag == 0, so request/responses require serial number
        prot = self.page_protection(PGN_ROM_OPTIONS)
        b = bytearray(self.read_page(PGN_ROM_OPTIONS))
        if prot != 0:
            # after first run, should be protected and in right state.
            assert b[1] == 0x0
        else:
            b[1] = 0x00     # same as default
            self.write_page(PGN_ROM_OPTIONS, b)

        self.read_ident()
        assert self.manid[1] & 0xc0 == 0x80, 'not B rev?'
        assert self.rom_id != b'\xff\xff\xff\xff\xff\xff\xff\xff'

        if prot != PROT_APH:
            # set write lock, except WP isn't possible on this page?! So use APH
            self.set_page_protection(PGN_ROM_OPTIONS, PROT_APH)

        # pick a keypair for communications (key C, no choice)
        #self.pick_keypair(kn=2) 

        self.write_page(PGN_SECRET_A, b'a'*32)
        self.write_page(PGN_SECRET_B, b'b'*32)

        if self.page_protection(PGN_PUBKEY_C) == 0:
            # write a pubkey for AUTH purposes
            self.write_page(PGN_PUBKEY_C, T_pubkey[:32])
            self.write_page(PGN_PUBKEY_C+1, T_pubkey[32:])
            self.set_page_protection(PGN_PUBKEY_C, PROT_AUTH|PROT_RP|PROT_WP)

        # known values in all pages
        for i in range(0, 16):
            try:
                SE2.write_page(i, (b'%x'%i)*32)
            except: pass




        

# EOF
