#
# Secure Element
#
# Talk to the ATECC[56]08A, which drives the Genuine/Caution LED's and holds secrets.
#
# - connected to "onewire" on PA0
# - not a standard "onewire" interface at all
# - full datasheet is under NDA (unfortunately, bad policy)
# - but very simmilar to ATSHA204 and family chips
# - bootloader can also read/write to this chip
# - XXX presently broken.
#
from machine import Pin, UART
from time import sleep_us, sleep_ms
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from uhashlib import sha256
from ucollections import namedtuple
from ckcc import rng_bytes
import ustruct


# bit patterns for zero and one, respectively
BIT0 = const(0x7d)
BIT1 = const(0x7f)

# these control the direction of the single wire
IOFLAG_CMD   = const(0x77)
IOFLAG_TX    = const(0x88)
IOFLAG_IDLE  = const(0xBB)
IOFLAG_SLEEP = const(0xCC)

class CRCError(RuntimeError):
    pass
class WrongResponseLength(RuntimeError):
    pass
class ChipErrorResponse(RuntimeError):
    pass
class WrongMacVerify(RuntimeError):
    pass

# Operations of the chip. Names per datasheet
class OP:
    CheckMac = 0x28
    Counter = 0x24
    DeriveKey = 0x1C
    ECDH = 0x43
    GenDig = 0x15
    GenKey = 0x40
    HMAC = 0x11         # 508a only
    Info = 0x30
    Lock = 0x17
    MAC = 0x08
    Nonce = 0x16
    Pause = 0x01        # 508a only
    PrivWrite = 0x46
    Random = 0x1B
    Read = 0x02
    Sign = 0x41
    SHA = 0x47
    UpdateExtra = 0x20
    Verify = 0x45
    Write = 0x12
    OP_AES = 0x51           # 608a only
    OP_KDF = 0x56           # 608a only
    OP_SecureBoot = 0x80    # 608a only
    OP_SelftTest = 0x77     # 608a only

# most errors are really communications failures
ERROR_CODES = {
    0x01: 'Checkmac or Verify Miscompare',
    0x03: 'Parse Error',
    0x05: 'ECC Fault',
    0x0f: 'Execution Error',
    0x11: 'Got wake token',
    0xee: 'Watchdog About to Expire',
    0xff: 'CRC/comm error',
}

def random_bytes(count):
    assert 8 <= count < 1024
    rv = bytearray(count)
    rng_bytes(rv)
    return rv

def slot_layout(slot_num):
    # Return number of 32-byte block, and number of bytes for each slot
    # each slot is different size, just because!
    if 0 <= slot_num <= 7:
        return (2, 36)
    elif slot_num == 8:
        return (13, 416)
    elif 9 <= slot_num <= 15:
        return (3, 72)

    raise ValueError(slot_num)

    
def crc16w(data, starting_value = 0):
    # CRC algo used by chip for error detect in communications
    data = bytearray(data)
    crc_reg = starting_value
    polynom = 0x8005

    for counter in range(len(data)):
        mask = 0x01
        while mask != 0x100:
            data_bit = 1 if (data[counter] & mask) else 0
            crc_bit = (crc_reg >> 15) & 0x1

            crc_reg <<= 1

            if data_bit != crc_bit:
                crc_reg ^= polynom

            mask <<= 1

    crc0 = (crc_reg & 0x00FF)
    crc1 = (crc_reg >> 8) & 0xff

    # return a byte string, since that's what I need.
    return bytearray((crc0, crc1))

def test_crc16w():
    # test vectors
    assert crc16w(a2b_hex('0411')) == a2b_hex('3343')
    assert crc16w(a2b_hex('ff')) == a2b_hex('0202')
    assert crc16w(a2b_hex('aa')) == a2b_hex('fe01')
    assert crc16w(a2b_hex('ffaa')) == a2b_hex('f183')
    assert crc16w(a2b_hex('07ccbebab2')) == a2b_hex('8598')
    assert crc16w(a2b_hex('ffaa5500')) == a2b_hex('26f4')

def read_params(block=0, offset=0, slot=0, is_config=True, is_otp=False, is_data=False, sz=0x80):
    assert 0 <= offset <= 0x1f, offset
    assert 0 <= block <= 12, block
    assert is_config or is_otp or is_data, "need zone"

    # encoding table 9-9 on page 55
    # always going to read as much as we can in one cycle

    if is_data:
        assert 0 <= slot < 16
        if 0 <= slot <= 7:
            assert block in (0,1), block
        elif slot == 8:
            assert 0 <= block < 13
        elif 9 <= slot < 16:
            assert 0 <= block < 3

        zone = 2
        p2 = (block << 8) | (slot << 3) | offset
    else:
        assert slot==0

        if is_config:
            zone = 0
        elif is_otp:
            zone = 1

        if offset & 0x7 != 0x0:
            sz = 0

        p2 = (block << 3) | offset

    if sz:
        assert (offset & 0x7) == 0, offset

    p1 = (zone | sz)
    resp_len = (32 if sz else 4)

    # note: these are ready for use as kwargs elsewhere
    return dict(p1=p1, p2=p2, resp_len=resp_len, delay=2)

def repr_params(args):
    return 'op=0x%x, p1=0x%x, p2=0x%x, body=%s' % (
                    args.get('opcode', 0xEF), args['p1'], args['p2'],
                    ASC(b2a_hex(args['body'])) if 'body' in args else 'None')

def write_params(**args):
    if 'sz' not in args:
        args['sz'] = 0
    rv = read_params(**args)
    rv['opcode'] = OP.Write
    rv['resp_len'] = 1
    rv['delay'] = 26        # worst case

    return rv

InfoStat = namedtuple('InfoStat', (
				'TK_KeyId',
				'TK_SourceFlag',
				'TK_GenDigData',
				'TK_GenKeyData',
				'TK_NoMacFlag',
				'EEPROM_RNG',
				'SRAM_RNG',
				'AuthValid',
                'AuthKey',
                'TK_Valid'))

def InfoStat_unpack(ss):
    v = ustruct.unpack("<H", ss)[0]
    pos,rv = 0, []
    for w in [4, 1,1,1,1, 1,1,1, 4, 1]:
        rv.append( (v >> pos) & ((1<<w)-1) )
        pos += w
    assert pos == 16
    return InfoStat(*rv)

class SecureElement:

    def __init__(self):
        # these required changes to ss/uart.c
        self.ow = UART(4, baudrate=230400, bits=7, parity=None, stop=1,
                                timeout=1, read_buf_len=(180*8))

        # correct pin settings, because we have external pullup
        self.pa0 = Pin('A0', mode=Pin.ALT_OPEN_DRAIN, pull=Pin.PULL_NONE, af=Pin.AF8_UART4)

        # LSB first, 0x88 = Transmit
        self.x88 = self.serialize(bytes([IOFLAG_TX]))

        # selftest
        test = b'\xa5'
        chk = self.serialize(test)
        chk2 = self.deserialize(chk)
        assert chk2 == test, (chk2, test)

        test_crc16w()

        self.d_slot = [None]*16
        self.data = None

        try:
            self.read()
        except:
            print("AE failed")
            self.data = None

    def reinit(self):
        # When bootloader accesses the UART, it clears interrupt enable bits
        # so reading doesn't work. Reinit UART to fix.
        self.ow.init(baudrate=230400, bits=7, parity=None, stop=1,
                                timeout=1, read_buf_len=(80*8))

    def deserialize(self, bb, offset=0):
        # deserialize bits received as bytes. maybe skip over N leading bytes
        rv = bytearray((len(bb) // 8) - offset)

        pos,o = (8*offset),0
        while 1:
            mask = 0x01
            for c in bb[pos:pos+8]:
                if c == BIT1:
                    rv[o] |= mask
                mask <<= 1
            pos += 8
            o += 1
            if pos >= len(bb):
                break

        return rv

    def serialize(self, msg):
        # turn bits into 8x longer bits
        rv = bytearray(len(msg) * 8)

        for pos, c in enumerate(msg):
            mask = 0x01
            for i in range(8):
                rv[(pos*8)+i] = BIT1 if (c & mask) else BIT0
                mask <<= 1

        return rv

    def go_idle(self):
        # XXX ?? idle then wakeup more useful, but no wakeups needed
        # This is useful to reset watchdog timer.
        ow = self.ow
        ow.write(b'\x00')   # WAKEUP token
        ow.read()           # thow out old garbage
        sleep_us(2500)      # tWHI: 2.5ms min
        ow.write(self.serialize(bytes([IOFLAG_IDLE])))
        #sleep_us(40)      # tTURNAROUND (80)

    def reset_watchdog(self):
        ow.write(self.serialize(bytes([IOFLAG_IDLE])))

    def reset_chip(self):
        self.go_sleep()

    def go_sleep(self):
        # This is useful to clear voltile state explicitly
        ow = self.ow
        ow.write(b'\x00')   # WAKEUP token
        ow.read()           # thow out old garbage
        sleep_us(2500)      # tWHI: 2.5ms min
        ow.write(self.serialize(bytes([IOFLAG_SLEEP])))
        #sleep_us(40)      # tTURNAROUND (80)

    def assume_data_blank(self):
        "data area is probably blank"
        self.d_slot = [(b'\xff' * slot_layout(sl)[1]) for sl in range(16)]

    def try_read_data(self, skip=[]):
        "try to read all slots; some will fail w/ private data"
        # XXX doesn't recover well from failed reads; avoid them
        for sl in range(16):
            if sl in skip:
                self.d_slot[sl] = None
                continue
            try:
                self.read_data_slot(sl)
            except RuntimeError:
                self.d_slot[sl] = None

    def send_recv(self, opcode=None, p1=0, p2=0, body=b'', resp_len=1, delay=None):
        #
        # Send a command block and read response. Sometimes a delay is needed.
        #
        # use a special setup packet to WRITE a command/value to device under test
        # see ../ae.h for struct aeCmdResponse_t

        assert len(body) <= 77
        assert 1 <= resp_len <= 65, resp_len
        assert opcode

        # organize packet:
        #  flag, len, op, p1, p2, (body), crc1, crc2
        pkt = ustruct.pack('BBBBH', IOFLAG_CMD, 1+1+1+2+len(body)+2, opcode, p1, p2)
        pkt += body
        pkt += crc16w(pkt[1:])

        pkt = self.serialize(pkt)

        ow = self.ow

        # must start with wakeup sequence
        ow.write(b'\x00')   # WAKEUP token
        ow.read()           # thow out old garbage
        sleep_us(2500)      # tWHI: 2.5ms min

        # send cmd packet
        ow.write(pkt)
        sleep_us(40)      # tTURNAROUND (80)

        if delay is None:
            # delay is required, but complete table is annoying
            if opcode in (OP.DeriveKey, OP.ECDH, OP.PrivWrite, OP.Sign):
                delay = 60
            elif opcode in (OP.GenKey, ):
                delay = 120
            else:
                delay = 20

        # delay for chip to do its maths
        sleep_ms(delay)

        while 1:
            # read back response
            if 0:
                ow.write(b'\x00')   # WAKEUP token
                while ow.any():
                    ow.read(1)           # thow out old garbage
                sleep_us(2500)      # tWHI: 2.5ms min
                ow.write(self.x88)

            # expect back
            # - the TX token (echo)
            # - length byte
            # - 1+ body
            # - 2 bytes CRC
            #
            resp = ow.read(8*(1+1+resp_len+2))

            if not resp:
                # chip wasn't ready yet: retry
                continue

            resp = self.deserialize(resp, 1)
            #print("resp: %r" % resp)

            if len(resp) < 4:
                # chip wasn't ready? Noise?
                raise WrongResponseLength(len(resp))

            if resp_len != resp[0]-3:
                if (resp[0] == 4) and (crc16w(resp[:-2]) == resp[-2:]):
                    # probably an error response
                    raise ChipErrorResponse(hex(resp[1]))

                print("wrong len: %s" % b2a_hex(resp))
                raise WrongResponseLength(len(resp))

            # check CRC, over all but last two bytes.
            expect = crc16w(resp[:-2])

            if expect != resp[-2:]:
                raise CRCError()
            
            return resp[1:-2]

    def ae_cmd(self, **kws):
        # return whatever bytes that come back
        return self.send_recv(**kws)

    def ae_cmd1(self, **kws):
        # returns the one byte
        kws.setdefault('resp_len', 1)
        return self.send_recv(**kws)[0]

    def read(self):
        "read entire CONFIG space: 4*32 bytes"
        rv = bytearray()
        for n in range(4):
            args = read_params(block=n, is_config=1)
            rv += self.ae_cmd(opcode=OP.Read, **args)

        self.data = rv

    def read_data_slot(self, slot_num, blkcount=None):
        "read a DATA slot, completely.. can be up to 3k of data"

        num_blocks, num_bytes = slot_layout(slot_num)

        d = b''
        for i in range(num_blocks):
            self.reset_watchdog()

            if blkcount is not None and i >= blkcount: break

            args = read_params(block=i, slot=slot_num, is_config=False, is_data=True, offset=0)
            d += self.ae_cmd(opcode=OP.Read, **args)

        d = d[0:num_bytes]
        #XXX waste of memory##self.d_slot[slot_num] = d

        return d

    def get_serial(self):
        return b2a_hex(self.data[0:4] + self.data[8:13])

    def write(self):
        '''
            Write the entire config block to chip. Does NOT lock it.
        '''
        assert self.data, "need read first"
        assert len(self.data) == 4*32

        zone = 0
        for n in range(16, 128, 4):
            if 84 <= n < 90:
                continue

            # must work on words, since can't write to most of the complete blocks.
            args = write_params(block=n//32, offset=n//4, is_config=True)
            try:
                x = self.ae_cmd(body=self.data[n:n+4], **args)
            except:
                print("n=%d args=%r" % (n, args))
                raise

            assert x[0] == 0, 'fail 0x%x @ n=%d' % (x[0], n)

            #readback = dev.ae_cmd(opcode=OP.Read, p1=zone, p2=p2, resp_len=32)
            args['resp_len'] = 4
            args['opcode'] = OP.Read
            readback = self.ae_cmd(**args)
            assert readback == self.data[n:n+4], 'bad r/b @ n=%d' % n

            self.reset_watchdog()

    def set_slot(self, n, slot_conf, key_conf):
        assert 0 <= n <= 15, n
        assert isinstance(slot_conf, SlotConfig)
        assert isinstance(key_conf, KeyConfig)

        self.data[20+(n*2) : 22+(n*2)] = slot_conf.pack()
        self.data[96+(n*2) : 98+(n*2)] = key_conf.pack()

    def set_combo(self, n, combo):
        self.set_slot(n, combo.sc, combo.kc)

    def get_combo(self, n):
        #  XXX broken
        from secel_config import ComboConfig, KeyConfig, SlotConfig

        rv = ComboConfig()
        blk = self.data
        rv.kc = KeyConfig.unpack(blk[96+(2*n):2+96+(2*n)])
        rv.sc = SlotConfig.unpack(blk[20+(2*n):2+20+(2*n)])
        return rv

    def set_otp_mode(self, read_only):
        # set OTPmode for consumption or read only
        # default is consumption.
        self.data[18] = 0xAA if read_only else 0x55

    def dump(self):
        from secel_config import secel_dump

        rnd = self.ae_cmd(opcode=OP.Random, resp_len=32, delay=24)
        secel_dump(self.data, rnd)

    def get_random(self):
        return self.ae_cmd(opcode=OP.Random, resp_len=32)

    def is_config_locked(self):
        "Is the config locked? Data and Slots might be unlocked still."
        return self.data[87] != 0x55

    def is_data_locked(self):
        "has data (+OTP) area been locked?"
        return self.data[86] != 0x55

    def LOCK(self, data=None, is_config=False, slot_num=None, datazone=False, no_crc=False, ecc_slots=[]):
        '''
            Lock the config area (default) or a specific slow or the OTP+Data area.
        '''
        if datazone and slot_num != None:
            # single slot of data area
            assert 0 <= slot_num < 16, slot_num
            if data == None:
                data = self.d_slot[slot_num]
            else:
                assert data == self.d_slot[slot_num], "Not the data we think is there"
            assert data is not None
            mode = 0x2 | (slot_num << 2)
        elif is_config:
            assert not datazone and slot_num==None
            data = self.data
            assert len(data) == 128
            mode = 0x00
        elif datazone:
            '''
                "The slot contents are concatenated in numerical
                order to create the input to the CRC algorithm.
                Slots that are configured to contain an ECC private
                key are never included in the summary CRC calculation.
                The OTP zone is then concatenated after the last
                Data slot and the CRC value is calculated"
            '''
            assert not is_config and slot_num is None
            included = [i for i in range(16) if not i not in ecc_slots]
            data = [self.d_slot[i] for i in included]
            assert all(data), "Missing data some slot(s): %r" % (
                                        [n for n in included if not self.d_slot[n]])
            assert all(len(self.d_slot[i]) == slot_layout(i)[1] for i in included), \
                        repr([len(i) for i in self.d_slot])
    
            data = b''.join(data)

            # we're not supporting pre-loading OTP area yet, so better be blank
            data += b'\xff'*64

            mode = 0x01
            if no_crc:
                mode |= 0x80
        else:
            raise ValueError("bad combo")

        chk = crc16w(data)

        rv = self.ae_cmd1(opcode=OP.Lock, p1=mode, p2=ustruct.unpack('<H', chk)[0], delay=33)
        if rv:
            raise ChipErrorResponse(hex(rv))

        if datazone and slot_num != None:
            # check read-back
            self.read()
            assert self.is_slot_locked(slot_num), "read back not showing locked?"

    def write_data_slot(self, slot_num, data):
        "write into a specific data slot; which could be pubkey, cert, etc"
        assert 0 <= slot_num <= 15, n
        assert len(data) % 4 == 0

        # track it for later Lock command
        self.d_slot[slot_num] = data + (b'\xff' * (slot_layout(slot_num)[1] - len(data)))

        block = 0
        while len(data):
            args = write_params(slot=slot_num, block=block, offset=0, is_data=True, sz=0x80)
            #print("WRITE: %r data=%s" % (args, b2a_hex(data[0:32])))
            assert len(data) >= 32
            rv = self.ae_cmd1(body=data[0:32], **args)
            if rv:
                raise ChipErrorResponse("write @ blk=%d: 0x%02x" % (block, rv))

            data = data[32:]
            block += 1
            if 1 <= len(data) < 32:
                # pad out final write; it's easier than guessing if partial
                # write would be allowed
                data += b'\xff' * (32 - len(data))

    def get_info(self, mode=2):
        x = self.ae_cmd(opcode=OP.Info, p1=mode, p2=0, resp_len=4, delay=2)
        return InfoStat_unpack(x[0:2]) if mode==2 else x

    def is_slot_locked(self, n):
        v = self.get_slot_locks()
        return not bool(v & (1<<n))

    def get_slot_locks(self):
        return ustruct.unpack('<H', self.data[88:90])[0]

    def get_valid_keys(self):
        # which key numbers does the chip consider valid right now.
        rv = []
        for i in range(16):
            x = self.ae_cmd(opcode=OP.Info, p1=1, p2=i, resp_len=4)[0]
            if x == 1:
                rv.append(i)
            else:
                assert x == 0
            #print("Info[key=%d] = %s" % (i, b2a_hex(x)))

        return rv

    def set_gpio(self, n):
        # 1=turn on green, 0=red light (if not yet setup)
        rv = self.ae_cmd(opcode=OP.Info, p1=3, p2=(2|(n&1)), resp_len=4)

        return rv[0]

    def get_gpio(self):
        rv = self.ae_cmd(opcode=OP.Info, p1=3, p2=0, resp_len=4)

        return rv[0]

    def load_nonce(self, mhash=None):
        "Set TempKey to a known, but randomly-based value"

        if mhash != None:
            # load with known value; won't work with some commands (ReqRandom=1)
            assert len(mhash) == 32

            rv = self.ae_cmd1(opcode = OP.Nonce, p1=3, p2=0, body=mhash)
            if rv:
                raise ChipErrorResponse(hex(rv))

        else:
            # A random number must be involved, so no choice in args to OP.Nonce here (ReqRandom).
            ch2 = random_bytes(20)
            rndout = self.ae_cmd(opcode = OP.Nonce, p1=0, p2=0, resp_len=32, body=ch2)

            # NOTE: response is the (old) contents of the RNG, not the TempKey value itself.
            assert len(rndout) == 32

            # TempKey on the chip will be set to the output of SHA256 over 
            # a message composed of my challenge, the RNG and 3 bytes of constants:
            return sha256(bytes(rndout) + ch2 + b'\x16\0\0').digest()

    def generate_ec_privkey(self, priv_slot_num):
        '''
            Have the chip pick an EC key, write it and return public key
        '''

        # returns 64 bytes of public key, but saves it as well
        return self.ae_cmd(opcode=OP.GenKey, p1=0x4, p2=priv_slot_num, resp_len=64)

    def write_ec_privkey(self, slot_num, secret, pre_auth=None):
        "write a known EC private key into a slot, verify it"
        assert len(secret) == 32

        if pre_auth: pre_auth()

        # doing an unencrypted, no-mac write.
        msg = (b'\0'*4) + secret
        assert len(msg) == 36
        self.ae_cmd1(opcode=OP.PrivWrite, p1=0, p2=slot_num, body=msg)

        # get chip to make public part of it again
        if pre_auth: pre_auth()

        # and verify it by signing something.
        mhash = random_bytes(32)
        self.load_nonce(mhash)
        sig_rs = self.ae_cmd(opcode=OP.Sign, p1=0x80, p2=slot_num, resp_len=64)
        assert len(sig_rs) == 64

        skey = SigningKey.from_string(secret, curve=NIST256p, hashfunc=sha256)

        skey.verifying_key.verify_digest(sig_rs, mhash)
        

    def write_ec_pubkey(self, slot_num, pubxy, signkey=None, do_lock=False):
        "Write a known public key, and verify it is right."
        assert len(pubxy) == 64
        assert slot_num >= 8
        assert not self.is_slot_locked(slot_num)

        # "Public keys can be written directly to the EEPROM using Write command and are always
        #  72 bytes long, formatted as follows: 4 pad bytes, 32 bytes of X, four pad bytes,
        #  then 32 bytes of Y."
        # - putting the 0x50 marks it as "validated", which is a little bogus, but has
        #   nice side-effect of making the key show as "valid" in Info reponse.

        msg = b'\x50' + (b'\0'*3) + pubxy[0:32] + b'\x50' + (b'\0'*3) + pubxy[32:64]
        assert len(msg) == 72

        # change the pubkey
        self.write_data_slot(slot_num, msg)

        if signkey:
            # To an on-chip verify to check the pubkey is right.
            # NOTE: can only work if we allowed key to sign random things (we dont)
            self.do_verify(slot_num, signkey)

        if do_lock:
            self.LOCK(slot_num=slot_num, data=msg, datazone=True)

        return msg

    def do_verify(self, slot_num, signkey):
        # To an on-chip verify to check a pubkey is right.
        # - set TempKey to a known, but randomly-based value...
        challenge = self.load_nonce()

        # sign that "message"
        sig = signkey.sign_digest(challenge)
        assert len(sig) == 64

        # check we're still good. Watchdog failure here would be bad.
        info = self.get_info()
        assert info.TK_Valid == 1, repr(info)

        # p1=0="stored" mode
        try:
            rv = self.ae_cmd1(opcode=OP.Verify, p1=0, p2=slot_num, body=sig)

            if rv:
                raise ChipErrorResponse(hex(rv))
        except Exception as e:
            print("\nFAILED to verify key[%d]: %s\n" % (slot_num, e))
            #x = self.get_combo(slot_num)
            #print("[%d] %s %s" % (slot_num, x.sc, x.kc))
            raise

        # check it worked right.
        info = self.get_info()
        assert info.TK_Valid == 0           # it's consumed I suppose
        assert info.AuthKey == slot_num
        assert info.AuthValid == 1

    def do_checkmac(self, slot_num, hkey):
        "verify we know the SHA256 key in slot n"
        assert len(hkey) == 32

        # Note: cannot read back while data zone is unlocked, but we 
        # can use the key right away in a CheckMac operation and that verifies
        # it real good.
        
        challenge = self.load_nonce()

        # 32 bytes of "client challenge" and 13 bytes of "other data" are needed, but
        # we have control over their contents.
        ch3 = b'0'*32           # unused/padding
        od = random_bytes(13)
        msg = hkey + challenge + od[0:4] + (b'\0'*8) + od[4:7] + b'\xee' \
                    + od[7:11] + b'\x01\x23' + od[11:13]
        assert len(msg) == 32+32+4+8+3+1+4+2+2
        resp = sha256(msg).digest()
        body = ch3 + resp + od
        assert len(body) == 32 + 32 + 13
        # mode=p1 must be 0x01 ... for AuthKey effect to be applied
        rv = self.ae_cmd1(opcode=OP.CheckMac, p1=0x1, p2=slot_num, body=body)

        if rv == 1:
            raise WrongMacVerify()
        elif rv:
            raise ChipErrorResponse(hex(rv))

        info = self.get_info()
        #print("After CheckMac Info = %r" % info)
        #assert info.TK_Valid == 0, info           # zero=consumed, but sometimes 1 if used for copy
        assert info.AuthKey == slot_num, info
        assert info.AuthValid == 1, 'AuthValid clear: %r' % info

        self.reset_watchdog()

    def hmac(self, slot_num, challenge, diverse=True):
        assert len(challenge) == 32
        self.load_nonce(mhash=challenge)

        return self.ae_cmd(opcode=OP.HMAC, p1=(1<<2) | ((1<<6) if diverse else 0),
                            p2=slot_num, resp_len=32)

    def gendig_slot(self, slot_num, hkey, noMac=False):
        # Construct a digest on the device (and here) than depends on the secret
        # contents of a specific slot.
        assert len(hkey) == 32
        assert not noMac, "don't know how to handle noMac=1 on orig key"

        challenge = self.load_nonce()

        # using Zone=2="Data" => "KeyID specifies a slot in the Data zone"

        msg = hkey + b'\x15\x02' + ustruct.pack("<H", slot_num)
        msg += b'\xee\x01\x23' + (b'\0'*25) + challenge
        assert len(msg) == 32+1+1+2+1+2+25+32

        rv = self.ae_cmd1(opcode=OP.GenDig, p1=0x2, p2=slot_num)
        if rv:
            raise ChipErrorResponse(hex(rv))

        self.reset_watchdog()

        return sha256(msg).digest()

    def read_encrypted(self, slot_num, read_kn, read_key):
        # use our knowledge of slot read_kn, to unlock and do encrypted-read of slot_num
        # - if slot not actually encrypted, will return garbage (no easy means to detect)
        dig = self.gendig_slot(read_kn, read_key)
        #print("After gendig:\n%r" % self.get_info())
        self.reset_watchdog()

        args = read_params(block=0, slot=slot_num, is_config=False, is_data=True, offset=0)
        rb = self.ae_cmd(opcode=OP.Read, **args)

        return bytes(a^b for a,b in zip(dig, rb))

    def write_encrypted(self, slot_num, write_kn, write_key, new_value):
        # use our knowledge of slot write_kn, to unlock and do encrypted-write into slot_num
        assert len(new_value) == 32
        assert len(write_key) == 32

        assert self.is_data_locked(), "enc write w/ data unlocked writes garbage"

        dig = self.gendig_slot(write_kn, write_key)
        #print("After gendig:\n%r" % self.get_info())
        self.reset_watchdog()

        enc = bytes(a^b for a,b in zip(dig, new_value))

        args = write_params(slot=slot_num, block=0, offset=0, is_data=True, sz=0x80)
        #print("WRITE: %r data=%s" % (args, b2a_hex(data[0:32])))
        assert len(enc) == 32

        # "authorizing mac" is also required to be sent:
        # SHA-256(TempKey, Opcode, Param1, Param2, SN<8>, SN<0:1>, <25 bytes of zeros>, PlainTextData)
        msg = (dig 
                + ustruct.pack('<bbH', OP.Write, args['p1'], args['p2']) 
                + b'\xee\x01\x23'
                + (b'\0'*25)
                + new_value)
        assert len(msg) == 32+1+1+2+1+2+25+32
                                
        auth_mac = sha256(msg).digest()

        rv = self.ae_cmd1(body=enc+auth_mac, **args)
        if rv:
            raise ChipErrorResponse(hex(rv))

    def derive_key(self, kn, old_val=None):

        # random tempkey
        challenge = self.load_nonce()

        rv = self.ae_cmd1(opcode=OP.DeriveKey, p1=0x0, p2=kn, delay=51)
        if rv:
            raise ChipErrorResponse(hex(rv))

        if old_val is not None:
            # calc new key
            msg = (old_val + bytes([OP.DeriveKey, 0x0]) + ustruct.pack("<H", kn)
                    + b'\xee\x01\x23'
                    + (b'\0'*25) + challenge)

            return sha256(msg).digest()

    def counter(self, idx, inc=False):
        assert 0 <= idx < 2, idx
        rv = self.ae_cmd(opcode=OP.Counter, p1=0x0 if not inc else 0x1, p2=idx, resp_len=4)
        return ustruct.unpack("<I", rv)[0]

