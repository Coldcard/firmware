# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Secure Element Config Area.
#
# Bitwise details about the the ATECC608a and 508a "config" area, which determines what
# you can and (mostly) cannot do with each private key in device.
#
# - you must contemplate the full datasheet at length
# - as of Jul/2019 the 608a datasheet is under NDA, sorry.
# - this file can be useful both in Micropython and CPython3
#
try:
    MPY=True
    from ubinascii import hexlify as b2a_hex
    from ubinascii import unhexlify as a2b_hex
    from uhashlib import sha256
    from ucollections import namedtuple
    import ustruct
except ImportError:
    MPY=False
    from binascii import b2a_hex, a2b_hex
    from hashlib import sha256
    import struct

def secel_dump(blk, rnd=None, which_nums=range(16)):
    ASC = lambda b: str(b, 'ascii')

    def hexdump(label, x):
        print(label + ASC(b2a_hex(x)) + ('  len=%d'%len(x)))

    #hexdump('SN: ', blk[0:4]+blk[8:13])
    hexdump('RevNum: ', blk[4:8])

    # guessing this nibble in RevNum corresponds to chip 508x vs 608x
    print("Chip type: atecc%x08" % ((blk[6]>>4)&0xf))
    partno = ((blk[6]>>4)&0xf)
    assert partno in [5, 6]

    if partno == 6:
        print('AES_Enable = 0x%x' % (blk[13] & 0x1))

    print('I2C_Enable = 0x%x' % (blk[14] & 0x1))
    if blk[14] & 0x01 == 0x01:
        print('I2C_Address = 0x%x' % (blk[16] >> 1))
    else:
        print('GPIO Mode = 0x%x' % (blk[16] & 0x3))
        print('GPIO Default = 0x%x' % ((blk[16]>>2) & 0x1))
        print('GPIO Detect (vs authout) = 0x%x' % ((blk[16]>>3) & 0x1))
        print('GPIO SignalKey/KeyId = 0x%x' % ((blk[16]>>4) & 0xf))
        print('I2C_Address(sic) = 0x%x' % blk[16])

    if partno == 5:
        print('OTPmode = 0x%x' % blk[18])
    if partno == 6:
        print('CountMatchKey = 0x%x' % ((blk[18] >> 4)&0xf))
        print('CounterMatch enable = %d' % (blk[18] &0x1))

    print('ChipMode = 0x%x' % blk[19])

    print()

    for i in which_nums:
        slot_conf = blk[20+(2*i):22+(2*i)]
        conf = SlotConfig.unpack(slot_conf)
        print('     Slot[%d] = 0x%s = %r' % (i, ASC(b2a_hex(slot_conf)), conf))

        key_conf = blk[96+(2*i):2+96+(2*i)]

        cls = KeyConfig_508 if partno == 5 else KeyConfig_608

        print('KeyConfig[%d] = 0x%s = %r' % (i, ASC(b2a_hex(key_conf)),
                                                    cls.unpack(key_conf)))

        print()

    hexdump('Counter[0]: ', blk[52:60])
    hexdump('Counter[1]: ', blk[60:68])
    if partno == 5:
        hexdump('LastKeyUse: ', blk[68:84])
    if partno == 6:
        print('UseLock = 0x%x' % blk[68])
        print('VolatileKeyPermission = 0x%x' % blk[69])
        hexdump('SecureBoot: ', blk[70:72])

        print('KldfvLoc = 0x%x' % blk[72])
        hexdump('KdflvStr: ', blk[73:75])

    # 75->83 reserved
    print('UserExtra = 0x%x' % blk[84])
    if partno == 5:
        print('Selector = 0x%x' % blk[85])
    if partno == 6:
        print('UserExtraAdd = 0x%x' % blk[85])

    print('LockValue = 0x%x' % blk[86])
    print('LockConfig = 0x%x' % blk[87])
    hexdump('SlotLocked: ', blk[88:90])

    if partno == 6:
        hexdump('ChipOptions: ', blk[90:92])
        print('ChipOptions = %r' % ChipOptions.unpack(blk[90:92]))

    hexdump('X509format: ', blk[92:96])

    if rnd is not None:
        hexdump('Random: ', rnd)


if MPY:
    # XXX readonly version for micropython

    def make_bitmask(name, defs):
        '''
            Take a list of bit widths and field names, and convert into a useful class.
        '''
        custom_t = namedtuple(name, [n for w,n in defs])

        assert sum(w for w,n in defs) == 16


        class wrapper:
            def __init__(self, *a, **kws):
                if not a:
                    a = [0] * len(defs)
                for idx, (_, nm) in enumerate(defs):
                    if nm in kws:
                        a[idx] = kws[nm]
                self.x = custom_t(*a)

            @classmethod
            def unpack(cls, ss):
                v = ustruct.unpack('<H', ss)[0]
                pos = 0 
                rv = []
                for w,n in defs:
                    rv.append( (v >> pos) & ((1<<w)-1) )
                    pos += w
                assert pos == 16
                return cls(*rv)

            def pack(self):
                ss = 0
                pos = 0 
                for w,n in defs:
                    v = getattr(self.x, n)
                    assert v < (1<<w), n+" is too big"
                    ss |= (v << pos)
                    pos += w
                assert pos == 16
                return ustruct.pack("<H", ss)

            def as_int(self):
                return ustruct.unpack("<H", self.pack())[0]

            def as_hex(self):
                return hex(self.as_int())

            def __repr__(self):
                return repr(self.x) + ('=0x%04x' % self.as_int())

        return wrapper
else:
    # full version for desktop... uses "namedlist" module to good effect
    from namedlist import namedlist

    # monkeypatch until namedlist catches up to python3.10
    # see <https://gitlab.com/ericvsmith/namedlist/-/merge_requests/1>
    try:
        from collections import Mapping as _
    except ImportError:
        import namedlist as nl
        from collections import abc as _abc
        nl._collections.Sequence = _abc.Sequence
        nl._collections.Mapping = _abc.Mapping

    def make_bitmask(name, defs):
        '''
            Name a list of bit widths and names, and convert into a class.
        '''
        rv = namedlist(name, (n for w,n in defs), default=0)

        assert sum(w for w,n in defs) == 16

        @classmethod
        def unpack(cls, ss):
            v = struct.unpack('<H', ss)[0]
            pos = 0 
            rv = {}
            for w,n in defs:
                rv[n] = (v >> pos) & ((1<<w)-1)
                pos += w
            assert pos == 16
            return cls(**rv)

        def pack(self):
            ss = 0
            pos = 0 
            for w,n in defs:
                v = getattr(self, n)
                assert v < (1<<w), n+" is too big"
                ss |= (v << pos)
                pos += w
            assert pos == 16
            return struct.pack("<H", ss)


        rv.unpack = unpack
        rv.pack = pack
        rv.as_int = lambda self: struct.unpack("<H", self.pack())[0]
        rv.as_hex = lambda self: hex(self.as_int())
        old_repr = rv.__repr__
        rv.__repr__ = lambda self: old_repr(self) + ('=0x%04x' % self.as_int())

        return rv

# Section 2.2.5, Table 2-11: KeyConfig (Bytes 96 thru 127)
KeyConfig_508 = make_bitmask('KeyConfig', [
                    (1, 'Private'),
                    (1, 'PubInfo'),
                    (3, 'KeyType'),
                    (1, 'Lockable'),
                    (1, 'ReqRandom'),
                    (1, 'ReqAuth'),
                    (4, 'AuthKey'),
                    (1, 'IntrusionDisable'),
                    (1, 'RFU'),
                    (2, 'X509id')])

# 608a: Section 2.2.13, Table 2-11: KeyConfig (Bytes 96 thru 127)
KeyConfig_608 = make_bitmask('KeyConfig', [
                    (1, 'Private'),
                    (1, 'PubInfo'),
                    (3, 'KeyType'),
                    (1, 'Lockable'),
                    (1, 'ReqRandom'),
                    (1, 'ReqAuth'),
                    (4, 'AuthKey'),
                    (1, 'PersistentDisable'),
                    (1, 'RFU'),
                    (2, 'X509id')])

# Section 2.2.12, Table 2-5: SlotConfig (Bytes 20 to 51)
SlotConfig = make_bitmask('SlotConfig', [
                    (4, 'ReadKey'),
                    (1, 'NoMac'),
                    (1, 'LimitedUse'),
                    (1, 'EncryptRead'),
                    (1, 'IsSecret'),
                    (4, 'WriteKey'),
                    (4, 'WriteConfig')])

# 508a: Section 9.9, for the Info command (mode=State)
InfoState_508 = make_bitmask('InfoState', [
				(4, 'TK_KeyId'),
				(1, 'TK_SourceFlag'),
				(1, 'TK_GenDigData'),
				(1, 'TK_GenKeyData'),
				(1, 'TK_NoMacFlag'),

				(1, 'EEPROM_RNG'),
				(1, 'SRAM_RNG'),
				(1, 'AuthValid'),
                (4, 'AuthKey'),
                (1, 'TK_Valid') ])

# 608a: Section 11.8, for the Info command (mode=State)
InfoState_608 = make_bitmask('InfoState', [
				(4, 'TK_KeyId'),
				(1, 'TK_SourceFlag'),
				(1, 'TK_GenDigData'),
				(1, 'TK_GenKeyData'),
				(1, 'TK_NoMacFlag'),

				(2, 'zeros'),
				(1, 'AuthValid'),
                (4, 'AuthKey'),
                (1, 'TK_Valid') ])

# 608a: ChipOptions, offset 90 in EEPROM data
# - the datasheet, in this one spot, lists the bits in MSB->LSB order, but elsewhere LSB->MSB
# - bit numbers are right, and register isn't other endian, just the text backwards
# - section 2.2.10 has in right order, but skips various bits in the register
ChipOptions = make_bitmask('ChipOptions', [
                    (1, 'POSTEnable'),
                    (1, 'IOProtKeyEnable'),
                    (1, 'KDFAESEnable'),
                    (5, 'mustbezero'),
                    (2, 'ECDHProt'),
                    (2, 'KDFProt'),
                    (4, 'IOProtKey'), ])
        
class ComboConfig(object):
    __slots__ = ['kc', 'sc', 'partno']        # block spelling mistakes

    def __init__(self, partno=5):
        self.partno = partno
        self.kc = KeyConfig_508() if partno == 5 else KeyConfig_608()
        self.sc = SlotConfig(WriteConfig=0x8)       # most restrictive

    @property
    def is_ec_key(self):
        return (self.kc.KeyType == 4)         # secp256r1

    def ec_key(self, limited_sign=False, ecdh_en=False):
        # basics for an EC key
        self.kc.KeyType = 4         # secp256r1
        self.kc.Private = 1         # is a EC private key
        self.kc.Lockable = 0        # normally set in stone
        self.kc.PubInfo = 1         # 1= allow gen of pubkey from this privkey
        self.kc.ReqRandom = 1       # operations need rnd component? no clear if needed
        self.sc.IsSecret = 1        # because is a private key
        self.sc.ReadKey = 0x2 if limited_sign else 0x3
        if ecdh_en:
            self.sc.ReadKey |= 0x4     # enable ECDH, even in the clear
        self.sc.WriteConfig = 0x2   # enable GenKey (not PrivWrite), no mac for key roll
        return self

    def hash_key(self, write_kn=None, roll_kn=None):
        # basics for a hashing key (32-bytes of noise)
        self.kc.KeyType = 7         # not EC
        self.kc.Private = 0         # not an EC private key
        self.kc.ReqRandom = 1
        self.sc.NoMac = 0
        self.sc.IsSecret = 1        # because is a secret key
        self.sc.EncryptRead = 0     # no readback supported at all, even encrypted
        self.sc.ReadKey = 0xf       # don't allow checkMac? Do allow other uses? IDK
        if write_kn is not None:
            assert 0 <= write_kn <= 15
            self.sc.WriteKey = write_kn
            self.sc.WriteConfig = 0x4       # encrypted writes allowed
        else:
            # 8="Never" - value must be written before data locked
            self.sc.WriteConfig = 0x8

        if roll_kn is not None:
            assert write_kn is None
            self.sc.WriteKey = roll_kn
            self.sc.WriteConfig = 0x2       # see Table 2-0: enable Roll w/o MAC, still never write

        return self

    def for_storage(self, lockable=True):
        # public data storage, not secrets
        self.kc.KeyType = 7         # not EC
        self.kc.Private = 0         # not an EC private key
        self.kc.Lockable = int(lockable)    # can delay slot locking
        self.sc.IsSecret = 0        # not a secret
        self.sc.ReadKey = 0x0       # allow checkMac
        self.sc.WriteConfig = 0     # permissive
        return self

    def writeable_storage(self, write_kn, lockable=False):
        # public data storage but require key to update
        self.kc.KeyType = 7         # not EC
        self.kc.Private = 0         # not an EC private key
        self.kc.Lockable = int(lockable)    # can delay slot locking
        self.sc.IsSecret = 0        # not a secret
        self.sc.ReadKey = 0x0       # allow checkMac
        # allow authenticated updates
        self.sc.WriteKey = write_kn 
        self.sc.WriteConfig = 0x4       # encrypted writes allowed
        return self

    def no_read(self):
        self.sc.IsSecret = 1        # because is a secret key
        self.sc.ReadKey = 0xf   
        self.sc.EncryptRead = 0     # no readback supported at all, even encrypted
        return self

    def no_pubkey(self):
        # don't allow export of pubkey (except during setup)
        assert self.is_ec_key       # EC cases only
        self.kc.PubInfo = 0
        return self

    def secret_storage(self, rw_kn):
        # secret data storage, which can be updated repeatedly in the field
        assert 0 <= rw_kn <= 15
        self.kc.KeyType = 7         # not EC
        self.kc.Private = 0         # not an EC private key
        self.kc.Lockable = 0        # cannot lock the slot (would be DoS attack)
        self.kc.ReqRandom = 1       # rng must be part of nonce
        self.sc.IsSecret = 1        # shh.. secret
        self.sc.EncryptRead = 1     # always encrypted read required
        self.sc.ReadKey = rw_kn   
        self.sc.WriteKey = rw_kn   
        self.sc.WriteConfig = 0x4   # encrypted write, no DeriveKey support
        return self

    def deterministic(self):
        # most keyslots should have ReqRandom=1 but if we're using it to hash up
        # a known value, like a PIN, then it can't be based on a nonce.
        self.kc.ReqRandom = 0
        return self

    def require_rng(self):
        # prevents replay attacks
        self.kc.ReqRandom = 1
        return self

    def require_auth(self, kn):
        # knowledge of another key will be required
        assert 0 <= kn <= 15
        self.kc.ReqAuth = 1
        self.kc.AuthKey = kn
        return self

    def lockable(self, lockable):
        self.kc.Lockable = int(lockable)    # can delay slot locking
        return self

    def limited_use(self):
        self.sc.LimitedUse = 1          # counter0 will inc by one each use
        return self

    def read_encrypted(self, kn):
        # readout allowed, but it's encrypted by key kn
        # "Reads from this slot are encrypted using the encryption algorithm
        #  documented in Section 9.16, Read Command"
        assert 0 <= kn <= 15
        self.kc.EncryptRead = 1
        self.kc.ReadKey = kn
        self.kc.IsSecret = 1
        return self

    def persistent_disable(self):
        assert self.partno == 6, '608a only'
        self.kc.PersistentDisable = 1
        return self
    
    def is_aes_key(self):
        assert self.partno == 6, '608a only'
        self.kc.KeyType = 6     # for use with AES
        return self

# EOF
