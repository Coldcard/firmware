# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Secure Element Config Area
#
# Bitwise details about the the ATECC508A "config" area, which determines what
# you can and (mostly) cannot do with each private key in device.
#
# - use must contemplate the full datasheet at length
# - but very simmilar to ATSHA204 and family chips
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

    hexdump('RevNum: ', blk[4:8])
    print('I2C_Enable = 0x%x' % (blk[14] & 0x1))
    if blk[14] & 0x01 == 0x01:
        print('I2C_Address = 0x%x' % (blk[16] >> 1))
    else:
        print('GPIO Mode = 0x%x' % (blk[16] & 0x3))
        print('GPIO Default = 0x%x' % ((blk[16]>>2) & 0x1))
        print('GPIO Detect (vs authout) = 0x%x' % ((blk[16]>>3) & 0x1))
        print('GPIO SignalKey/KeyId = 0x%x' % ((blk[16]>>4) & 0xf))
        print('I2C_Address(sic) = 0x%x' % blk[16])
    print('OTPmode = 0x%x' % blk[18])
    print('ChipMode = 0x%x' % blk[19])

    for i in which_nums:
        slot_conf = blk[20+(2*i):22+(2*i)]
        conf = SlotConfig.unpack(slot_conf)
        print('     Slot[%d] = 0x%s = %r' % (i, ASC(b2a_hex(slot_conf)), conf))

        key_conf = blk[96+(2*i):2+96+(2*i)]

        print('KeyConfig[%d] = 0x%s = %r' % (i, ASC(b2a_hex(key_conf)),
                                                    KeyConfig.unpack(key_conf)))

        print()

    hexdump('Counter[0]: ', blk[52:60])
    hexdump('Counter[1]: ', blk[60:68])
    hexdump('LastKeyUse: ', blk[68:84])

    print('UserExtra = 0x%x' % blk[84])
    print('Selector = 0x%x' % blk[85])

    print('LockValue = 0x%x' % blk[86])
    print('LockConfig = 0x%x' % blk[87])
    hexdump('SlotLocked: ', blk[88:90])
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
                v = ustruct.unpack("<H", ss)[0]
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

    def make_bitmask(name, defs):
        '''
            Name a list of bit widths and names, and convert into a class.
        '''
        rv = namedlist(name, (n for w,n in defs), default=0)

        assert sum(w for w,n in defs) == 16

        @classmethod
        def unpack(cls, ss):
            v = struct.unpack("<H", ss)[0]
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
KeyConfig = make_bitmask('KeyConfig', [
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

# Section 2.2.1, Table 2-5: SlotConfig (Bytes 20 to 51)
SlotConfig = make_bitmask('SlotConfig', [
                    (4, 'ReadKey'),
                    (1, 'NoMac'),
                    (1, 'LimitedUse'),
                    (1, 'EncryptRead'),
                    (1, 'IsSecret'),
                    (4, 'WriteKey'),
                    (4, 'WriteConfig')])

# Section 9.9, for the Info command (mode=State)
InfoState = make_bitmask('InfoState', [
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
        
class ComboConfig(object):
    __slots__ = ['kc', 'sc']        # block spelling mistakes
    def __init__(self):
        self.kc = KeyConfig()
        self.sc = SlotConfig(WriteConfig=0x8)       # most restrictive

    @property
    def is_ec_key(self):
        return (self.kc.KeyType == 4)         # secp256r1

    def ec_key(self, limited_sign=False):
        # basics for an EC key
        self.kc.KeyType = 4         # secp256r1
        self.kc.Private = 1         # is a EC private key
        self.kc.Lockable = 0        # normally set in stone
        self.sc.IsSecret = 1        # because is a private key
        self.sc.ReadKey = 0x2 if limited_sign else 0xf       # allow CheckMac only, or all usages
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

    def require_auth(self, kn):
        # knowledge of another key will be required
        assert 0 <= kn <= 15
        self.kc.ReqAuth = 1
        self.kc.AuthKey = kn
        return self

    def lockable(self, lockable):
        self.kc.Lockable = int(lockable)    # can delay slot locking
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
        
    

