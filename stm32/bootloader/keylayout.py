#!/usr/bin/env python3
#
# Determine bits needed to configure ATECC508A to our purposes.
#
# Resulting data travels in the bootloader and is used once during
# factory setup.
#
import sys
from secel_config import *
from textwrap import TextWrapper

# Specific slots (aka key numbers) are reserved for specific purposes.
class KEYNUM:
    # reserve 0: it's weird
    pairing = 1     # pairing hash key (picked by bootloader)
    words = 2       # secret used just for generated 2-phase protection words (random, forgotten)
    pin_1 = 3       # user-defined PIN to protect the cryptocoins (primary)
    pin_2 = 4       # user-defined PIN to protect cryptocoins (secondary)
    lastgood_1 = 5  # publically readable, PIN required to update: last successful PIN entry (1)
    lastgood_2 = 6  # publically readable, PIN required to update: last successful PIN entry (2)
    pin_3 = 7       # Duress wallet 1 (no PIN failure counts)
    pin_4 = 8       # Duress wallet 2 (no PIN failure counts)
    secret_1 = 9    # arbitrary bytes protected by corresponding pin
    secret_2 = 10   # arbitrary bytes protected by corresponding pin
    secret_3 = 11   # bytes protected by corresponding pin
    secret_4 = 12   # bytes protected by corresponding pin
    brickme = 13    # "Brick Me" PIN holder (no associated secret, but can roll the pairing secret)
    firmware = 14   # hash of flash areas, stored as an unreadable secret, controls GPIO+light
    # reserve 15: special limited use key


class AEConfig:
    def __init__(self):
        # typical data from a specific virgin chip; serial number and hardware rev will vary!
        self.data = bytearray(a2b_hex('01233b7e00005000e9f5342beec05400c0005500832087208f20c48f8f8f8f8f9f8faf8f0000000000000000000000000000af8fffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffff00005555ffff0000000000003300330033001c001c001c001c001c003c003c003c003c003c003c003c001c00'))
        assert len(self.data) == 4*32 == 128
        self.d_slot = [None]*16

    def set_slot(self, n, slot_conf, key_conf):
        assert 0 <= n <= 15, n
        assert isinstance(slot_conf, SlotConfig)
        assert isinstance(key_conf, KeyConfig)

        self.data[20+(n*2) : 22+(n*2)] = slot_conf.pack()
        self.data[96+(n*2) : 98+(n*2)] = key_conf.pack()

    def set_combo(self, n, combo):
        self.set_slot(n, combo.sc, combo.kc)

    def get_combo(self, n):
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
        secel_dump(self.data)

    def set_gpio_config(self, kn):
        # GPIO is active-high output, controlled by indicated key number
        assert 0 <= kn <= 15
        assert self.data[14] & 1 == 0, "can only work on chip w/ SWI not I2C"
        self.data[16] = 0x1 | (kn << 4)     # "Auth0" mode in table 7-1

    def checks(self):
        # reserved areas / known values
        c = self.data
        assert c[17] == 0               # reserved
        assert c[18] in (0xaa, 0x55)    # OTPmode
        assert c[86] in (0x00, 0x55)    # LockValue
        assert set(c[90:96]) == set([0])  # RFU, X509Format

def cpp_dump_hex(buf):
    # format for CPP macro
    txt = ', '.join('0x%02x' %i for i in buf)
    tw = TextWrapper(width=60)
    return '\n'.join('\t%s   \\' % i for i in tw.wrap(txt))


def main():

    ae = AEConfig()

    # default all slots to storage
    cc = [ComboConfig() for i in range(16)]
    for j in range(16):
        cc[j].for_storage()

    # unique keys per-device
    # - pairing key for linking AE and main micro together
    # - critical!
    cc[KEYNUM.pairing].hash_key(roll_kn=KEYNUM.brickme).lockable(False)

    # - "words" HMAC-key used for for 2-phase PIN words (only)
    cc[KEYNUM.words].hash_key().require_auth(KEYNUM.pairing).kc.ReqRandom = 0

    # PIN and corresponding protected secrets
    # - if you know old value of PIN, you can write it (to change to new PIN)
    for kn, sec_num, lg_num in [
            (KEYNUM.pin_1, KEYNUM.secret_1, KEYNUM.lastgood_1), 
            (KEYNUM.pin_2, KEYNUM.secret_2, KEYNUM.lastgood_2), 
            (KEYNUM.pin_3, KEYNUM.secret_3, None), 
            (KEYNUM.pin_4, KEYNUM.secret_4, None)
    ]:
        cc[kn].hash_key(write_kn=kn).require_auth(KEYNUM.pairing)
        cc[sec_num].secret_storage(kn).require_auth(kn)
        if lg_num is not None:
            # used to hold counter[0/1] value when we last successfully got the PIN
            cc[lg_num].writeable_storage(kn).require_auth(KEYNUM.pairing)

    # "Brick Me" PIN holder: enables Roll of pairing secret + device destruction
    cc[KEYNUM.brickme].hash_key(write_kn=KEYNUM.brickme).require_auth(KEYNUM.pairing)

    # field updateable secret, hopefully based on hash of flash contents
    # - if you know this value, then you can enable the green light
    # - to change it, you need the primary pin
    cc[KEYNUM.firmware].secret_storage(KEYNUM.pin_1).no_read().require_auth(KEYNUM.pairing)

    # Slot 8 is special because its data area is larger and could hold a
    # certificate in DER format. All ther others are 36/72 bytes only
    # BTW: an errata limits this to just 224 bytes, which is not enough
    assert cc[8].kc.KeyType == 7

    # Slot 0 has baggage because a zero value for ReadKey has special meaning,
    # so avoid using it. But had to put something in ReadKey, so it's 15 sometimes.
    assert cc[0].sc.IsSecret == 0
    assert cc[15].sc.IsSecret == 0

    assert len(cc) == 16
    for idx, x in enumerate(cc):
        if idx not in (0, KEYNUM.pairing, 15):
            # Use of **any** key require knowledge of pairing secret
            # except PIN-protected slots, which require PIN (which requires pairing secret)
            assert cc[idx].kc.ReqAuth, idx
            assert (cc[idx].kc.AuthKey == KEYNUM.pairing) or \
                    (cc[cc[idx].kc.AuthKey].kc.AuthKey == KEYNUM.pairing), idx

        ae.set_combo(idx, cc[idx])

    # require CheckMac on indicated key to turn on GPIO
    ae.set_gpio_config(KEYNUM.firmware)

    ae.checks()

    #ae.dump()

    # generate a single header file we will need

    with open('ae_config.h', 'wt') as fp:
        print('// autogenerated; see bootloader/keylayout.py\n', file=fp)

        print('// bytes [16..84) of chip config area', file=fp)
        print('#define AE_CHIP_CONFIG_1 { \\', file=fp)
        print(cpp_dump_hex(ae.data[16:84]), file=fp)
        print('}\n\n', file=fp)

        print('// bytes [90..128) of chip config area', file=fp)
        print('#define AE_CHIP_CONFIG_2 { \\', file=fp)
        print(cpp_dump_hex(ae.data[90:]), file=fp)
        print('}\n\n', file=fp)

        print('// key/slot usage and names', file=fp)
        names = [nm for nm in dir(KEYNUM) if nm[0] != '_']
        for v,nm in sorted((getattr(KEYNUM, nm), nm) for nm in names):
            print('#define KEYNUM_%-20s\t%d' % (nm.lower(), v), file=fp)

        print('\n/*\n', file=fp)
        sys.stdout = fp
        ae.dump()
        print('\n*/', file=fp)

if __name__ == '__main__':
    main()
