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
from contextlib import contextmanager

# Specific slots (aka key numbers) are reserved for specific purposes.
class KEYNUM_508:       # mark 1, 2
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

class KEYNUM_608:       # mark 3+
    # reserve 0: it's weird
    pairing = 1     # pairing hash key (picked by bootloader)
    pin_stretch = 2 # secret used to stretch pin (random, forgotten)
    main_pin = 3    # user-defined PIN to protect the cryptocoins (primary)
    pin_attempt = 4 # secret mixed into pin generation (rate limited, random, forgotten)
    lastgood = 5    # publically readable, PIN required to update: last successful PIN entry (1)
    match_count = 6 # match counter, updated if they get the PIN right
    duress_pin = 7  # duress wallet (no PIN failure counts)
    long_secret = 8 # 416 bytes protected by main pin (must be #8 - special longer slot) 
    secret = 9          # 72 arbitrary bytes protected by main pin (normal case)
    duress_secret = 10  # 72 arbitrary bytes protected by duress pin
    duress_lastgood = 11 # counter value when duress last worked (so we can fake num_fails)
    # available: 12
    brickme = 13    # "Brick Me" PIN holder (no associated secret, but can roll the pairing secret)
    firmware = 14   # hash of flash areas, stored as an unreadable secret, controls GPIO+light
    # reserve 15: non-special, but some fields have all ones and so point to it.


class AEConfig:
    def __init__(self):
        # typical data from a specific virgin chip; serial number and hardware rev will vary!
        self.data = bytearray(a2b_hex('01233b7e00005000e9f5342beec05400c0005500832087208f20c48f8f8f8f8f9f8faf8f0000000000000000000000000000af8fffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffff00005555ffff0000000000003300330033001c001c001c001c001c003c003c003c003c003c003c003c001c00'))
        assert len(self.data) == 4*32 == 128
        self.d_slot = [None]*16

    def set_slot(self, n, slot_conf, key_conf):
        assert 0 <= n <= 15, n
        assert isinstance(slot_conf, SlotConfig)
        assert 'KeyConfig' in str(type(key_conf))

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

    def disable_KdfIvLoc(self):
        # prevent use of weird AES KDF init vector junk
        self.data[72] = 0xf0

    def checks(self):
        # reserved areas / known values
        c = self.data
        assert c[17] == 0               # reserved
        if self.partno == 5:
            assert c[18] in (0xaa, 0x55)    # OTPmode
        assert c[86] in (0x00, 0x55)    # LockValue
        if self.partno == 5:
            assert set(c[90:96]) == set([0])  # RFU, X509Format
        if self.partno == 6:
            assert set(c[92:96]) == set([0])  # RFU, X509Format



class AEConfig508(AEConfig):
    def __init__(self):
        # typical data from a specific virgin chip; serial number and hardware rev will vary!
        self.data = bytearray(a2b_hex('01233b7e00005000e9f5342beec05400c0005500832087208f20c48f8f8f8f8f9f8faf8f0000000000000000000000000000af8fffffffff00000000ffffffff00000000ffffffffffffffffffffffffffffffff00005555ffff0000000000003300330033001c001c001c001c001c003c003c003c003c003c003c003c001c00'))
        assert len(self.data) == 4*32 == 128
        self.d_slot = [None]*16
        self.partno = 5

class AEConfig608(AEConfig):
    def __init__(self):
        # typical data from a specific virgin chip; serial number and hardware rev will vary!
        self.data = bytearray(a2b_hex('01236c4100006002bbe66928ee015400c0000000832087208f20c48f8f8f8f8f9f8faf8f0000000000000000000000000000af8fffffffff00000000ffffffff000000000000000000000000000000000000000000005555ffff0000000000003300330033001c001c001c001c001c003c003c003c003c003c003c003c001c00'))
        assert len(self.data) == 4*32 == 128
        self.d_slot = [None]*16
        self.partno = 6


    def counter_match(self, kn):
        assert 0 <= kn <= 15
        self.data[18] = (kn << 4) | 0x1

    @contextmanager
    def chip_options(self):
        co  = ChipOptions.unpack(self.data[90:92])
        yield co
        self.data[90:92] = co.pack()


def cpp_dump_hex(buf):
    # format for CPP macro
    txt = ', '.join('0x%02x' %i for i in buf)
    tw = TextWrapper(width=60)
    return '\n'.join('\t%s   \\' % i for i in tw.wrap(txt))



def main():
    with open('ae_config.h', 'wt') as fp:
        print('// autogenerated; see bootloader/keylayout.py\n', file=fp)

        for partno, ae, KEYNUM in [ (6, AEConfig608(), KEYNUM_608),
                                    (5, AEConfig508(), KEYNUM_508)]:
            doit(partno, ae, KEYNUM, fp)

def doit(partno, ae, KEYNUM, fp):
    # default all slots to storage
    cc = [ComboConfig() for i in range(16)]
    for j in range(16):
        cc[j].for_storage()

    # unique keys per-device
    # - pairing key for linking AE and main micro together
    # - critical!
    cc[KEYNUM.pairing].hash_key(roll_kn=KEYNUM.brickme).lockable(False)


    if partno == 5:
        # mark 1/2: most keyslots require knowledge of a PIN
        secure_map = [
            (KEYNUM.pin_1, KEYNUM.secret_1, KEYNUM.lastgood_1), 
            (KEYNUM.pin_2, KEYNUM.secret_2, KEYNUM.lastgood_2), 
            (KEYNUM.pin_3, KEYNUM.secret_3, None), 
            (KEYNUM.pin_4, KEYNUM.secret_4, None) ]

        # - "words" HMAC-key used for for 2-phase PIN words (only)
        cc[KEYNUM.words].hash_key().require_auth(KEYNUM.pairing).deterministic()

        main_pin = KEYNUM.pin_1
        unused_slots = [0, 15]

    if partno == 6:
        # mark 3+: no more secondary pin, some renaming, plus KDF
        secure_map = [
            (KEYNUM.main_pin, KEYNUM.secret, KEYNUM.lastgood), 
            (KEYNUM.main_pin, KEYNUM.long_secret, None), 
            (KEYNUM.duress_pin, KEYNUM.duress_secret, KEYNUM.duress_lastgood), 
        ]
        main_pin = KEYNUM.main_pin
        unused_slots = [0, 12, 15]

        # new slots related to pin attempt- and rate-limiting
        # - both hold random, unknown contents, can't be changed
        # - use of the first one will cost a counter incr
        # - actual PIN to be used is rv=HMAC(pin_stretch, rv) many times
        cc[KEYNUM.pin_attempt].hash_key().require_auth(KEYNUM.pairing).deterministic().limited_use()

        # to rate-limit PIN attempts (also used for prefix words) we require
        # many HMAC cycles using this random+unknown value.
        cc[KEYNUM.pin_stretch].hash_key().require_auth(KEYNUM.pairing).deterministic()

        # chip-enforced pin attempts: link keynum and enable "match count" feature
        cc[KEYNUM.match_count].writeable_storage(main_pin).require_auth(KEYNUM.pairing)
        ae.counter_match(KEYNUM.match_count)

        # turn off selftest feature (performance problem), and enforce encryption
        # (io protection) for verify, etc.
        with ae.chip_options() as opt:
            opt.POSTEnable = 0
            opt.IOProtKeyEnable = 1
            opt.ECDHProt = 0x1      # allow encrypted output
            opt.KDFProt = 0x1       # allow encrypted output
            opt.IOProtKey = KEYNUM.pairing

        # don't want
        ae.disable_KdfIvLoc()

    # PIN and corresponding protected secrets
    # - if you know old value of PIN, you can write it (to change to new PIN)
    for kn, sec_num, lg_num in secure_map:
        cc[kn].hash_key(write_kn=kn).require_auth(KEYNUM.pairing)
        cc[sec_num].secret_storage(kn).require_auth(kn)
        if lg_num is not None:
            # used to hold counter0] value when we last successfully got that PIN
            cc[lg_num].writeable_storage(kn).require_auth(KEYNUM.pairing)

    # "Brick Me" PIN holder: enables Roll of pairing secret + device destruction
    cc[KEYNUM.brickme].hash_key(write_kn=KEYNUM.brickme).require_auth(KEYNUM.pairing)

    # field updateable secret, hopefully based on hash of flash contents
    # - if you know this value, then you can enable the green light
    # - to change it, you need the primary pin
    cc[KEYNUM.firmware].secret_storage(main_pin).no_read().require_auth(KEYNUM.pairing)

    # Slot 8 is special because its data area is larger and could hold a
    # certificate in DER format. All ther others are 36/72 bytes only
    # BTW: on the 508a, an errata limits this to just 224 bytes, which is not enough anyway
    assert cc[8].kc.KeyType == 7

    # Slot 0 has baggage because a zero value for ReadKey has special meaning,
    # so avoid using it. But had to put something in ReadKey, so it's 15 sometimes.
    assert cc[0].sc.IsSecret == 0
    assert cc[15].sc.IsSecret == 0

    assert len(cc) == 16
    for idx, x in enumerate(cc):
        # no EC keys on this project
        assert cc[idx].kc.KeyType in [6,7], idx

        if idx == KEYNUM.pairing:
            assert cc[idx].kc.KeyType == 7
        elif idx in unused_slots:
            # check not used
            assert cc[idx].sc.as_int() == 0x0000, (partno, idx)
            assert cc[idx].kc.as_int() == 0x003c, (partno, idx)
        else:
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
    if fp:
        print("#ifdef FOR_%d08\n" % partno, file=fp)

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

        if partno == 6:
            print('\n/*\n', file=fp)
            sys.stdout = fp
            ae.dump()
            print('\n*/', file=fp)

        print("#endif /* FOR_%d08 */\n\n" % partno, file=fp)

if __name__ == '__main__':
    main()
