# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
from main import ae
from secel import WrongMacVerify

# Key/slot numbers
KN_pairing = 1
KN_words = 2
KN_pins =    [3, 6,  9, 11, 13]
KN_secrets = [4, 7, 10, 12]
KN_lastgood = [5, 8]
KN_brickme = 13
KN_firmware = 14

# 36 bytes in many slots, so extra 4 bytes are ones
FF4 = b'\xff\xff\xff\xff'

# normally, this would be the big secret
pairing_key = b'12345678'*4

# normally, this key destroyed after loading
words_key = b'87654321'*4

# play values for PIN / bitcoin secret
BLANK = b'\0'*32
PIN = b'1234'*8
SEC = b'hello world' + b' '*(32-11)

def test_read(x_pin=PIN, idx=0):
    assert len(x_pin) == len(SEC) == 32

    # optional: check it's the right PIN
    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.do_checkmac(KN_pins[idx], x_pin)     # fails on wrong pin
    info = ae.get_info()
    # gets: InfoStat(TK_KeyId=0, TK_SourceFlag=0, TK_GenDigData=0,
    #   TK_GenKeyData=0, TK_NoMacFlag=0, EEPROM_RNG=1, SRAM_RNG=0,
    #   AuthValid=1, AuthKey=3, TK_Valid=0)
    assert info.AuthKey == KN_pins[idx], info
    assert info.TK_GenDigData == 0, info

    # - so can't use that for encrypted read, but does verify the slot contents

    # NOW: read the secret out, encrypted
    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)

    rb = ae.read_encrypted(KN_secrets[idx], KN_pins[idx], x_pin)
    print("  secret[%d] = %r" % (idx, rb))
    if idx < len(KN_lastgood):
        ae.reset_watchdog()
        ae.do_checkmac(KN_pairing, pairing_key)
        rb = ae.read_data_slot(KN_lastgood[idx], blkcount=1)
        print("lastgood[%d] = %r" % (idx, rb))

def change_pin(old_pin, new_pin, idx=0):
    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    try:
        ae.do_checkmac(KN_pins[idx], old_pin)
    except WrongMacVerify:
        print("that's the wrong PIN")
        return 0

    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.write_encrypted(KN_pins[idx], KN_pins[idx], old_pin, new_pin)
    
    # verify change
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.do_checkmac(KN_pins[idx], new_pin)

    print("[%d] new pin in effect" % idx)
    ae.reset_chip()
    ae.do_checkmac(KN_pairing, pairing_key)

    if idx < len(KN_secrets):
        return ae.read_encrypted(KN_secrets[idx], KN_pins[idx], new_pin)

def change_secret(the_pin, new_secret, idx=0):
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.write_encrypted(KN_secrets[idx], KN_pins[idx], the_pin, new_secret)

    ae.reset_chip()
    ae.do_checkmac(KN_pairing, pairing_key)
    rb = ae.read_encrypted(KN_secrets[idx], KN_pins[idx], the_pin)
    assert rb == new_secret

    return rb

def change_lastgood(the_pin, new_value, idx=0):
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.write_encrypted(KN_lastgood[idx], KN_pins[idx], the_pin, new_value)

    ae.reset_chip()
    ae.do_checkmac(KN_pairing, pairing_key)
    rb = ae.read_data_slot(KN_lastgood[idx], blkcount=1)
    assert rb == new_value

    return rb
        

def test_fw(fw=None):
    # write a value (someday will be the flash checksum)
    fw = fw or b'test'*8
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.write_encrypted(KN_firmware, KN_pairing, pairing_key, fw)

    # verify it's what we wanted
    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.do_checkmac(KN_firmware, fw)

    # we can now show the green light
    return ae.set_gpio(1)

def test_brick(the_pin=BLANK):
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.do_checkmac(KN_brickme, the_pin)
    ae.reset_watchdog()
    #print(ae.get_info())
    nk = ae.derive_key(KN_pairing, pairing_key)
    print("new key?: %s" % b2a_hex(nk))

def test():

    for idx in range(5):
        ae.reset_watchdog()
        change_pin(BLANK, PIN, idx=idx)

        ae.reset_watchdog()
        change_pin(PIN, BLANK, idx=idx)

    cnt = b'1'*32
    for idx in range(2):
        rb = change_lastgood(BLANK, cnt, idx=idx)
        print('lastgood[%d] = %r' % (idx, rb))

    for idx in range(4):
        rb = change_secret(BLANK, SEC, idx=idx)
        print('secret[%d] = %r' % (idx, rb))

    assert test_fw() == 1
    print("firmware/gpio works")
    
    

def go():

    # see bootloader/data/ae_layout.h

    c1 = bytes([
        0xe1, 0x00, 0x55, 0x00, 0x00, 0x00, 0x8f, 0x2d, 0x8f, 0x80,   \
        0x8f, 0x43, 0xc3, 0x43, 0x00, 0x43, 0x8f, 0x46, 0xc6, 0x46,   \
        0x00, 0x46, 0x8f, 0x49, 0xc9, 0x49, 0x8f, 0x4b, 0xcb, 0x4b,   \
        0x8f, 0x4d, 0xc1, 0x41, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,   \
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,   \
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   \
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff   \
    ])

    c2 = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x5c, 0x00,   \
        0xbc, 0x01, 0xfc, 0x01, 0xdc, 0x03, 0x9c, 0x01, 0xfc, 0x01,   \
        0xdc, 0x06, 0x9c, 0x01, 0xfc, 0x01, 0xdc, 0x09, 0xfc, 0x01,   \
        0xdc, 0x0b, 0xfc, 0x01, 0xdc, 0x01, 0x3c, 0x00   \
    ])


    if not ae.is_config_locked():
        ae.data[16:84] = c1
        ae.data[90:128] = c2
        assert len(ae.data) == 128
        b4 = bytes(ae.data)
        ae.write()
        ae.read()
        assert b4 == ae.data
        print("locking configzone")
        ae.LOCK(is_config=1)
        ae.reset_watchdog()
        ae.read()

    # assume all slots are blank
    ae.assume_data_blank()

    if not ae.is_slot_locked(KN_pairing):
        assert len(pairing_key) == 32
        ae.write_data_slot(KN_pairing, pairing_key)
    
        # cannot lock this slot, or else we can't burn it via DeriveKey
        #ae.LOCK(data=pairing_key+FF4, slot_num=KN_pairing, datazone=True)
    else:
        ae.d_slot[KN_pairing] = pairing_key+FF4

    # check pairing key works
    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    print("checkmac pairing works")

    if not ae.is_slot_locked(KN_words):
        assert len(words_key) == 32
        ae.write_data_slot(KN_words, words_key)
        ae.do_checkmac(KN_words, words_key)      # check write

        # always lock it
        ae.LOCK(data=words_key+b'\xff\xff\xff\xff', slot_num=KN_words, datazone=True)
    else:
        ae.d_slot[KN_words] = words_key+FF4

    # need both keys to be able to do this!
    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    ae.do_checkmac(KN_words, words_key)         # will fail if we didn't just auth w/ pairing key
    print("checkmac words works")

    ae.reset_watchdog()
    ae.do_checkmac(KN_pairing, pairing_key)
    hm = ae.hmac(KN_words, b'0'*32, diverse=False)      # production: will be diverse mode
    assert hm == a2b_hex('aadec702b4855df0c1838a48978d56a65e5871f291e835d0f833aa2fdfd30290'), b2a_hex(hm)
    print("HMAC(words, '0'*32) works")

    # Set PIN's to something known.
    # simple non-encrypted write can work while data unlocked
    if not ae.is_data_locked():
        for idx in range(4):
            ae.reset_watchdog()
            ae.write_data_slot(KN_pins[idx], BLANK)
            ae.write_data_slot(KN_secrets[idx], BLANK)
            if idx < len(KN_lastgood):
                ae.write_data_slot(KN_lastgood[idx], BLANK)

        ae.reset_watchdog()
        ae.write_data_slot(KN_brickme, BLANK)
        ae.write_data_slot(KN_firmware, BLANK)

        print("Locking data zone")
        ae.LOCK(datazone=True, ecc_slots=[], no_crc=1)
        ae.reset_watchdog()
        ae.read()

    print("Success")

if 0:
    # exec on import
    go()
