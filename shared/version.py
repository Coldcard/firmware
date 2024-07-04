# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# version.py - Get lots of different version numbers from stuff.
#
# REMINDER: update simulator version of this file if API changes are made.
#
from public_constants import MAX_TXN_LEN, MAX_UPLOAD_LEN

def decode_firmware_header(hdr):
    from sigheader import FWH_PY_FORMAT
    import ustruct

    magic_value, timestamp, version_string = ustruct.unpack_from(FWH_PY_FORMAT, hdr)[0:3]

    parts = ['%02x'%i for i in timestamp]
    date = '20' + '-'.join(parts[0:3])

    vers = bytes(version_string).rstrip(b'\0').decode()

    return date, vers, ''.join(parts[:-2])

def get_fw_header():
    # located in our own flash
    from sigheader import FLASH_HEADER_BASE_MK4, FW_HEADER_SIZE
    import uctypes

    global mk_num

    return uctypes.bytes_at(FLASH_HEADER_BASE_MK4,
                            FW_HEADER_SIZE)

def get_mpy_version():
    # read my own file header
    # see stm32/bootloader/sigheader.h

    try:
        hdr = get_fw_header()
        return decode_firmware_header(hdr)
    except:
        # this is early in boot process, so don't fail!
        return '20YY-MM-DD', '?.??', '180731121314'

def get_header_value(fld_name):
    # get a single value, raw, from header; based on field name
    from sigheader import FWH_PY_FORMAT, FWH_PY_VALUES
    import ustruct

    idx = FWH_PY_VALUES.split().index(fld_name)
    hdr = get_fw_header()

    return ustruct.unpack_from(FWH_PY_FORMAT, hdr)[idx]

def nfc_presence_check():
    # Does NFC hardware exist on this board?
    # SDA/SCL will be tied low
    from machine import Pin
    return Pin('NFC_SDA', mode=Pin.IN).value() or Pin('NFC_SCL', mode=Pin.IN).value()

def get_is_devmode():
    # what firmware signing key did we boot with? are we in dev mode?
    import ckcc
    return ckcc.is_debug_build()


def serial_number():
    # Our USB serial number, both in DFU mode (system boot ROM), and later thanks to code in
    #   USBD_StrDescriptor()
    #
    # - this is **probably** public info, since shared freely over USB during enumeration
    #
    import machine
    i = machine.unique_id()
    return "%02X%02X%02X%02X%02X%02X" % (i[11], i[10] + i[2], i[9], i[8] + i[0], i[7], i[6])

def probe_system():
    # run-once code to determine what hardware we are running on
    global hw_label, has_608, is_factory_mode, is_devmode, has_psram, is_edge
    global has_se2, mk_num, has_nfc, has_qr, num_sd_slots, has_qwerty, has_battery, supports_hsm
    global MAX_UPLOAD_LEN, MAX_TXN_LEN

    from sigheader import RAM_BOOT_FLAGS, RBF_FACTORY_MODE
    import ckcc, callgate, machine

    hw_label = 'mk4'
    has_608 = True
    nfc_presence_check()  # hardware present; they might not be using it
    has_qr = False          # QR scanner
    num_sd_slots = 1        # might have dual slots on Q1
    mk_num = 4
    has_battery = False
    has_qwerty = False
    is_edge = False
    supports_hsm = True
    has_nfc = True

    cpuid = ckcc.get_cpu_id()
    assert cpuid == 0x470  # STM32L4S5VI

    # detect Q1 based on pins.csv
    try:
        machine.Pin('LCD_TEAR')     # only defined on Q1 build, will error otherwise
        has_qr = True
        num_sd_slots = 2
        hw_label = 'q1'
        has_battery = True
        has_qwerty = True
        supports_hsm = False
        # but, still mk_num = 4
    except ValueError:
        pass

    # Boot loader needs to tell us stuff about how we were booted, sometimes:
    # - did we just install a new version, for example (obsolete in mk4)
    # - are we running in "factory mode" with flash un-secured?
    is_factory_mode = callgate.get_factory_mode()

    bn = callgate.get_bag_number()
    if bn:
        # this path supports testing/dev with RDP!=2, which normal production bootroms enforce
        is_factory_mode = False

    # what firmware signing key did we boot with? are we in dev mode?
    is_devmode = get_is_devmode()

    # newer, edge code in effect?
    is_edge = (get_mpy_version()[1][-1] == 'X')

    # increase size limits for mk4
    from public_constants import MAX_TXN_LEN_MK4, MAX_UPLOAD_LEN_MK4
    MAX_UPLOAD_LEN = MAX_UPLOAD_LEN_MK4
    MAX_TXN_LEN = MAX_TXN_LEN_MK4

probe_system()

# EOF
