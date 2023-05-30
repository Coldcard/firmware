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
    from sigheader import FLASH_HEADER_BASE, FLASH_HEADER_BASE_MK4, FW_HEADER_SIZE
    import uctypes

    global mk_num

    return uctypes.bytes_at(FLASH_HEADER_BASE_MK4 if mk_num == 4 else FLASH_HEADER_BASE,
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

    if mk_num == 4:
        # mk4: are we built differently?
        import ckcc
        return ckcc.is_debug_build()

    from sigheader import RAM_HEADER_BASE, FWH_PK_NUM_OFFSET
    import stm

    # Important? Use the RAM version of this, not flash version!
    kn = stm.mem32[RAM_HEADER_BASE + FWH_PK_NUM_OFFSET]

    # For now, all keys are "production" except number zero, which will be made public
    # - some other keys may be de-authorized and so on in the future
    is_devmode = (kn == 0)

    return is_devmode


def is_fresh_version():
    # Did we just boot into a new firmware for the first time?
    # - mk4+ does not use this approach, light will be solid green during upgrade
    if mk_num >= 4: return False

    from sigheader import RAM_BOOT_FLAGS, RBF_FRESH_VERSION
    import stm

    flags = stm.mem32[RAM_BOOT_FLAGS]

    return bool(flags & RBF_FRESH_VERSION)


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
    global hw_label, has_608, has_fatram, is_factory_mode, is_devmode, has_psram
    global has_se2, mk_num, has_nfc, has_qr, num_sd_slots, has_qwerty, has_battery, is_edge
    global MAX_UPLOAD_LEN, MAX_TXN_LEN

    from sigheader import RAM_BOOT_FLAGS, RBF_FACTORY_MODE
    import ckcc, callgate, stm
    from machine import Pin

    # NOTE: mk1 not supported anymore.
    # PA10 is pulled-down in Mark2, open in previous revs
    #mark2 = (Pin('MARK2', Pin.IN, pull=Pin.PULL_UP).value() == 0)

    hw_label = 'mk2'
    has_fatram = False
    has_psram = False
    has_608 = True
    has_se2 = False
    has_nfc = False         # hardware present; they might not be using it
    has_qr = False          # QR scanner
    num_sd_slots = 1        # might have dual slots on Q1
    mk_num = 2
    has_battery = False
    has_qwerty = False
    is_edge = False

    cpuid = ckcc.get_cpu_id()
    if cpuid == 0x461:      # STM32L496RG6
        hw_label = 'mk3'
        has_fatram = True
        mk_num = 3
    elif cpuid == 0x470:    # STM32L4S5VI
        hw_label = 'mk4'
        has_fatram = True
        has_psram = True
        has_se2 = True
        mk_num = 4
        has_nfc = nfc_presence_check()
    else:
        # mark 2
        has_608 = callgate.has_608()

    # detect Q1 based on pins.csv
    try:
        Pin('LCD_TEAR')     # only defined on Q1 build, will error otherwise
        has_qr = True
        num_sd_slots = 2
        hw_label = 'q1'
        has_battery = True
        has_qwerty = True
        # but, still mk_num = 4
    except ValueError:
        pass

    # Boot loader needs to tell us stuff about how we were booted, sometimes:
    # - did we just install a new version, for example (obsolete in mk4)
    # - are we running in "factory mode" with flash un-secured?
    if mk_num < 4:
        is_factory_mode = bool(stm.mem32[RAM_BOOT_FLAGS] & RBF_FACTORY_MODE)
    else:
        is_factory_mode = callgate.get_factory_mode()

    bn = callgate.get_bag_number()
    if bn:
        # this path supports testing/dev with RDP!=2, which normal production bootroms enforce
        is_factory_mode = False

    # what firmware signing key did we boot with? are we in dev mode?
    is_devmode = get_is_devmode()

    # increase size limits for mk4
    if has_psram:
        from public_constants import MAX_TXN_LEN_MK4, MAX_UPLOAD_LEN_MK4
        MAX_UPLOAD_LEN = MAX_UPLOAD_LEN_MK4
        MAX_TXN_LEN = MAX_TXN_LEN_MK4

probe_system()

# EOF
