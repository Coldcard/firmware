# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# version.py - Get lots of different version numbers from stuff.
#
# REMINDER: update simulator version of this file if API changes are made.
#

def get_mpy_version():
    # read my own file header
    # see stm32/bootloader/sigheader.h
    from sigheader import FLASH_HEADER_BASE, FW_HEADER_SIZE, FWH_PY_FORMAT
    import ustruct, uctypes

    try:
        # located in flash, but could also use RAM version
        hdr = uctypes.bytes_at(FLASH_HEADER_BASE, FW_HEADER_SIZE)

        magic_value, timestamp, version_string = ustruct.unpack_from(FWH_PY_FORMAT, hdr)[0:3]

        parts = ['%02x'%i for i in timestamp]
        date = '20' + '-'.join(parts[0:3])

        vers = bytes(version_string).rstrip(b'\0').decode()

        return date, vers, ''.join(parts[:-2])
    except:
        # this is early in boot process, so don't fail!
        return '20YY-MM-DD', '?.??', '180731121314'

def get_header_value(fld_name):
    # get a single value, raw, from header; based on field name
    from sigheader import FLASH_HEADER_BASE, FW_HEADER_SIZE, FWH_PY_FORMAT, FWH_PY_VALUES
    import ustruct, uctypes

    idx = FWH_PY_VALUES.split().index(fld_name)

    hdr = uctypes.bytes_at(FLASH_HEADER_BASE, FW_HEADER_SIZE)

    return ustruct.unpack_from(FWH_PY_FORMAT, hdr)[idx]

def is_devmode():
    # what firmware signing key did we boot with? are we in dev mode?
    from sigheader import RAM_HEADER_BASE, FWH_PK_NUM_OFFSET
    import stm

    # Important? Use the RAM version of this, not flash version!
    kn = stm.mem32[RAM_HEADER_BASE + FWH_PK_NUM_OFFSET]

    # For now, all keys are "production" except number zero, which will be made public
    # - some other keys may be de-authorized and so on in the future
    is_devmode = (kn == 0)

    return is_devmode

# Boot loader needs to tell us stuff about how we were booted, sometimes:
# - did we just install a new version, for example
# - are we running in "factory mode" with flash un-secured?

def is_factory_mode():
    from sigheader import RAM_BOOT_FLAGS, RBF_FACTORY_MODE
    import stm, callgate

    is_factory = bool(stm.mem32[RAM_BOOT_FLAGS] & RBF_FACTORY_MODE)

    bn = callgate.get_bag_number()
    if bn:
        # this path supports testing/dev with RDP!=2, which normal production bootroms enforce
        is_factory = False

    return is_factory

def is_fresh_version():
    from sigheader import RAM_BOOT_FLAGS, RBF_FRESH_VERSION
    import stm

    flags = stm.mem32[RAM_BOOT_FLAGS]

    return bool(flags & RBF_FRESH_VERSION)


def serial_number():
    # Our USB serial number, both in DFU mode (system boot ROM), and later thanks to code in
    #   USBD_StrDescriptor()
    #
    # - this is **completely** public info, since we can be booted into DFU mode by any anybody
    #
    import machine
    i = machine.unique_id()
    return "%02X%02X%02X%02X%02X%02X" % (i[11], i[10] + i[2], i[9], i[8] + i[0], i[7], i[6])

def probe_system():
    # run-once code to determine what hardware we are running on
    global has_membrane, hw_label, has_608

    import ckcc, callgate
    from machine import Pin

    # PA10 is pulled-down in Mark2, open in previous revs
    mark2 = (Pin('MARK2', Pin.IN, pull=Pin.PULL_UP).value() == 0)

    if not mark2:
        has_membrane = False
        hw_label = 'mk1'
    else:
        has_membrane = True
        hw_label = 'mk2'

    if ckcc.is_stm32l496():
        hw_label = 'mk3'

    has_608 = callgate.has_608()

probe_system()

# EOF
