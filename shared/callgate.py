# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# callgate.py - thin wrapper around modckcc and the bootloader and it's services.
#
import ckcc

def get_bl_version():
    # version string and related details
    # something like:   ('1.0.0', [('time', '20180220.092345'), ('git', 'master@f8d1758')])
    rv = bytearray(64)
    ln = ckcc.gate(0, rv, 0)
    ver, *args = str(rv[0:ln], 'utf8').split(' ')
    return ver, [tuple(i.split('=', 1)) for i in args]
    
def get_bl_checksum(salt=0):
    # salted checksum over code
    rv = bytearray(32)
    ckcc.gate(1, rv, salt)
    return rv
    
def enter_dfu(msg=0):
    # enter DFU while showing a message
    #   0 = normal DFU
    #   1 = downgrade attack detected
    #   2 = blankish
    #   3 = i am bricked
    #
    ckcc.oneway(2, msg)

def show_logout(dont_clear=0):
    # wipe memory and die, shows standard message
    # dont_clear=1 => don't clear OLED
    # 2=> restart system after wipe
    ckcc.oneway(3, dont_clear)

def get_genuine():
    return ckcc.gate(4, None, 0)
def clear_genuine():
    ckcc.gate(4, None, 1)
def set_genuine():
    # does checksum over firmware, and might set green
    return ckcc.gate(4, None, 3)

def get_dfu_button():
    # read current state
    rv = bytearray(1)
    ckcc.gate(12, rv, 0)
    return (rv[0] == 1)

def get_bl_rng():
    # read 32 bytes of RNG (test)
    rv = bytearray(32)
    assert ckcc.gate(17, rv, 0) == 0
    return rv

def get_is_bricked():
    # see if we are a brick?
    return ckcc.gate(5, None, 0) != 0

def set_bag_number(s):
    assert 3 <= len(s) < 32
    arg = bytearray(32)     # zero pad
    arg[0:len(s)] = s
    return ckcc.gate(19, arg, 1)

def set_rdp_level(n):
    # complex hardware rules around these changes.
    assert n in {0,1,2}
    return ckcc.gate(19, None, 100+n)

def get_bag_number():
    arg = bytearray(32)
    ckcc.gate(19, arg, 0)

    if arg[0] == 0xff:
        return None

    rv = bytes(arg)
    return str(rv[0:rv.index(b'\0')], 'ascii')

def get_highwater():
    arg = bytearray(8)
    ckcc.gate(21, arg, 0)

    return arg
    
def set_highwater(ts):
    arg = bytearray(ts)
    return ckcc.gate(21, arg, 2)

# EOF
