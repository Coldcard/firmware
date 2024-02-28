# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# callgate.py - thin wrapper around modckcc and the bootloader and its services.
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
    # 3=> Q1: power down after wipe
    ckcc.oneway(3, dont_clear)

def get_genuine():
    return ckcc.gate(4, None, 0)
def clear_genuine():
    ckcc.gate(4, None, 1)
def set_genuine():
    # does checksum over firmware, and might set green
    return ckcc.gate(4, None, 3)

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

def get_factory_mode():
    # are we in normal RDP=2 mode (else in factory setup time)
    arg = bytearray(1)
    ckcc.gate(19, arg, 2)
    return (arg[0] != 2)

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

    return bytes(arg)
    
def set_highwater(ts):
    arg = bytearray(ts)
    return ckcc.gate(21, arg, 2)

def has_608():
    return ckcc.gate(6, None, 0) == 0

def get_608_rev():
    # return A, B, C and so on
    config = bytearray(128)
    ckcc.gate(20, config, 0)
    if config[7] < 0x3:
        return 'A'
    if config[7] == 0x3:
        return 'B'
    if config[7] == 0x5:
        return 'C'
    return '?'

def fast_wipe(silent=True):
    # mk4: wipe seed, also reboots immediately: can stop and show a screen or not
    ckcc.oneway(23, 0xBeef if silent else 0xdead)

def fast_brick():
    # mk4: brick and reboot. Near instant. Shows brick screen.
    ckcc.oneway(24, 0xDead)

def mcu_key_usage():
    # mk4: avail/consumed/total stats, one will be in use typically
    from ustruct import unpack
    arg = bytearray(3*4)
    ckcc.gate(25, arg, 0)
    return unpack('3I', arg)

def read_rng(source=2):
    # return random bytes from a secure source
    # - first byte is # of valid random bytes
    arg = bytearray(33)
    rv = ckcc.gate(26, arg, source)
    assert not rv
    return arg[1:1+arg[0]]

def get_se_parts():
    # we know better than bootrom
    return ['ATECC608'+get_608_rev(), 'DS28C36B']
    if 0:
        # mk4: report part names
        # - gets a nul-terminated string, w/ newline between them
        arg = bytearray(80)
        rv = ckcc.gate(27, arg, 0)
        if rv:
            # happens w/ obsolete versions of bootrom that never left Toronto
            return ['SE1', 'SE2']
        ln = bytes(arg).find(b'\0')
        return arg[0:ln].decode().split('\n')
        

# EOF
