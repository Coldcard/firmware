# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Replacement for modckcc.c and complexity of the bootloader.
#
# REMINDER: you must recompile coldcard-mpy if you change this file!
#
import ustruct, sys, uasyncio, utime
from ubinascii import hexlify as b2a_hex
#from ubinascii import unhexlify as a2b_hex

from uerrno import *
ERANGE = const(34)

rng_fd = open('/dev/urandom', 'rb')

# Emulate the red/green LED
global genuine_led
led_pipe = open(int(sys.argv[3]), 'wb')
led_pipe.write(b'\xff\x01')     # all off, except SE1 green
genuine_led = True

# State of SE1/SE2/bootrom
from sim_secel import SEState
SE_STATE = SEState()

# Provide a way to dump few hundred/4k bytes of data from QR or NFC simulated read
data_pipe = uasyncio.StreamReader(open(int(sys.argv[4]), 'rb'))
        
# HACK: reduce size of heap in Unix simulator to be more similar to 
# actual hardware, so we can enjoy those out-of-memory errors too!
# target, post boot: 25376 bytes [mk3]
# - not entirely fair because our pointers may be 64bit
# - heap for unix port defined (in unix/main.c) to be 1M * ptr size bytes
# - arm version seems to be able to handle much lower heap size??
# - unix is not freezing the main code, so those bytecodes take major memory
# - mk4: over 500k of space after boot anyway!!! Yeah!
#balloon = bytearray(700*1024)

# patch in monitoring of text on screen
if 1:
    import sim_display


###  remainder should be module functions from real ckcc  ###

def rng():
    # return 30 bit random number
    return ustruct.unpack('I', rng_fd.read(4))[0] >> 2

def rng_bytes(buf):
    # Fill a buffer with random bits; caller must provide sized buffer
    actual = rng_fd.readinto(buf)
    assert actual == len(buf)

def pin_prefix(pin, buf_out):
    # return 4 bytes (32-bit number)
    # real thing is nothing like this!
    from uhashlib import sha256

    buf_out[0:4] = sha256(pin).digest()[0:4]

    return 0

def gate(method, buf_io, arg2):
    # the "callgate" into the bootloader
    import version

    # - only spuratically implemented (say it like in _Clueless_)
    # - none of the error checking is repeated here
    # - not trying too hard to fake the hardware-related features

    if method == 0:
        # version string
        hc = b'2.0.0 time=20180220.092345 git=master@f8d1758'
        buf_io[0:len(hc)] = hc
        return len(hc)

    if method == 16:
        if len(buf_io) < 8: return ERANGE
        utime.sleep_ms(500)     # because is slow in real world
        return pin_prefix(buf_io[0:arg2], buf_io)

    if method == 18:
        return SE_STATE.pin_stuff(arg2, buf_io)

    if method == 4:
        # control the green/red light
        global genuine_led
        if arg2 == 1:
            # clear it
            genuine_led = False
            led_pipe.write(b'\x01\x00')
        if arg2 == 3:
            # real code would do checksum then go green
            genuine_led = True
            led_pipe.write(b'\x01\x01')
        return 1 if genuine_led else 0

    if method == 5:
        # are we a brick? No.
        return 0

    if method == 6:
        # do we have 608?
        return ENOENT if not version.has_608 else 0

    if method == 19:
        # bag number
        if arg2 == 0:
            buf_io[0:32] = b'CSIM0000' + b'\0'*(32-8)
        if arg2 == 1:
            # not supported: write
            print("Write BAG NUMBER: %r" % buf_io)
            return 0
        if arg2 == 2:
            # query RDP level, ie. in factory mode?
            buf_io[0] = 0xff if ('-f' in sys.argv) else 2

    if method == 21:
        # high water mark
        if arg2 == 0:
            #buf_io[0:8] = b'\x18\x07\x11\x19S\x08\x00\x00'
            #buf_io[0:8] = b'!\x04)\x21\'"\x00\x00'
            buf_io[0:8] = b'!\x03)\x19\'"\x00\x00'
            #buf_io[0:8] = bytes(8)
        elif arg2 == 2:
            print("New highwater: %s" % b2a_hex(buf_io[0:8]))
        return 0

    if method == 20:
        # read 608 config bytes (128)
        assert len(buf_io) == 128
        buf_io[:] = b'\x01#\xbf\x0b\x00\x00`\x04CP,\xbf\xeeap\x00\xe1\x00a\x00\x00\x00\x8f-\x8f\x80\x8fC\xaf\x80\x00C\x00C\x8fG\xc3C\xc3C\xc7G\x00G\x00\x00\x8fM\x8fC\x00\x00\x00\x00\x1f\xff\x00\x1a\x00\x1a\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xea\xff\x02\x15\x00\x00\x00\x00<\x00\\\x00\xbc\x01\xfc\x01\xbc\x01\x9c\x01\x9c\x01\xfc\x01\xdc\x03\xdc\x03\xdc\x07\x9c\x01<\x00\xfc\x01\xdc\x01<\x00'
        return 0

    if method == 22 and version.has_se2:
        # trick pin actions
        from sim_se2 import SE2
        return SE2.callgate(buf_io, arg2)

    if method == 23:
        # fast wipe 
        if not version.has_se2:
            return ENOENT
        if arg2 == 0xBeef:
            # silent version, but does reset system
            print("silent wipe of secret & reset")
        elif arg2 == 0xDead:
            # noisy, shows screen, halts
            print("wipes secret and die w/ screen: Seed Wiped")
        return EPERM

    if method == 24:
        # fast brick -- locks up w/ message
        if not version.has_se2:
            return ENOENT
        if arg2 == 0xDead:
            print("Fast brick")
            return 0
        else:
            return EPERM

    if method == 25:
        # mcu_key_usage
        N = 256
        ustruct.pack_into('3I', buf_io, 0,  N-5, 1, N)
        return 0

    if method == 26:
        # read RNG (not) from SE (not)
        if arg2 == 1:
            buf_io[0] = 32
            buf_io[1:1+32] = bytes(range(32))
        elif arg2 == 2:
            buf_io[0] = 8
            buf_io[1:1+8] = bytes(range(8))
        else:
            return ERANGE;
        return 0

    if method == 27:
        buf_io[:] = b'ATECC608B\nDS28C36B\0'
        return 0

    return ENOENT

def oneway(method, arg2):

    # TODO: capture method/arg2 into an object so unit tests can read it back while we are dead

    print("\n\nNOTE: One-way callgate into bootloader: method=%d arg2=%d\n\n" % (method, arg2))
    while 1:
        utime.sleep(60)

def is_simulator():
    return True

def is_debug_build():
    return True


def get_sim_root_dirs():
    # return a single path and list of files to pretend to find there
    import ffilib, os
    libc = ffilib.libc()

    b = bytearray(500)
    cwd = libc.func("s", "getcwd", "pi")(b, len(b))
    assert cwd

    return cwd, cwd+'/MicroSD'

def presume_green():
    global genuine_led
    assert genuine_led == True

def breakpoint():
    raise SystemExit

def watchpoint():
    pass

def vcp_enabled(_):
    return True

def usb_active():
    pass

def get_cpi_id():
    if ('--mk2' in sys.argv):
        return 0x2222       # don't know
    if ('--mk3' in sys.argv):
        return 0x461       # STM32L496RG6
    if ('--mk4' in sys.argv):
        return 0x470       # STM32L4S5
    if ('--q1' in sys.argv):
        return 0x470       # STM32L4S5

    #default mk4
    return 0x470       # STM32L4S5

def lcd_blast(buf):
    # sends to LCD
    return

# EOF
