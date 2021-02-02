#
# Replacement for modckcc.c and complexity of the bootloader.
#
# REMINDER: you must recompile coldcard-mpy if you change this file!
#
import ustruct
#from ubinascii import hexlify as b2a_hex
#from ubinascii import unhexlify as a2b_hex
#import utime as time

from uerrno import *
ERANGE = const(34)

rng_fd = open('/dev/urandom', 'rb')

# Emulate the red/green LED
import sys
global genuine_led
try:
    led_pipe = open(int(sys.argv[3]), 'wb')
    led_pipe.write(b'\x01')
except:
    pass
genuine_led = True

if 1:
    # remove pauses that lengthen test case times...
    async def no_drama(msg, seconds):
        print("Pause (%ds): %s" % (seconds, msg))
    import ux
    ux.ux_dramatic_pause = no_drama
        
# HACK: reduce size of heap in Unix simulator to be more similar to 
# actual hardware, so we can enjoy those out-of-memory errors too!
# target, post boot: 25376 bytes
# - not entirely fair because our pointers may be 64bit
# - heap for unix port defined (in unix/main.c) to be 1M * ptr size bytes
# - arm version seems to be able to handle much lower heap size??
# - unix is not freezing the main code, so those bytecodes take major memory
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
        return pin_prefix(buf_io[0:arg2], buf_io)

    if method == 18:
        from sim_secel import pin_stuff
        return pin_stuff(arg2, buf_io)

    if method == 4:
        # control the green/red light
        global genuine_led
        if arg2 == 1:
            # clear it
            genuine_led = False
            led_pipe.write(bytes([0x10]))
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
            return buf_io

    if method == 21:
        # high water mark
        if arg2 == 0:
            buf_io[0:8] = b'\x18\x07\x11\x19S\x08\x00\x00'
        return 0

    if method == 20:
        # read 608 config bytes (128)
        assert len(buf_io) == 128
        buf_io[:] = b'\x01#\xbf\x0b\x00\x00`\x03CP,\xbf\xeeap\x00\xe1\x00a\x00\x00\x00\x8f-\x8f\x80\x8fC\xaf\x80\x00C\x00C\x8fG\xc3C\xc3C\xc7G\x00G\x00\x00\x8fM\x8fC\x00\x00\x00\x00\x1f\xff\x00\x1a\x00\x1a\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xea\xff\x02\x15\x00\x00\x00\x00<\x00\\\x00\xbc\x01\xfc\x01\xbc\x01\x9c\x01\x9c\x01\xfc\x01\xdc\x03\xdc\x03\xdc\x07\x9c\x01<\x00\xfc\x01\xdc\x01<\x00'
        return 0

    return ENOENT

def oneway(method, arg2):

    print("\n\nNOTE: One-way callgate into bootloader: method=%d arg2=%d\n\n" % (method, arg2))
    raise SystemExit

def is_simulator():
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

def is_stm32l496():
    return ('--mk2' not in sys.argv)


# EOF
