#
#
# Test code to check crypto on 608a is doing what we think it is.
#
# Requires:
# - various fields to be known quantities, which doesn't happen in normal cases
# - JTAG (Cortex) debugger
# - non-release firmware of bootloader, and system in "factory mode"
# - code compiled to put 0x41 in secret spots of 608
#
from keylayout import KEYNUM_608 as KEYNUM
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from hmac import HMAC

keys = {}

# mdb 0x08007800 32
keys[KEYNUM.pairing] = a2b_hex(
'480d071589163dc9d6016c8af718ff0d7d4be8fa0a397745605151b423df4675')

# fixed values from instrumented version of code
for kn in [KEYNUM.pin_stretch, KEYNUM.pin_attempt, KEYNUM.words]:
    keys[kn] = bytes((0x41+kn) for i in range(32))

assert all(len(i) == 32 for i in keys.values()), repr(keys)

PURPOSE_NORMAL = a2b_hex('58184d33')
PURPOSE_WORDS  = a2b_hex('73676d2e')

KDF_ITER_WORDS      = 16
KDF_ITER_PIN        = 32

def show(lab, val):
    print('%s => \n    %s' % (lab, b2a_hex(val).decode('ascii')))

# see pin_hash in pins.c
def pin_hash(pin, purpose):
    assert len(purpose) == 4

    if len(pin) == 0:
        return bytes(32)

    md = sha256()
    md.update(keys[KEYNUM.pairing])
    md.update(purpose)
    md.update(pin)

    return sha256(md.digest()).digest()

# see ae_kdf_iter in ae.c
def ae_kdf_iter(keynum, start, iterations):

    hm = HMAC(keys[keynum], msg=start, digestmod=sha256)

    end = hm.digest()

    show('mixin(%d)' % keynum, end)

    for i in range(iterations):
        hs = HMAC(keys[KEYNUM.pin_stretch], msg=end, digestmod=sha256)
        end = hs.digest()

    show('2nd last', end)

    md = sha256()
    md.update(keys[KEYNUM.pairing])
    md.update(end)
    md.update(start)
    md.update(bytes([keynum]))

    return md.digest()


if 1:
    # for "WORDS"
    print("-- for words --")

    # on target, do this:
    #    import ckcc; b = bytearray(32); b[0:2] = b'12'; ckcc.gate(16, b, 2)
    #    from ubinascii import hexlify as b2a_hex; b2a_hex(b[:4])
    prefix = b'12'

    start = pin_hash(prefix, PURPOSE_WORDS)
    show('pin_hash(%r, WORDS)' % prefix, start)

    end = ae_kdf_iter(KEYNUM.words, start, KDF_ITER_WORDS)

    show('ae_kdf_iter()', end)

    show('words value', end[0:4])

if 1:
    # for PIN codes
    print("\n-- for PIN code --")
    # on target, do this:
    # 
    #     >>> from pincodes import PinAttempt; pa = PinAttempt(); pa.setup(b'12-12')
    #     32
    #     >>> pa.login()
    #     True
    #     >>> from ubinascii import hexlify as b2a_hex
    #     >>> b2a_hex(pa.cached_main_pin)
    #     b'75feafe5b8bfc8c255d816c6d6919f3f1b59769fcdee57174ab78044a839911f'
    # 

    pin = b'12-12'
    start = pin_hash(pin, PURPOSE_NORMAL)
    result = ae_kdf_iter(KEYNUM.pin_attempt, start, KDF_ITER_PIN);
    show('main pin', result)


