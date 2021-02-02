#
# Fake PIN login stuff
#
# - any pin starting with '77' will delay for # of seconds defined in suffix of PIN
# - data not really stored anywhere, except global "SECRETS" in this file
# - do any pin with '88'  prefix, and will jump to just 2 chances left
#
import ustruct, version
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
import utime as time

from uerrno import *
ERANGE = const(34)

global SECRETS
SECRETS = {}

EPIN_HMAC_FAIL       = const(-100)
EPIN_HMAC_REQUIRED   = const(-101)
EPIN_BAD_MAGIC       = const(-102)
EPIN_RANGE_ERR       = const(-103)
EPIN_BAD_REQUEST     = const(-104)
EPIN_I_AM_BRICK      = const(-105)
EPIN_AE_FAIL         = const(-106)
EPIN_MUST_WAIT       = const(-107)
EPIN_PIN_REQUIRED    = const(-108)
EPIN_WRONG_SUCCESS   = const(-109)
EPIN_OLD_ATTEMPT     = const(-110)
EPIN_AUTH_MISMATCH   = const(-111)
EPIN_AUTH_FAIL       = const(-112)
EPIN_OLD_AUTH_FAIL   = const(-113)
EPIN_PRIMARY_ONLY    = const(-114)


def pin_stuff(submethod, buf_io):
    from pincodes import (PIN_ATTEMPT_SIZE, PIN_ATTEMPT_FMT_V1, PA_ZERO_SECRET,
                        PIN_ATTEMPT_SIZE_V1, CHANGE_LS_OFFSET,
                        PA_SUCCESSFUL, PA_IS_BLANK, PA_HAS_DURESS, PA_HAS_BRICKME,
                        CHANGE_WALLET_PIN, CHANGE_DURESS_PIN, CHANGE_BRICKME_PIN,
                        CHANGE_SECRET, CHANGE_DURESS_SECRET, CHANGE_SECONDARY_WALLET_PIN )

    if len(buf_io) != (PIN_ATTEMPT_SIZE if version.has_608 else PIN_ATTEMPT_SIZE_V1):
        return ERANGE

    global SECRETS

    (magic, is_secondary,
            pin, pin_len,
            delay_achieved,
            delay_required,
            num_fails,
            attempts_left,
            state_flags,
            private_state,
            hmac,
            change_flags,
            old_pin, old_pin_len,
            new_pin, new_pin_len,
            secret) = ustruct.unpack_from(PIN_ATTEMPT_FMT_V1, buf_io)

    # NOTE: ignoring mk2 additions for now, we have no need for it.

    # NOTE: using strings here, not bytes; real bootrom uses bytes
    pin = pin[0:pin_len].decode()
    old_pin = old_pin[0:old_pin_len].decode()
    new_pin = new_pin[0:new_pin_len].decode()

    kk = '_pin1' if not is_secondary else '_pin2'

    if submethod == 0:
        # setup
        state_flags = (PA_SUCCESSFUL | PA_IS_BLANK) if not SECRETS.get(kk, False) else 0

        if pin.startswith('77'):
            delay_required = int(pin.split('-')[1]) * 2
            num_fails = 3
        if pin.startswith('88'):
            attempts_left = 2
            num_fails = 11

        if version.has_608:
            attempts_left = 13
            num_fails = 0
            if 0:       # XXX  test
                num_fails = 10
                attempts_left = 3

    elif submethod == 1:
        # delay
        time.sleep(0.500)
        delay_achieved += 1

    elif submethod == 2:
        # Login

        expect = SECRETS.get(kk, '')
        if pin == expect:
            state_flags = PA_SUCCESSFUL

            ts = a2b_hex(SECRETS.get(kk+'_secret', '00'*72))

        elif pin == SECRETS.get(kk + '_duress', None):
            state_flags = PA_SUCCESSFUL

            ts = a2b_hex(SECRETS.get(kk+'_duress_secret', '00'*72))

        else:
            if version.has_608:
                num_fails += 1
                attempts_left -= 1
            else:
                state_flags = 0

            return EPIN_AUTH_FAIL

        time.sleep(0.5)

        if ts == b'\0'*72:
            state_flags |= PA_ZERO_SECRET

        if kk+'_duress' in SECRETS:
            state_flags |= PA_HAS_DURESS
        if kk+'_brickme' in SECRETS:
            state_flags |= PA_HAS_BRICKME

        del ts

    elif submethod == 3:
        # CHANGE pin and/or wallet secrets

        cf = change_flags

        # NOTE: this logic copied from real deal

        # must be here to do something.
        if cf == 0: return EPIN_RANGE_ERR;

        if cf & CHANGE_BRICKME_PIN:
            if is_secondary:
                # only main PIN holder can define brickme PIN
                return EPIN_PRIMARY_ONLY
            if cf != CHANGE_BRICKME_PIN:
                # only pin can be changed, nothing else.
                return EPIN_BAD_REQUEST

        if (cf & CHANGE_DURESS_SECRET) and (cf & CHANGE_SECRET):
            # can't change two secrets at once.
            return EPIN_BAD_REQUEST

        if (cf & CHANGE_SECONDARY_WALLET_PIN):
            if is_secondary:
                # only main user uses this call 
                return EPIN_BAD_REQUEST;

            if (cf != CHANGE_SECONDARY_WALLET_PIN):
                # only changing PIN, no secret-setting
                return EPIN_BAD_REQUEST;

            kk = '_pin2'

        
        # what PIN will we change
        pk = None
        if change_flags & (CHANGE_WALLET_PIN | CHANGE_SECONDARY_WALLET_PIN):
            pk = kk
        if change_flags & CHANGE_DURESS_PIN:
            pk = kk+'_duress'
        if change_flags & CHANGE_BRICKME_PIN:
            pk = kk+'_brickme'

        if pin == SECRETS.get(kk + '_duress', None):
            # acting duress mode... let them only change duress pin
            if pk == kk:
                pk = kk+'_duress'
            else:
                return EPIN_OLD_AUTH_FAIL

        if pk != None:
            # Must match old pin correctly, if it is defined.
            if SECRETS.get(pk, '') != old_pin:
                print("secel: wrong OLD pin (expect %s, got %s)" % (SECRETS[pk], old_pin))
                return EPIN_OLD_AUTH_FAIL

            # make change
            SECRETS[pk] = new_pin

            if not new_pin and pk != kk:
                del SECRETS[pk]

        if change_flags & CHANGE_SECRET:
            SECRETS[kk+'_secret'] = str(b2a_hex(secret), 'ascii')
        if change_flags & CHANGE_DURESS_SECRET:
            SECRETS[kk+'_duress_secret'] = str(b2a_hex(secret), 'ascii')

        time.sleep(1.5)

    elif submethod == 4:
        # Fetch secrets
        duress_pin = SECRETS.get(kk+'_duress')

        if pin == duress_pin:
            secret = a2b_hex(SECRETS.get(kk+'_duress_secret', '00'*72))
        else:
            # main/sec secrets
            expect = SECRETS.get(kk, '')
            if pin == expect:
                secret = a2b_hex(SECRETS.get(kk+'_secret', '00'*72))
            else:
                return EPIN_AUTH_FAIL

    elif submethod == 5:
        # greenlight firmware
        from ckcc import genuine_led, led_pipe
        genuine_led = True
        led_pipe.write(b'\x01')

    elif submethod == 6:
        if not version.has_608:
            return ENOENT

        # long secret read/change.
        cf = change_flags
        assert CHANGE_LS_OFFSET == 0xf00
        blk = (cf >> 8) & 0xf
        if blk > 13: return EPIN_RANGE_ERR
        off = blk * 32

        if 'ls' not in SECRETS:
            SECRETS['ls'] = bytearray(416)

        if (cf & CHANGE_SECRET):
            SECRETS['ls'][off:off+32] = secret
        else:
            secret = SECRETS['ls'][off:off+32]

    else:
        # bogus submethod
        return ENOENT


    hmac = b'69'*16

    ustruct.pack_into(PIN_ATTEMPT_FMT_V1, buf_io, 0, magic, is_secondary,
            pin.encode(), pin_len, delay_achieved, delay_required,
            num_fails, attempts_left,
            state_flags, private_state, hmac,
            change_flags, old_pin.encode(), old_pin_len, new_pin.encode(), new_pin_len, secret)

    return 0

