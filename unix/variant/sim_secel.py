# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Fake PIN login stuff
#
# - data not really stored anywhere, except global "SECRETS" in this file
#
import ustruct, version
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
import utime as time

from uerrno import *
ERANGE = const(34)

# used by test cases
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

class SEState:
    def __init__(self):
        self.num_fails = 0
        self.attempts_left = 13

    def force_fails(self, num_fails):
        # For testing purposes (untested)
        #   sim_exec('ckcc.SE_STATE.force_fails(n)')
        assert 0 <= num_fails <= 13
        self.num_fails = num_fails
        self.attempts_left = (13 - num_fails)

    def pin_stuff(self, submethod, buf_io):
        from pincodes import (PIN_ATTEMPT_SIZE, PIN_ATTEMPT_FMT_V1, PA_ZERO_SECRET,
                            PIN_ATTEMPT_SIZE_V1, CHANGE_LS_OFFSET,
                            PA_SUCCESSFUL, PA_IS_BLANK, PA_HAS_DURESS, PA_HAS_BRICKME,
                            CHANGE_WALLET_PIN, CHANGE_DURESS_PIN, CHANGE_BRICKME_PIN,
                            AE_LONG_SECRET_LEN,
                            CHANGE_SECRET, CHANGE_DURESS_SECRET, CHANGE_SECONDARY_WALLET_PIN )

        if len(buf_io) < (PIN_ATTEMPT_SIZE if version.has_608 else PIN_ATTEMPT_SIZE_V1):
            return ERANGE

        global SECRETS

        rv = 0

        (magic, is_secondary,
                pin, pin_len,
                delay_achieved,
                delay_required,
                IGNORED_num_fails,
                IGNORED_attempts_left,
                state_flags,
                private_state,
                hmac,
                change_flags,
                old_pin, old_pin_len,
                new_pin, new_pin_len,
                secret) = ustruct.unpack_from(PIN_ATTEMPT_FMT_V1, buf_io)

        # NOTE: ignoring mk2 additions for now, we have no need for it.

        # NOTE: using strings here, not bytes; real bootrom & API, uses bytes
        pin = pin[0:pin_len].decode()
        old_pin = old_pin[0:old_pin_len].decode()
        new_pin = new_pin[0:new_pin_len].decode()

        assert not is_secondary         # mk1-3 concept not supported anymore
        kk = '_pin1'

        if submethod == 0:
            # setup
            state_flags = (PA_SUCCESSFUL | PA_IS_BLANK) if not SECRETS.get(kk, False) else 0

        elif submethod == 1:
            # delay - mk2 concept, obsolete
            time.sleep(0.05)
            delay_achieved += 1

        elif submethod == 2:
            # Login
            from variant.sim_se2 import SE2
            ts = None

            expect = SECRETS.get(kk, '')

            got = SE2.try_trick_login(pin, self.num_fails)
            if got != None:
                # good login, but it's a trick
                ts = SE2.wallet
                flags, arg = got

                delay_required = flags
                delay_achieved = arg
                state_flags = PA_SUCCESSFUL
            elif pin == expect:
                # good normal login
                state_flags = PA_SUCCESSFUL
                delay_required, delay_achieved = (0,0)
                self.attempts_left = 13
                self.num_fails = 0

                ts = a2b_hex(SECRETS.get(kk+'_secret', '00'*72))
            else:
                # failed both true PIN and trick pins (or so it seems, see FAKE_OUT)
                self.num_fails += 1
                self.attempts_left -= 1

                rv = EPIN_AUTH_FAIL

            time.sleep(0.05)

            if ts == bytes(72):
                state_flags |= PA_ZERO_SECRET

            del ts

        elif submethod == 3:
            # CHANGE pin and/or wallet secrets

            cf = change_flags

            # NOTE: this logic copied from real deal

            # must be here to do something.
            if cf == 0: return EPIN_RANGE_ERR;

            if cf & (CHANGE_BRICKME_PIN | CHANGE_DURESS_SECRET | CHANGE_SECONDARY_WALLET_PIN):
                # obsolete mk1-3 stuff
                return EPIN_BAD_REQUEST
            
            # what PIN will we change
            pk = None
            if change_flags & CHANGE_WALLET_PIN:
                pk = kk

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
                # obsolete mk1-3 stuff
                return EPIN_BAD_REQUEST

            time.sleep(0.05)

        elif submethod == 4:
            # Fetch secrets
            from sim_se2 import SE2
            duress_pin = SECRETS.get(kk+'_duress')

            secret = None

            if SE2.wallet:
                if SE2.wallet == 'delta':
                    secret = a2b_hex(SECRETS.get(kk+'_secret', '00'*72))
                else:
                    secret = SE2.wallet
            elif pin == duress_pin:
                secret = a2b_hex(SECRETS.get(kk+'_duress_secret', '00'*72))
            else:
                if change_flags & CHANGE_DURESS_SECRET:
                    # wants the duress secret
                    expect = SECRETS.get(kk, '')
                    if pin == expect:
                        secret = a2b_hex(SECRETS.get(kk+'_duress_secret', '00'*72))
                else:
                    # main/secondary secret
                    expect = SECRETS.get(kk, '')
                    if pin == expect:
                        secret = a2b_hex(SECRETS.get(kk+'_secret', '00'*72))

            if secret is None:
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
                # len(secret)==72 here, only using 32 bytes of it
                SECRETS['ls'][off:off+32] = secret[0:32]
            else:
                # Mk3 and earlier only will use this
                secret = SECRETS['ls'][off:off+32]

        elif submethod == 7:
            # pin_firmware_upgrade(args) process for mk4
            if version.mk_num < 4:
                return ENOENT

            # not implemented in simulator
            pass

        elif submethod == 8:
            # new mk4 api for long-secret fetch
            if version.mk_num < 4:
                return ENOENT

            assert len(buf_io) == PIN_ATTEMPT_SIZE + AE_LONG_SECRET_LEN, len(buf_io)
            buf_io[-AE_LONG_SECRET_LEN:] = SECRETS.get('ls', bytes(AE_LONG_SECRET_LEN))

        else:
            # bogus submethod
            return ENOENT


        hmac = b'69'*16

        ustruct.pack_into(PIN_ATTEMPT_FMT_V1, buf_io, 0, magic, is_secondary,
                pin.encode(), pin_len, delay_achieved, delay_required,
                self.num_fails, self.attempts_left,
                state_flags, private_state, hmac,
                change_flags, old_pin.encode(), old_pin_len, new_pin.encode(), new_pin_len, secret)

        return rv

