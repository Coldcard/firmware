# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# pincodes.py - manage PIN code (which map to wallet seeds)
#
import ustruct, ckcc, version
from ubinascii import hexlify as b2a_hex
from callgate import enter_dfu
from bip39 import wordlist_en

# See ../stm32/bootloader/pins.h for source of these constants.
#
MAX_PIN_LEN = const(32)

# how many bytes per secret (you don't have to use them all)
AE_SECRET_LEN = const(72)

# on mark3 (608a) we can also store a longer secret
AE_LONG_SECRET_LEN = const(416)

# magic number for struct
PA_MAGIC_V1    = const(0x2eaf6311)
PA_MAGIC_V2    = const(0x2eaf6312)

# For state_flags field: report only covers current wallet (primary vs. secondary)
PA_SUCCESSFUL         = const(0x01)
PA_IS_BLANK           = const(0x02)
PA_HAS_DURESS         = const(0x04)
PA_HAS_BRICKME        = const(0x08)
PA_ZERO_SECRET        = const(0x10)

# For change_flags field:
CHANGE_WALLET_PIN           = const(0x001)
CHANGE_DURESS_PIN           = const(0x002)
CHANGE_BRICKME_PIN          = const(0x004)
CHANGE_SECRET               = const(0x008)
CHANGE_DURESS_SECRET        = const(0x010)
CHANGE_SECONDARY_WALLET_PIN = const(0x020)
CHANGE_FIRMWARE             = const(0x040)      # Mk4+
CHANGE_LS_OFFSET            = const(0xf00)

# See below for other direction as well.
PA_ERROR_CODES = {
     -100: "HMAC_FAIL",
     -101: "HMAC_REQUIRED",
     -102: "BAD_MAGIC",
     -103: "RANGE_ERR",
     -104: "BAD_REQUEST",
     -105: "I_AM_BRICK",
     -106: "AE_FAIL",           # SE1 on Mk4
     -107: "MUST_WAIT",
     -108: "PIN_REQUIRED",
     -109: "WRONG_SUCCESS",
     -110: "OLD_ATTEMPT",
     -111: "AUTH_MISMATCH",
     -112: "AUTH_FAIL",
     -113: "OLD_AUTH_FAIL",
     -114: "PRIMARY_ONLY",
     -115: "SE2_FAIL",
}

# just a few of the likely ones; non-programing errors
EPIN_I_AM_BRICK     = const(-105)
EPIN_MUST_WAIT      = const(-107)
EPIN_PIN_REQUIRED   = const(-108)
EPIN_WRONG_SUCCESS  = const(-109)
EPIN_OLD_ATTEMPT    = const(-110)
EPIN_AUTH_MISMATCH  = const(-111)
EPIN_AUTH_FAIL      = const(-112)
EPIN_OLD_AUTH_FAIL  = const(-113)

# We are round-tripping this big structure, partially signed by bootloader.
'''
    uint32_t    magic_value;            // = PA_MAGIC_V2 or V1 for older bootroms
    int         is_secondary;           // (bool) primary or secondary
    char        pin[MAX_PIN_LEN];       // value being attempted
    int         pin_len;                // valid length of pin
    uint32_t    delay_achieved;         // so far, how much time wasted? [508a only]
    uint32_t    delay_required;         // how much will be needed? [508a only]
    uint32_t    num_fails;              // for UI: number of fails PINs
    uint32_t    attempts_left;          // trys left until bricking [608a only]
    uint32_t    state_flags;            // what things have been setup/enabled already
    uint32_t    private_state;          // some internal (encrypted) state
    uint8_t     hmac[32];               // bootloader's hmac over above, or zeros
    // remaining fields are return values, or optional args;
    int         change_flags;           // bitmask of what to do
    char        old_pin[MAX_PIN_LEN];   // (optional) old PIN value
    int         old_pin_len;            // (optional) valid length of old_pin, can be zero
    char        new_pin[MAX_PIN_LEN];   // (optional) new PIN value
    int         new_pin_len;            // (optional) valid length of new_pin, can be zero
    uint8_t     secret[72];             // secret to be changed OR return value
    // may grow from here in future versions (V1 bootroms don't expect more)
    uint8_t     cached_main_pin[32];    // iff they provided right pin already (V2)
'''
PIN_ATTEMPT_FMT_V1 = 'Ii32si6I32si32si32si72s'
PIN_ATTEMPT_FMT_V2_ADDITIONS = '32s'

PIN_ATTEMPT_SIZE_V1  = const(248)
PIN_ATTEMPT_SIZE  = const(248+32)

# small cache of pin-prefix to words, for 608a based systems
_word_cache = []

class BootloaderError(RuntimeError):
    pass

class PinAttempt:
    seconds_per_tick = 0.5

    def __init__(self):
        self.is_secondary = False
        self.pin = None
        self.secret = None
        self.is_empty = None
        self.tmp_value = False          # simulated SE, in-ram only
        self.magic_value = PA_MAGIC_V2 if version.has_608 else PA_MAGIC_V1
        self.delay_achieved = 0         # so far, how much time wasted?: mk4: tc_arg
        self.delay_required = 0         # how much will be needed?  mk4: tc_flags
        self.num_fails = 0              # for UI: number of fails PINs
        self.attempts_left = 0          # ignore in mk1/2 case, only valid for mk3
        self.state_flags = 0            # useful readback
        self.private_state = 0          # opaque data, but preserve
        self.cached_main_pin = bytearray(32)


        assert MAX_PIN_LEN == 32        # update FMT otherwise
        assert ustruct.calcsize(PIN_ATTEMPT_FMT_V1) == PIN_ATTEMPT_SIZE_V1, \
                            ustruct.calcsize(PIN_ATTEMPT_FMT)
        assert ustruct.calcsize(PIN_ATTEMPT_FMT_V2_ADDITIONS) == PIN_ATTEMPT_SIZE - PIN_ATTEMPT_SIZE_V1

        # check for bricked system early
        import callgate
        if callgate.get_is_bricked():
            # die right away if it's not going to work
            print("SE bricked")
            callgate.enter_dfu(3)

    def __repr__(self):
        return '<PinAttempt: fails/left=%d/%d tc_flag/arg=0x%x/0x%x>' % (
                        self.num_fails, self.attempts_left,
                        self.delay_required, self.delay_achieved)

    def marshal(self, msg, is_duress=False, is_brickme=False, new_secret=None, 
                    new_pin=None, old_pin=None, get_duress_secret=False, is_secondary=False,
                    ls_offset=None, fw_upgrade=None, spare_num=None
            ):
        # serialize our state, and maybe some arguments
        change_flags = 0

        if new_secret is not None:
            change_flags |= CHANGE_SECRET if not is_duress else CHANGE_DURESS_SECRET
            assert len(new_secret) in (32, AE_SECRET_LEN)
            import stash
            stash.SensitiveValues.clear_cache()
        else:
            new_secret = bytes(AE_SECRET_LEN)

        # NOTE: pins should be bytes here.

        if get_duress_secret:
            # special case for reading duress secret from main wallet
            change_flags |= CHANGE_DURESS_SECRET 

        if new_pin is not None:
            if is_duress:
                change_flags |= CHANGE_DURESS_PIN
            elif is_brickme:
                change_flags |= CHANGE_BRICKME_PIN
            elif is_secondary:
                change_flags |= CHANGE_SECONDARY_WALLET_PIN
            else:
                change_flags |= CHANGE_WALLET_PIN
                assert not old_pin or old_pin == self.pin
                old_pin = self.pin

            assert len(new_pin) <= MAX_PIN_LEN
            assert old_pin != None
            assert len(old_pin) <= MAX_PIN_LEN
        else:
            new_pin = b''
            old_pin = old_pin if old_pin is not None else self.pin

        if ls_offset is not None:
            change_flags |= (ls_offset << 8)        # see CHANGE_LS_OFFSET
        if spare_num is not None:
            assert 0 <= spare_num <= 3
            change_flags |= (spare_num << 8)        # useful for fetch/change secret on Mk4

        if fw_upgrade:
            change_flags = CHANGE_FIRMWARE
            new_secret = ustruct.pack('2I', *fw_upgrade) + bytes(AE_SECRET_LEN-8)

        # can't send the V2 extra stuff if the bootrom isn't expecting it
        fields = [self.magic_value,
                    (1 if self.is_secondary else 0),
                    self.pin, len(self.pin),
                    self.delay_achieved,
                    self.delay_required,
                    self.num_fails,
                    self.attempts_left,
                    self.state_flags,
                    self.private_state,
                    self.hmac,
                    change_flags,
                    old_pin, len(old_pin),
                    new_pin, len(new_pin),
                    new_secret]

        if version.has_608:
            fmt = PIN_ATTEMPT_FMT_V1 + PIN_ATTEMPT_FMT_V2_ADDITIONS
            fields.append(self.cached_main_pin)
        else:
            fmt = PIN_ATTEMPT_FMT_V1

        ustruct.pack_into(fmt, msg, 0, *fields)

    def unmarshal(self, msg):
        # unpack it and update our state, return other state
        x = ustruct.unpack_from(PIN_ATTEMPT_FMT_V1, msg)
        
        (self.magic_value, was_secondary,
                self.pin, pin_len,
                self.delay_achieved,
                self.delay_required,
                self.num_fails,
                self.attempts_left,
                self.state_flags,
                self.private_state,
                self.hmac,
                change_flags,
                old_pin, old_pin_len,
                new_pin, new_pin_len,
                secret) = x

        # NOTE: not useful to readback values we sent and it never updates
        #new_pin = new_pin[0:new_pin_len]
        #old_pin = old_pin[0:old_pin_len]
        self.pin = self.pin[0:pin_len]

        if self.magic_value == PA_MAGIC_V2:
            # pull out V2 extra values 
            self.cached_main_pin, = ustruct.unpack_from(PIN_ATTEMPT_FMT_V2_ADDITIONS,
                                                            msg, PIN_ATTEMPT_SIZE_V1)

        return secret

    def roundtrip(self, method_num, after_buf=None, **kws):

        buf = bytearray(PIN_ATTEMPT_SIZE if version.has_608 else PIN_ATTEMPT_SIZE_V1)

        self.marshal(buf, **kws)

        if after_buf is not None:
            buf.extend(after_buf)

        #print("> tx: %s" % b2a_hex(buf))

        err = ckcc.gate(18, buf, method_num)

        #print("[%d] rx: %s" % (err, b2a_hex(buf)))
        
        if err <= -100:
            #print("[%d] req: %s" % (err, b2a_hex(buf)))
            if err == EPIN_I_AM_BRICK:
                # don't try to continue!
                enter_dfu(3)
            raise BootloaderError(PA_ERROR_CODES[err], err)
        elif err:
            raise RuntimeError(err)

        if after_buf is not None:
            return buf[PIN_ATTEMPT_SIZE:]
        else:
            return self.unmarshal(buf)

    @staticmethod
    def prefix_words(pin_prefix):
        # take a prefix of the PIN and turn it into a few
        # bip39 words for anti-phishing protection
        assert 1 <= len(pin_prefix) <= MAX_PIN_LEN, len(pin_prefix)
        global _word_cache

        if version.has_608:
            for k,v in _word_cache:
                if pin_prefix == k:
                    return v

        buf = bytearray(pin_prefix + b'\0'*MAX_PIN_LEN)
        err = ckcc.gate(16, buf, len(pin_prefix))
        if err:
            raise RuntimeError(err)

        # use just 22 bits of that
        bits = ustruct.unpack('I', buf[0:4])[0]
        w1 = (bits >> 11) & 0x7ff
        w2 = bits & 0x7ff

        rv = wordlist_en[w1], wordlist_en[w2]

        if version.has_608:
            # MRU: keep only a few
            if len(_word_cache) > 4:
                _word_cache.pop()
            _word_cache.insert(0, (pin_prefix, rv))

        return rv

    def is_delay_needed(self):
        # obsolete starting w/ mk3 and values re-used for other stuff
        if version.has_608:
            return False
        return self.delay_achieved < self.delay_required

    def is_blank(self):
        # device has no PIN at this point
        return bool(self.state_flags & PA_IS_BLANK)

    def is_successful(self):
        # we've got a valid pin
        return bool(self.state_flags & PA_SUCCESSFUL)

    def is_secret_blank(self):
        assert self.state_flags & PA_SUCCESSFUL
        return bool(self.state_flags & PA_ZERO_SECRET)

    # Mk1/2/3 concepts, not used in Mk4
    def has_duress_pin(self):
        return bool(self.state_flags & PA_HAS_DURESS)
    def has_brickme_pin(self):
        return bool(self.state_flags & PA_HAS_BRICKME)

    def has_tmp_seed(self):
        return not self.tmp_value == False

    def reset(self):
        # start over, like when you commit a new seed
        return self.setup(self.pin, self.is_secondary)

    def setup(self, pin, secondary=False):
        self.is_secondary = secondary
        self.pin = pin
        self.hmac = bytes(32)

        _ = self.roundtrip(0)

        return self.state_flags

    def delay(self):
        # obsolete since Mk3, but called from login.py
        self.roundtrip(1)

    def login(self):
        # test we have the PIN code right, and unlock access if so.
        chk = self.roundtrip(2)
        self.is_empty = (chk[0] == 0)

        # IMPORTANT: You will need to re-read settings since the key for that has changed
        ok = self.is_successful()

        if ok:
            # it's a bit sensitive, and no longer useful: wipe.
            global _word_cache
            _word_cache.clear()

        return ok

    def change(self, **kws):
        # change various values, stored in secure element
        if self.tmp_value: return

        self.roundtrip(3, **kws)

        # IMPORTANT: 
        # - call new_main_secret() when main secret changes!
        # - is_secret_blank and is_successful may be wrong now, re-login to get again

    def fetch(self, duress_pin=None, spare_num=0):
        if self.tmp_value:
            # must make a copy here, and must be mutable instance so not reused
            if spare_num:
                return bytearray(AE_SECRET_LEN)
            return bytearray(self.tmp_value)

        if duress_pin is None:
            secret = self.roundtrip(4, spare_num=spare_num)
        else:
            # mk3 and earlier
            secret = self.roundtrip(4, old_pin=duress_pin, get_duress_secret=True)

        return secret

    def ls_fetch(self):
        # get the "long secret"
        #assert (13 * 32) == 416 == AE_LONG_SECRET_LEN
        if self.tmp_value:
            return bytes(AE_LONG_SECRET_LEN)

        if version.mk_num < 4:
            secret = b''
            for n in range(13):
                secret += self.roundtrip(6, ls_offset=n)[0:32]

            return secret
        else:
            # faster method for Mk4
            return self.roundtrip(8, after_buf=bytes(AE_LONG_SECRET_LEN))

    def ls_change(self, new_long_secret):
        # set the "long secret"
        assert len(new_long_secret) == AE_LONG_SECRET_LEN
        if self.tmp_value: return

        for n in range(13):
            self.roundtrip(6, ls_offset=n, new_secret=new_long_secret[n*32:(n*32)+32])

    def greenlight_firmware(self):
        # hash all of flash and commit value to SE1
        self.roundtrip(5)
        ckcc.presume_green()

    def firmware_upgrade(self, start, length):
        # tell the bootrom to use data in PSRAM to upgrade now.
        # - requires main pin because it writes expected world check value before upgrade
        # - will fail if not self.is_successful() already (ie. right PIN entered)
        self.roundtrip(7, fw_upgrade=(start, length))
        # not-reached

    def new_main_secret(self, raw_secret, chain=None):
        # Main secret has changed: reset the settings+their key,
        # and capture xfp/xpub
        from glob import settings
        import stash
        stash.SensitiveValues.clear_cache()

        # capture values we have already
        old_values = dict(settings.current)

        settings.set_key(raw_secret)
        settings.load()

        # merge in settings, including what chain to use, timeout, etc.
        settings.merge(old_values)

        # Recalculate xfp/xpub values (depends both on secret and chain)
        with stash.SensitiveValues(raw_secret) as sv:
            if chain is not None:
                sv.chain = chain
            sv.capture_xpub()

        # does not call settings.save() but caller should!

    def tmp_secret(self, encoded):
        # Use indicated secret and stop using the SE; operate like this until reboot
        self.tmp_value = bytes(encoded + bytes(AE_SECRET_LEN - len(encoded)))

        # We're no longer blank. hard to say about duress secret and stuff tho
        self.state_flags = PA_SUCCESSFUL

        # Clear bip-39 secret, not applicable anymore.
        import stash
        stash.bip39_passphrase = ''
        stash.SensitiveValues.clear_cache()

        # Copies system settings to new encrypted-key value, calculates
        # XFP, XPUB and saves into that, and starts using them.
        self.new_main_secret(self.tmp_value)

    def trick_request(self, method_num, data):
        # send/recv a trick-pin related request (mk4 only)
        buf = bytearray(PIN_ATTEMPT_SIZE)
        self.marshal(buf)
        buf.extend(data)

        err = ckcc.gate(22, buf, method_num)

        #print("[%d] rx: %s" % (err, b2a_hex(buf)))
        
        if err <= -100:
            raise BootloaderError(PA_ERROR_CODES[err], err)

        return err, buf[PIN_ATTEMPT_SIZE:]

    def is_deltamode(self):
        # (mk4 only) are we operating w/ a slightly wrong PIN code?
        if version.mk_num < 4:
            return False

        from trick_pins import TC_DELTA_MODE
        return bool(self.delay_required & TC_DELTA_MODE)

    def get_tc_values(self):
        # Mk4 only
        # return (tc_flags, tc_arg)
        return self.delay_required, self.delay_achieved
        

# singleton
pa = PinAttempt()

# EOF
