# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# pincodes.py - manage PIN code (which map to wallet seeds)
#
import ustruct, ckcc, version, chains, stash
from callgate import enter_dfu, get_is_bricked
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

def retry_ae_fail(*args):
    err = ckcc.gate(*args)
    if err == -106:  # AE_FAIL
        err = ckcc.gate(*args)
    return err

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

        # If set, a spending policy is in effect, and so even tho we know the master
        # seed, we are not going to let them see it, nor sign things we dont like, etc.
        self.hobbled_mode = False

        #assert MAX_PIN_LEN == 32        # update FMT otherwise
        #assert ustruct.calcsize(PIN_ATTEMPT_FMT_V1) == PIN_ATTEMPT_SIZE_V1
        #assert ustruct.calcsize(PIN_ATTEMPT_FMT_V2_ADDITIONS) \
        #                    == PIN_ATTEMPT_SIZE - PIN_ATTEMPT_SIZE_V1

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
            assert old_pin is not None
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

        err = retry_ae_fail(18, buf, method_num)

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

        for k,v in _word_cache:
            if pin_prefix == k:
                return v

        for retry in range(3):
            buf = bytearray(pin_prefix + b'\0'*MAX_PIN_LEN)
            err = ckcc.gate(16, buf, len(pin_prefix))
            if not err:
                break
            if err == 5:        # EIO
                # serial comm error; can be noise.
                continue
            raise RuntimeError(err)

        # use just 22 bits of that
        bits = ustruct.unpack('I', buf[0:4])[0]
        w1 = (bits >> 11) & 0x7ff
        w2 = bits & 0x7ff

        rv = wordlist_en[w1], wordlist_en[w2]

        # MRU: keep only a few
        if len(_word_cache) > 4:
            _word_cache.pop()
        _word_cache.insert(0, (pin_prefix, rv))

        return rv

    def is_blank(self):
        # device has no PIN at this point
        return bool(self.state_flags & PA_IS_BLANK)

    def is_successful(self):
        # we've got a valid pin
        return bool(self.state_flags & PA_SUCCESSFUL)

    def is_secret_blank(self):
        assert self.is_successful()
        return bool(self.state_flags & PA_ZERO_SECRET)

    def has_secrets(self):
        return not self.is_secret_blank() or self.tmp_value

    def reset(self):
        # start over, like when you commit a new seed
        return self.setup(self.pin, self.is_secondary)

    def setup(self, pin, secondary=False):
        self.is_secondary = secondary
        self.pin = pin
        self.hmac = bytes(32)

        _ = self.roundtrip(0)

        return self.state_flags

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
        if not kws.pop("tmp_lockdown", False):
            if self.tmp_value: return

        self.roundtrip(3, **kws)

        # IMPORTANT: 
        # - call new_main_secret() when main secret changes!
        # - is_secret_blank and is_successful may be wrong now, re-login to get again

    def fetch(self, duress_pin=None, spare_num=0, bypass_tmp=False):
        if self.tmp_value and not bypass_tmp:
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

    def new_main_secret(self, raw_secret=None, chain=None, bip39pw='', blank=False,
                        target_nvram_key=None):
        # Main secret has changed: reset the settings+their key,
        # and capture xfp/xpub
        # if None is provided as raw_secret -> restore to main seed
        from glob import settings, dis
        stash.SensitiveValues.clear_cache()

        bypass_tmp = False
        stash.bip39_passphrase = bool(bip39pw)

        # capture values we have already
        old_values = dict(settings.current)

        if chain is None:
            chain = chains.get_chain(old_values.get("chain", None))

        if raw_secret is None:
            assert pa.tmp_value
            bypass_tmp = True
            pa.tmp_value = None
            if blank:
                # wipe current ephemeral secret settings slot
                settings.blank()
                old_values = None
        else:
            if target_nvram_key is None:
                settings.set_key(raw_secret)
            else:
                # we already have hashed nvram key calculated
                # from self.tmp_secret - use it
                settings.nvram_key = target_nvram_key

            settings.load()

        # Recalculate xfp/xpub values (depends both on secret and chain)
        try:
            with stash.SensitiveValues(raw_secret, bypass_tmp=bypass_tmp) as sv:
                if chain is not None:
                    sv.chain = chain

                if raw_secret is None:
                    # restore to main wallet's settings
                    settings.return_to_master_seed()
                    xfp = settings.get("xfp", 0)
                    dis.draw_status(xfp=xfp, tmp=0, bip39=0)
                else:
                    xfp = sv.capture_xpub()
                    dis.draw_status(xfp=xfp)

            settings.merge_previous_active(old_values)

        except stash.ZeroSecretException:
            settings.return_to_master_seed()
            # full re-draw, user has no master seed & is returning from tmp
            dis.draw_status(full=True)

    def tmp_secret(self, encoded, chain=None, bip39pw=''):
        # Use indicated secret and stop using the SE; operate like this until reboot
        from glob import settings
        from utils import xfp2str
        from nvstore import SettingsObject

        val = bytes(encoded + bytes(AE_SECRET_LEN - len(encoded)))
        if self.tmp_value == val:
            # noop - already enabled
            return False, "Temporary master key already in use."

        target_nvram_key = None
        if encoded is not None:
            # disallow using master seed as temporary
            xfp = xfp2str(settings.master_get("xfp", 0))
            master_err = ("Cannot use master seed as temporary. BUT you have just successfully "
                          "tested recovery of your master seed [%s].") % xfp
            target_nvram_key = settings.hash_key(val)
            if SettingsObject.master_nvram_key:
                assert self.tmp_value
                if target_nvram_key == SettingsObject.master_nvram_key:
                    return False, master_err
            else:
                if target_nvram_key == settings.nvram_key:
                    return False, master_err

        if not self.tmp_value:
            # leaving from master seed, might capture some useful values
            settings.leaving_master_seed()

        self.tmp_value = val

        # Copies system settings to new encrypted-key value, calculates
        # XFP, XPUB and saves into that, and starts using them.
        self.new_main_secret(self.tmp_value, chain=chain, bip39pw=bip39pw,
                             target_nvram_key=target_nvram_key)

        # On Q1, update status icons
        from glob import dis
        dis.draw_status(bip39=1 if bip39pw else 0, tmp=1)

        return True, None

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
        from trick_pins import TC_DELTA_MODE
        return bool(self.delay_required & TC_DELTA_MODE)


    def get_tc_values(self):
        # Mk4 only
        # return (tc_flags, tc_arg)
        return self.delay_required, self.delay_achieved

    @staticmethod
    async def enforce_brick():
        # check for bricked system early
        if get_is_bricked():
            try:
                # regardless of settings, become a forever calculator after brickage.
                while version.has_qwerty:
                    from calc import login_repl
                    await login_repl()
            finally:
                # die right away if it's not going to work
                enter_dfu(3)
        

# singleton
pa = PinAttempt()

# EOF
