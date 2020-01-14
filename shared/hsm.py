# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# hsm.py
#
# Unattended signing of transactions and messages, subject to a set of rules.
#
import stash, ustruct, tcc, ux, chains, sys, gc, uio, ujson, uos, utime
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys, the_ux
from utils import problem_file_line, cleanup_deriv_path
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput
from auth import UserAuthorizedAction
from utils import pretty_short_delay, pretty_delay
from uasyncio.queues import QueueEmpty
from ubinascii import a2b_base64
from pincodes import AE_LONG_SECRET_LEN
from stash import blank_object
from users import Users, MAX_NUMBER_USERS
from public_constants import MAX_USERNAME_LEN

# this is None or points to the active HSMPolicy object
global hsm_active
hsm_active = None

# where we save policy/config
POLICY_FNAME = '/flash/hsm-policy.json'

def pop_list(j, fld_name, cleanup_fcn=None):
    # returns either None or a list of items; raises if not a list (ie. single item)
    v = j.pop(fld_name, None) or None
    if v:
        if not isinstance(v, list):
            raise ValueError("need a list for: " + fld_name)
        if cleanup_fcn:
            return [cleanup_fcn(i) for i in v]
    return v

def pop_int(j, fld_name, mn=0, mx=1000):
    # returns an int or None. Also range check.
    v = j.pop(fld_name, None)
    if v is None: return v
    assert int(v) == v, "%s: must be integer" % fld_name
    v = int(v)
    assert mn <= v < mx, "%s: must in range: %d..%d" % (fld_name, mn, mx)
    return v

def pop_bool(j, fld_name, default=False):
    # return a bool, but accept 1/0 and True/False
    return bool(j.pop(fld_name, default))

def pop_string(j, fld_name, mn_len=0, mx_len=80):
    v = j.pop(fld_name, None)
    if v is None: return v
    assert isinstance(v, str), '%s: must be string' % fld_name
    assert mn_len <= len(v) <= mx_len, '%s: length must be %d..%d' % (fld_name, mn_len, mx_len)
    return v

class HSMPolicy:
    # implements and enforces the HSM signing/activity/logging policy

    def load(self, j):
        # Decode json object provided: destructive
        # NOTES:
        # - attr name == json name if possible
        # - always add to self.save()!
        # - raise errors and they will be shown to user

        # fail if we can't log it
        self.must_log = pop_bool(j, 'must_log')

        # require a 4-digit PIN by local user (no UX feedback)
        self.local_conf = pop_bool(j, 'local_conf')

        # a list of paths we can accept for signing
        self.msg_paths = pop_list(j, 'msg_paths', cleanup_deriv_path)

        # free text shown at top
        self.notes = j.pop('notes', None)

        # time period, in minutes
        self.period = pop_int(j, 'period', 1, 3*24*60)

        # how many times they may view the long-secret
        self.allow_sl = pop_int(j, 'allow_sl', 1, 10)

        self.set_sl = pop_string(j, 'set_sl', 16, AE_LONG_SECRET_LEN-2)
        if self.set_sl:
            assert self.allow_sl, 'need allow_sl>=1'        # because pointless otherwise

        # error checking, must be last!
        extra = set(j.keys())
        if extra:
            raise ValueError("Unknown item: " + ', '.join(extra))

        # statistics / state
        self.refusals = 0
        self.approvals = 0
        self.sl_reads = 0
        self.pending_auth = {}
        self.need_pin = None

        # velocity limits
        self.current_period = utime.time() # starts now
        self.period_spent = 21E6

    def period_reset_time(self):
        # time from now, in seconds, until the period resets and the velocity
        # total is reset
        if not self.period: return 0
        end = self.current_period + (self.period*60)
        return utime.time() - end
        
    def save(self):
        # create JSON document for next time.
        simple = ['must_log', 'msg_paths', 'notes', 'period', 'allow_sl', 'local_conf']
        rv = dict()
        for fn in simple:
            rv[fn] = getattr(self, fn, None)

        # never write this secret into JSON
        assert 'set_sl' not in rv

        return rv

    def log_refuse(self, msg):
        # when things fail
        self.log("REFUSED: " + msg)
        self.refusals += 1
        self.last_refusal = msg

    def log_approved(self, msg):
        # when things fail
        self.log("APPROVED: " + msg)
        self.approvals += 1
        self.last_refusal = None

    def log(self, msg):
        # try to write to SD card.
        print("HSM LOG: " + msg)
        pass

    def explain(self, fd):

        if self.notes:
            fd.write('=-=\n%s\n=-=\n' % self.notes)

        fd.write('Transactions:\n')

        if self.period:
            fd.write('\nVelocity Period:\n %d minutes' % self.period)
            if self.period >= 60:
                fd.write('\n = %.3g hrs' % (self.period / 60))

        fd.write('\n\nMessage signing:\n')
        if self.msg_paths:
            fd.write("- Allowed if path is: %s\n" % ' OR '.join(self.msg_paths))
        else:
            fd.write("- Not allowed.\n")

        fd.write('\nOther policy:\n\n')
        fd.write('- MicroSD card %s receive log entries.\n' % ('MUST' if self.must_log else 'will'))
        if self.set_sl:
            fd.write('- Storage Locker will be updated (once).\n')
        if self.allow_sl:
            fd.write('- Storage Locker can be read only %s.\n' 
                        % ('once' if self.allow_sl == 1 else ('%d times'%self.allow_sl)))

        self.summary = fd.getvalue()

    def status(self, rv):
        # add some values we will share over USB during HSM operation
        for fn in ['summary', 'last_refusal', 'approvals', 'refusals', 'sl_reads']:
            rv[fn] = getattr(self, fn, None)

        if self.need_pin and self.local_conf:
            rv['need_pin'] = self.need_pin

        # sensitive values, summarize only!
        rv['pending_auth'] = len(self.pending_auth)

    def activate(self):
        # user approved activation, so apply it.
        global hsm_active
        assert not hsm_active
        hsm_active = self

        # save the "long secret" ... probably only happens first time HSM policy
        # is activated, because we don't store that original value except here 
        # and in SE.
        if self.set_sl:
            from main import pa

            # add length half-word to start, and pad to max size
            tmp = bytearray(AE_LONG_SECRET_LEN)
            val = self.set_sl.encode('utf8')
            ustruct.pack_into('H', tmp, 0, len(val))
            tmp[2:2+len(self.set_sl)] = val

            pa.ls_change(tmp)

            # memory cleanup
            blank_object(tmp)
            blank_object(val)
            blank_object(self.set_sl)
            self.set_sl = None

    def fetch_storage_locker(self):
        # USB request to read the storage locker (aka. long secret from 608a)
        # - limited by counter, because typically only needed at startup
        # - please keep in mind the desktop needs this secret, and probably blabs it
        # - our memory also is contaiminated with this secret, and no easy way to clean
        assert self.allow_sl, 'not allowed'
        assert self.sl_reads < self.allow_sl, 'consumed'
        self.sl_reads += 1

        from main import pa
        raw = pa.ls_fetch()
        ll, = ustruct.unpack_from('H', raw)
        assert 0 <= ll <= AE_LONG_SECRET_LEN-2

        return raw[2:2+ll]

    def usb_auth_user(self, username, token, totp_time):
        # User via USB has proposed a totp/user/password for auth purposes
        # - but just capture data at this point, we can't use until PSBT arrives
        # - reject bogus users at this point?
        # - to avoid timing attacks, keep this linear
        assert 1 < len(username) <= MAX_USERNAME_LEN, 'badlen'
        assert len(self.pending_auth)+1 <= MAX_NUMBER_USERS, 'toomany'

        self.pending_auth[username] = (token, totp_time)
        

    async def approve_msg_sign(self, story, msg_text, subpath):
        # Maybe approve indicated message to be signed.
        # return 'y' or 'x'
        self.log('Message signing requested\n-vvv-%s\n-^^^-' % story)
        if not self.msg_paths: 
            self.log_refuse("Message signing not permitted")
            return 'x'

        if subpath not in self.msg_paths:
            self.log_refuse('Message signing not enabled for that path')
            return 'x'

        self.log_approved('Message signing')
        return 'y'
        

class ApproveHSMPolicy(UserAuthorizedAction):
    title = 'Start HSM?'

    def __init__(self, policy, new_file=False):
        self.policy = policy
        self.new_file = new_file
        super().__init__()

    async def interact(self):
        # Just show the address... no real confirmation needed.

        try:

            msg = uio.StringIO()
            self.policy.explain(msg)
            msg.write('\n\nPress OK to enable HSM mode.')

            ch = await ux_show_story(msg, title=self.title)
            del msg

            self.refused = (ch != 'y')

            if not self.refused and self.new_file:
                confirm_char = '12346'[tcc.random.uniform(5)]
                msg = '''Last chance. You are defining a new policy which \
allows the Coldcard to sign specific transactions without any further user approval.\n\n\
Press %s to save policy and enable HSM mode.''' % confirm_char

                ch = await ux_show_story(msg, title=self.title,
                                escape='x'+confirm_char, strict_escape=True)
                self.refused = (ch != confirm_char)

        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            self.done()
            UserAuthorizedAction.cleanup()      # because no results to store

        # cleanup already done, and nothing more here ... return
        if self.refused:
            return

        if self.new_file:
            # save it for next run
            with open(POLICY_FNAME, 'w+t') as f:
                ujson.dump(self.policy.save(), f)

        # go into special HSM mode .. one-way trip
        self.policy.activate()
        the_ux.reset(hsm_ux_obj)

        return

def hsm_policy_available():
    # Is there an HSM policy ready to go? Offer the menu item then.
    try:
        uos.stat(POLICY_FNAME)
        return True
    except:
        return False

async def start_hsm_approval(sf_len=0, usb_mode=False):
    # Show details of the proposed HSM policy (or saved one)
    # If approved, go into HSM mode and never come back to normal.

    UserAuthorizedAction.cleanup()

    is_new = True

    if sf_len:
        with SFFile(0, length=sf_len) as fd:
            json = fd.read(sf_len).decode()
    else:
        try:
            json = open(POLICY_FNAME, 'rt').read()
        except:
            raise ValueError("No existing policy")

        is_new = False

    # parse as JSON
    try:
        try:
            js_policy = ujson.loads(json)
        except:
            raise ValueError("JSON parse fail")

        # parse the policy
        policy = HSMPolicy()
        policy.load(js_policy)
    except BaseException as exc:
        err = "HSM Policy invalid: %s: %s" % (problem_file_line(exc), str(exc))
        if usb_mode:
            raise ValueError(err)

        # What to do in a menu case? Shouldn't happen anyway, but
        # maybe they downgraded the CC firmware, and so old policy file
        # isn't suitable anymore.
        print(err)

        await ux_show_story("Cannot start HSM.\n\n%s" % err)
        return

    ar = ApproveHSMPolicy(policy, is_new)
    UserAuthorizedAction.active_request = ar

    if usb_mode:
        # for USB case, kill any menu stack, and put our thing at the top
        abort_and_goto(UserAuthorizedAction.active_request)
    else:
        # menu item case: add to stack, so we can still back out
        from ux import the_ux
        the_ux.push(UserAuthorizedAction.active_request)

    return ar

def hsm_status_report():
    # return a JSON-able object. Documented and external programs
    # rely on this output... and yet, don't overshare either.
    rv = dict()
    rv['active'] = bool(hsm_active)

    if not hsm_active:
        rv['policy_available'] = hsm_policy_available()

        ar = UserAuthorizedAction.active_request
        if ar and isinstance(ar, ApproveHSMPolicy):
            # we are waiting for local user to approve entry into HSM mode
            rv['approval_wait'] = True

    if hsm_active:
        hsm_active.status(rv)

    return rv

class hsmUxInteraction:
    # Based on Menu() class, but just skeleton: blocks everything

    def show(self):
        from main import dis
        from display import FontTiny

        uptime = utime.ticks_ms() // 1000

        # make this screen saver fun
        x,y = 2,0

        # TODO: show "time til period reset", dont show amounts

        dis.clear()
        dis.text(None, 2, "HSM Ready")
        
        fy = -11
        dis.text(4, fy, "Suitable transactions will be", FontTiny)
        dis.text(4, fy+8,  "signed without any interaction.", FontTiny)
        #dis.text(None, -1, "X to REBOOT ", FontTiny)

        x, y = 3, 28
        for lab, xoff, val in [ 
            ('APPROVED', 10, str(hsm_active.approvals)),
            ('REFUSED', 10, str(hsm_active.refusals)),
            ('PERIOD LEFT', 3, 'n/a'),
        ]:
            nx = dis.text(x, y-7, lab, FontTiny)
            dis.text(x+xoff, y+1, val)
            x = nx + 8

        # heartbeat display
        # >>> from main import *; from display import FontTiny
        # >>> dis.width('interaction', FontTiny)
        line_ws = ( (32, 48, 16, 8),
                    (24, 28, 12, 44 ) )
        phase = (utime.ticks_ms() // 1000) % 8
        line = phase // 4
        y = 63 if line else 54
        x = 4 + sum((line_ws[line][i]+4) for i in range(phase%4))
        w = line_ws[line][phase%4]
        dis.dis.line(x, y, x+w, y, True)

        dis.show()

    update_contents = show

    async def interact(self):
        import main
        from actions import login_now
        from uasyncio import sleep_ms

        # Prevent any other component from reading numpad
        real_numpad = main.numpad
        main.numpad = NeuterPad

        # Kill time, waiting for user input
        while 1:
            self.show()
            gc.collect()

            try:
                # Poll for an event, no block
                ch = real_numpad.get_nowait()

                if ch == 'x':
                    await login_now()       # immediate reboots

            except QueueEmpty:
                await sleep_ms(250)
            except:
                # just in case
                continue

            # do the interactions, but don't let user actually press anything
            req = UserAuthorizedAction.active_request
            if req and not req.ux_done:
                try:
                    await req.interact()
                except AbortInteraction:
                    pass


# singleton
hsm_ux_obj = hsmUxInteraction()

# Mock version of NumpadBase from numpad.py
class NeuterPad:
    disabled = True

    @classmethod
    async def get(cls):
        return 

    @classmethod
    def get_nowait(cls):
        raise QueueEmpty

    @classmethod
    def empty(cls):
        return True

    @classmethod
    def stop(cls):
        return

    @classmethod
    def abort_ux(cls):
        return

    @classmethod
    def inject(cls, key):
        return

# EOF
