# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# hsm.py
#
# Unattended signing of transactions and messages, subject to a set of rules.
#
import stash, ure, tcc, ux, chains, sys, gc, uio, ujson, uos, utime
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys, the_ux
from utils import problem_file_line, cleanup_deriv_path
from psbt import psbtObject, FatalPSBTIssue, FraudulentChangeOutput
from auth import UserAuthorizedAction
from utils import pretty_short_delay, pretty_delay
from uasyncio.queues import QueueEmpty

# this is None or points to the active HSMPolicy object
global hsm_active
hsm_active = None

# where we save policy/config
POLICY_FNAME = '/flash/hsm-policy.json'

def get_list(j, fld_name, cleanup_fcn=None):
    # returns either None or a list of items; raises if not a list (ie. single item)
    v = j.pop(fld_name, None) or None
    if v:
        if not isinstance(v, list):
            raise ValueError("need a list for: " + fld_name)
        if cleanup_fcn:
            return [cleanup_fcn(i) for i in v]
    return v

def get_int(j, fld_name, mn=0, mx=1000):
    v = j.pop(fld_name, None) or None
    if v is None: return v
    assert int(v) == v, "%s: must be integer" % fld_name
    v = int(v)
    assert mn <= v < mx, "%s: must in range: %d..%d" % (fld_name, mn, mx)
    return v

class HSMPolicy:
    # implements and enforces the HSM signing/activity/logging policy

    def load(self, j):
        # Decode json object provided: destructive
        # NOTES:
        # - attr name == json name if possible
        # - always add to self.save()!
        self.must_log = bool(j.pop('must_log', False))

        # a list of paths we can accept for signing
        self.msg_paths = get_list(j, 'msg_paths', cleanup_deriv_path)

        # free text shown at top
        self.notes = j.pop('notes', None)

        # time period, in minutes
        self.period = get_int(j, 'period', 1, 3*24*60)

        # error checking
        extra = set(j.keys())
        if extra:
            raise ValueError("Unknown item: " + ', '.join(extra))

        # statistics
        self.refusals = 0
        self.approvals = 0

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
        simple = ['must_log', 'msg_paths', 'notes', 'period']
        rv = dict()
        for fn in simple:
            rv[fn] = getattr(self, fn, None)

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
            fd.write(self.notes)
            fd.write('\n')

        fd.write('Transactions:\n')

        fd.write('\nMessage signing:\n')
        if self.msg_paths:
            fd.write("- Allowed if path is: %s\n" % ' OR '.join(self.msg_paths))
        else:
            fd.write("- Not allowed\n")

        fd.write('\nOther policy:\n\n')
        fd.write('- MicroSD card %s receive log entries.\n' % ('MUST' if self.must_log else 'will'))

        self.summary = fd.getvalue()

    def status(self, rv):
        for fn in ['summary', 'last_refusal', 'approvals', 'refusals']:
            rv[fn] = getattr(self, fn, None)
                    

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
        approved = False

        try:
            confirm_char = '12346'[tcc.random.uniform(5)]

            msg = uio.StringIO()
            self.policy.explain(msg)
            msg.write('\n\nPress %s to enable HSM mode.' % confirm_char)

            ch = await ux_show_story(msg, title=self.title,
                                        escape='x'+confirm_char, strict_escape=True)
            del msg

            if ch == confirm_char:
                approved = True
            else:
                # they don't want to!
                self.refused = True
                # no need to be dramatic, IMHO
                #await ux_dramatic_pause("Refused.", 2)

        except BaseException as exc:
            self.failed = "Exception"
            sys.print_exception(exc)
        finally:
            self.done()
            UserAuthorizedAction.cleanup()      # because no results to store

        UserAuthorizedAction.cleanup()

        if not approved:
            return

        if self.new_file:
            # save it for next run
            with open(POLICY_FNAME, 'w+t') as f:
                ujson.dump(self.policy.save(), f)

        # go into special HSM mode .. one-way trip
        global hsm_active
        hsm_active = self.policy
        the_ux.reset(hsm_ux_obj)

        return

def hsm_policy_available():
    # Is there an HSM policy ready to go? Offer the menu item then.
    try:
        uos.stat(POLICY_FNAME)
        return True
    except:
        return False

def maybe_start_hsm(sf_len=0, ux_reset=False):
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
        if ux_reset:
            raise ValueError(err)

        # What to do in a menu case? Shouldn't happen anyway, but
        # maybe they downgraded the CC firmware, and so old policy file
        # isn't suitable anymore. Don't crash, but no means to show msg
        # since this is sync code.
        print(err)
        return

    ar = ApproveHSMPolicy(policy, is_new)
    UserAuthorizedAction.active_request = ar

    if ux_reset:
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

        # heartbeat
        y = 63
        w = 8
        phase = (utime.ticks_ms() // 100) % (128-w)
        x = phase
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
