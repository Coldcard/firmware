# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# hsm_ux.py
#
# User experience related to the HSM. Ironic because there isn't a user present.
#
import ustruct, tcc, ux, chains, sys, gc, uio, ujson, uos, utime
from ckcc import is_simulator
from sffile import SFFile
from ux import ux_aborted, ux_show_story, abort_and_goto, ux_dramatic_pause, ux_clear_keys, the_ux
from ux import AbortInteraction
from utils import problem_file_line, cleanup_deriv_path
from auth import UserAuthorizedAction
from utils import pretty_short_delay, pretty_delay
from uasyncio.queues import QueueEmpty
from ubinascii import a2b_base64
from users import Users, MAX_NUMBER_USERS
from public_constants import MAX_USERNAME_LEN

import hsm
from hsm import HSMPolicy, POLICY_FNAME, LOCAL_PIN_LENGTH

class ApproveHSMPolicy(UserAuthorizedAction):
    title = 'Start HSM?'

    def __init__(self, policy, new_file=False):
        self.policy = policy
        self.new_file = new_file
        super().__init__()

    async def interact(self):
        # Just show the address... no real confirmation needed.

        try:
            self.refused = True

            msg = uio.StringIO()
            self.policy.explain(msg)
            msg.write('\n\nPress OK to enable HSM mode.')

            try:
                ch = await ux_show_story(msg, title=self.title)
            except AbortInteraction:
                ch = 'x'
            finally:
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

        # go into special HSM mode .. one-way trip
        self.policy.activate(self.new_file)
        the_ux.reset(hsm_ux_obj)

        return

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

class hsmUxInteraction:
    # Based on Menu() class, but just skeleton: blocks everything

    def __init__(self):
        self.busy = None
        self.percent = 0
        self.digits = ''

    def show(self):
        from main import dis, hsm_active
        from display import FontTiny

        uptime = utime.ticks_ms() // 1000

        # make this screen saver fun
        x,y = 2,0

        # TODO: show "time til period reset", dont show amounts

        dis.clear()
        #dis.text(None, 2, "HSM Ready")
        dis.text(0, 0, "HSM Ready")
        
        fy = -11
        dis.text(0, fy, "Suitable transactions will be", FontTiny)
        dis.text(0, fy+8,  "signed without any interaction.", FontTiny)
        #dis.text(None, -1, "X to REBOOT ", FontTiny)

        x, y = 0, 29
        for lab, ljust, val in [ 
            ('APPROVED', 0, str(hsm_active.approvals)),
            ('REFUSED', 0, str(hsm_active.refusals)),
            ('PERIOD LEFT', 1, 'n/a'),
        ]:
            nx = dis.text(x, y-7, lab, FontTiny)
            if ljust:
                dis.text(x, y+1, val)
            else:
                hw = nx - x
                tw = 7*len(val)     # = dis.width(val, FontSmall)
                dis.text(x+((hw-tw)//2)-1, y+1, val)
            x = nx + 6

        # heartbeat display
        # >>> from main import *; from display import FontTiny
        # >>> dis.width('interaction', FontTiny)
        line_ws = ( (32, 48, 16, 8),
                    (24, 28, 12, 44 ) )
        phase = (utime.ticks_ms() // 1000) % 8
        line = phase // 4
        y = 63 if line else 54
        x = 0 + sum((line_ws[line][i]+4) for i in range(phase%4))
        w = line_ws[line][phase%4]-1
        dis.dis.line(x, y, x+w, y, True)

        # UX "feedback" for digits
        if self.digits:
            #x, y = 0, 14                                    # left, under HSM
            #x, y = 128 - (LOCAL_PIN_LENGTH*2) - 1, 0       # top right
            #x, y = 128 - (LOCAL_PIN_LENGTH*(4+2)) - 1, 12       # top right, below progress
            x, y = 75, 11       # right below progress bar
            for ch in self.digits:
                x = dis.text(x, y, ch, FontTiny) + 2

        if self.busy:
            self.draw_busy(False)

        dis.show()
    update_contents = show

    def draw_busy(self, now=True):
        from display import FontTiny
        from main import dis

        self.percent = .5

        x,y = 75, 0
        if now:
            # clear under it
            dis.clear_rect(x,y, 128-x, 9)

        if self.busy:
            msg = self.busy.rstrip('.')
            dis.text(x, y, msg, FontTiny)

            if self.percent:
                w = int((128 - x - 4) * self.percent)
                dis.dis.line(x, y+8, x+w, y+8, True)

        if now:
            dis.show()


    # replacements for display.py:Display functions
    def hack_fullscreen(self, msg, percent=None, line2=None):
        self.busy = msg
        self.percent = percent or 0
        self.draw_busy()

    def hack_progress_bar(self, percent):
        self.percent = int(percent*100)
        if percent >= 1:
            self.busy = None
        self.draw_busy()

    # report digits that are entered
    def pop_digits(self):
        # clear any partial pin entered so far
        rv = self.digits
        self.digits = ''
        return rv

    async def interact(self):
        import main
        from actions import login_now
        from uasyncio import sleep_ms

        # Prevent any other component from reading numpad
        real_numpad = main.numpad
        main.numpad = NeuterPad()

        # Replace some drawing functions
        main.dis.fullscreen = self.hack_fullscreen
        main.dis.progress_bar = self.hack_progress_bar
        main.dis.progress_bar_show = self.hack_progress_bar

        # Kill time, waiting for user input
        self.digits = ''
        while not main.numpad.test_restart:
            self.show()
            gc.collect()

            try:
                # Poll for an event, no block
                ch = real_numpad.get_nowait()

                if ch == 'x':
                    await login_now()       # immediate reboots

                elif ch != 'y':
                    self.digits += ch
                    if len(self.digits) > LOCAL_PIN_LENGTH:
                        # keep last x digits
                        self.digits = self.digits[-LOCAL_PIN_LENGTH:]
                    self.show()

            except QueueEmpty:
                await sleep_ms(250)
            except BaseException as exc:
                # just in case, keep going
                sys.print_exception(exc)
                continue

            # do the interactions, but don't let user actually press anything
            req = UserAuthorizedAction.active_request
            if req and not req.ux_done:
                try:
                    await req.interact()
                except AbortInteraction:
                    pass

        assert is_simulator()

        # This code only reachable on the simulator!
        # - need to cleanup and reset so we run another test w/o restart
        from actions import goto_top_menu
        import main
        main.hsm_active = None
        main.numpad = real_numpad
        goto_top_menu()
        return


# singleton
hsm_ux_obj = hsmUxInteraction()

# Mock version of NumpadBase from numpad.py
class NeuterPad:
    disabled = True
    test_restart = False

    async def get(self):
        return 

    def get_nowait(self):
        raise QueueEmpty

    def empty(self):
        return True

    def stop(self):
        return
    def start(self):
        return

    def abort_ux(self):
        return

    def inject(self, key):
        if key == 'TEST_RESET':
            assert is_simulator()
            self.test_restart = True
        return

