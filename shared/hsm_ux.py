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
        self.busy_text = None
        self.percent = None
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
        dis.text(4, 0, "HSM MODE")
        dis.hline(15)
        
        if 0:
            fy = -11
            dis.text(0, fy, "Suitable transactions will be", FontTiny)
            dis.text(0, fy+8,  "signed without any interaction.", FontTiny)
            #dis.text(None, -1, "X to REBOOT ", FontTiny)

        left = hsm_active.get_time_left()
        if left is None:
            left = ' n/a'
        elif left == -1:
            left = ' --'
        else:
            left = pretty_short_delay(left)

        x, y = 0, 28
        for lab, xoff, val in [ 
            ('APPROVED', 0, str(hsm_active.approvals)),
            ('REFUSED', 0, str(hsm_active.refusals)),
            ('PERIOD LEFT', 5, left),
            #('PERIOD LEFT', 1, '13h 20m'),
        ]:
            nx = dis.text(x+xoff, y-7, lab, FontTiny)
            hw = nx - x
            tw = 7*len(val)     # = dis.width(val, FontSmall)
            if lab == 'REFUSED':
                dis.dis.line(nx+2, 0, nx+2, y+16, 1)
            else:
                if not xoff:
                    dis.dis.line(nx+2, y-12, nx+2, y+16, 1)

            dis.text(x+((hw-tw)//2)-1, y+1, val)
            x = nx + 7

        dis.hline(y+17)

        if 0:
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
        if len(self.digits) < 6:
            msg = self.digits + ('#' * (6-len(self.digits)))
        elif self.digits:
            msg = self.digits
        else:
            msg = '_'*6
        dis.text(80, 0, msg)

        # contains a dis.show()
        self.draw_busy(None, None)

    update_contents = show

    def draw_busy(self, msg, percent):
        from display import FontTiny
        from main import dis

        self.last_percent = 0.5

        # centered in bottom part of screen.
        y = 48

        # clear under it
        dis.clear_rect(0,y, 128, 64-y)

        if percent is not None:
            self.percent = percent

            # reset display once we're at 100%
            if percent >= 0.995:            # ~ last pixel
                self.percent = None
                self.busy_text = msg = None

        if msg is not None:
            self.busy_text = msg

        if self.busy_text is not None:
            dis.text(None, y, self.busy_text)

        if self.percent is not None:
            dis.dis.hline(0, 63, int(128 * self.percent), 1)

        dis.show()


    # replacements for display.py:Display functions
    def hack_fullscreen(self, msg, percent=None, line2=None):
        self.draw_busy(msg, percent)
    def hack_progress_bar(self, percent):
        self.draw_busy(None, percent)

    async def interact(self):
        import main
        from main import numpad
        from actions import login_now
        from uasyncio import sleep_ms

        # Prevent any other component from reading numpad
        # XXX this should be NeuterPad?
        numpad.stop()

        # Replace some drawing functions
        main.dis.fullscreen = self.hack_fullscreen
        main.dis.progress_bar = self.hack_progress_bar
        main.dis.progress_bar_show = self.hack_progress_bar

        # Kill time, waiting for user input
        self.digits = ''
        self.test_restart = False
        while not self.test_restart:
            self.show()
            gc.collect()

            try:
                # Poll for an event, no block
                ch = numpad.get_nowait()

                if ch == 'x':
                    self.digits = ''
                elif ch == 'y':
                    if len(self.digits) == LOCAL_PIN_LENGTH:
                        main.hsm_active.local_pin_entered(self.digits)
                        self.digits = ''
                elif ch == numpad.ABORT_KEY:
                    # important to eat these and fully suppress them
                    pass
                else:
                    self.digits += ch
                    if len(self.digits) > LOCAL_PIN_LENGTH:
                        # keep last N digits
                        self.digits = self.digits[-LOCAL_PIN_LENGTH:]

                # do immediate screen update
                continue

            except QueueEmpty:
                await sleep_ms(100)
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

        # This code only reachable on the simulator!
        # - need to cleanup and reset so we run another test w/o restart
        assert is_simulator()

        from actions import goto_top_menu
        main.hsm_active = None
        numpad.start()
        goto_top_menu()

        return


# singleton
hsm_ux_obj = hsmUxInteraction()

# Mock version of NumpadBase from numpad.py
# - just in case we missed some code that blocks on user input
# - this will cause it to not to work.
from numpad import NumpadBase
class NeuterPad(NumpadBase):
    disabled = True
    repeat_delay = 0

    def __init__(self, loop=None):
        pass

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
        return

# EOF
