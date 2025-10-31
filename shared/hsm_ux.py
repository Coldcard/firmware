# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# hsm_ux.py
#
# User experience related to the HSM. Ironic because there isn't a user present.
#
import ustruct, sys, gc, uio, ujson, uos, utime, ngu
from sffile import SFFile
from ux import ux_show_story, abort_and_goto
from ux import AbortInteraction
from utils import problem_file_line
from auth import UserAuthorizedAction
from queues import QueueEmpty


from hsm import HSMPolicy, POLICY_FNAME, LOCAL_PIN_LENGTH

# see ../graphics/cylon.py
# storing as a string instead of a tuple saves 80 bytes
cylon = b':AHNTZ`eimprsttsqnkgb]WQKD=70)#\x1d\x17\x12\r\t\x06\x03\x01\x00\x00\x01\x02\x04\x07\x0b\x0f\x14\x1a &,3'


def period_display(sec):
    # imprecise, shorter on screen display
    if sec >= 3600:
        return '%2dh %2dm' % (sec //3600, (sec//60) % 60)
    else:
        return '%2dm %2ds' % ((sec//60) % 60, sec % 60)

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
                confirm_char = '12346'[ngu.random.uniform(5)]
                msg = '''Last chance. You are defining a new policy which \
allows the Coldcard to sign specific transactions without any further user approval.\n\n\
Policy hash:\n%s\n\n
Press %s to save policy and enable HSM mode.''' % (self.policy.hash(), confirm_char)

                ch = await ux_show_story(msg, title=self.title,
                                escape='x'+confirm_char, strict_escape=True)
                self.refused = (ch != confirm_char)

        except BaseException as exc:
            self.failed = "Exception"
            # sys.print_exception(exc)
            self.refused = True

        self.ux_done = True
        UserAuthorizedAction.cleanup()

        # cleanup already done, and nothing more here ... return
        if self.refused:
            self.done()         # restores/draws menu (might be needed from USB mode)
            return

        # go into special HSM mode .. one-way trip
        self.policy.activate(self.new_file)
        abort_and_goto(hsm_ux_obj)

        return

async def start_hsm_approval(sf_len=0, usb_mode=False, startup_mode=False):
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
    cant_fail = False
    try:
        try:
            js_policy = ujson.loads(json)
        except:
            raise ValueError("JSON parse fail")

        cant_fail = bool(js_policy.get('boot_to_hsm', False))

        # parse the policy
        policy = HSMPolicy()
        policy.load(js_policy)
    except BaseException as exc:
        err = "HSM Policy invalid: %s: %s" % (problem_file_line(exc), str(exc))
        if usb_mode:
            raise ValueError(err)

        # What to do in a menu case? Shouldn't happen anyway, but
        # maybe they upgraded the firmware, and so old policy file
        # isn't suitable anymore.
        # - or maybe the settings have been f-ed with.
        print(err)

        if startup_mode and cant_fail:
            # die as a brick here, not safe to proceed w/o HSM active
            import callgate, ux
            ux.show_fatal_error(err.replace(': ', ':\n '))
            callgate.show_logout(1)     # die w/ it visible
            # not reached

        await ux_show_story("Cannot start HSM.\n\n%s" % err)
        return

    # Boot-to-HSM feature: don't ask, just start policy immediately
    if startup_mode and policy.boot_to_hsm:
        from ux import the_ux
        msg = uio.StringIO()
        policy.explain(msg)
        policy.activate(False)
        the_ux.reset(hsm_ux_obj)
        return None
        

    ar = ApproveHSMPolicy(policy, is_new)
    UserAuthorizedAction.active_request = ar

    if startup_mode:
        return ar

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
        self.phase = 0

    def draw_background(self):
        # Render and capture static parts of screen one-time.
        from glob import dis
        from display import FontTiny

        dis.clear()
        dis.text(6, 0, "HSM MODE")
        dis.show() # cover the 300ms or so it takes to draw the rest below

        dis.hline(15)

        x, y = 0, 28
        for lab, xoff, val in [ 
            ('APPROVED', 0, '0'),
            ('REFUSED', 0, '0'),
            ('PERIOD LEFT', 5, 'xx'),
        ]:
            nx = dis.text(x+xoff, y-7, lab, FontTiny)
            hw = nx - x
            if lab == 'REFUSED':
                dis.dis.line(nx+2, 0, nx+2, y+16, 1)
            else:
                if not xoff:
                    dis.dis.line(nx+2, y-12, nx+2, y+16, 1)

            # keep this:
            #print('%s @ x=%d' % (lab, x+(hw//2)-2))

            # was:
            #tw = 7*len(val)     # = dis.width(val, FontSmall)
            #dis.text(x+((hw-tw)//2)-1, y+1, val)
            x = nx + 7

        dis.hline(y+17)

        # no local confirmation code entered, typically
        dis.text(80, 0, '######')

        # save this static background
        self.screen_buf = dis.dis.buffer[:]


    def show(self):
        from glob import dis, hsm_active

        # Plan: show "time til period reset", and some stats,
        # but never show amounts or private info.

        dis.dis.buffer[:] = self.screen_buf[:]

        left = hsm_active.get_time_left()
        if left is None:
            left = ' n/a'
        elif left == -1:
            left = ' --'
        else:
            left = period_display(left)

        # 3 statistics; see draw_background for X positions
        y = 28+1
        for x, val in [ (14, str(hsm_active.approvals % 10000)),
                        (51, str(hsm_active.refusals)),
                        (98, left)]:
            tw = 7*len(val)     # = dis.width(val, FontSmall)
            dis.text(x - tw//2, y, val)

        # heartbeat display
        if 1:
            #self.phase = (utime.ticks_ms() // 50) % len(cylon)
            self.phase = (self.phase + 1) % len(cylon)
            x = cylon[self.phase]
            w = 12
            dis.dis.line(x, 63, x+w-1, 63, True)

        if self.digits:
            # UX "feedback" for digits
            if len(self.digits) < 6:
                msg = self.digits + ('#' * (6-len(self.digits)))
            elif self.digits:
                msg = self.digits

            # dis.width('######', FontSmall) == 42
            x, y, w, h = 80, 0, 42, 14
            dis.clear_rect(x,y, x+w, y+h)
            dis.text(x, y, msg)

        # contains a dis.show()
        self.draw_busy(None, None)

    update_contents = show

    def draw_busy(self, msg, percent):
        from display import FontTiny
        from glob import dis

        self.last_percent = 0.5

        # centered in bottom part of screen.
        y = 48

        if percent is not None:
            self.percent = percent

            # reset display once we're at 100%
            if percent >= 0.995:            # ~ last pixel
                self.percent = None
                self.busy_text = msg = None

        if msg is not None:
            self.busy_text = msg

        if self.busy_text is not None:
            # clear under it
            dis.clear_rect(0,y, 128, 64-y)
            dis.text(None, y, self.busy_text)

        if self.percent is not None:
            x = int(128 * self.percent)
            dis.dis.hline(0, 63, x, 1)
            dis.dis.hline(x+1, 63, 127, 0)

        dis.show()


    # replacements for display.py:Display functions
    def hack_fullscreen(self, msg, percent=None, **kwargs):
        self.draw_busy(msg, percent)
    def hack_progress_bar(self, percent):
        self.draw_busy(None, percent)

    async def interact(self):
        import glob
        from glob import numpad
        from uasyncio import sleep_ms

        # Replace some drawing functions
        orig_fullscreen = glob.dis.fullscreen
        orig_progress_bar = glob.dis.progress_bar
        orig_progress_bar_show = glob.dis.progress_bar_show
        glob.dis.fullscreen = self.hack_fullscreen
        glob.dis.progress_bar = self.hack_progress_bar
        glob.dis.progress_bar_show = self.hack_progress_bar

        # get ready ourselves
        glob.dis.set_brightness(1)        # dimest, but still readable
        self.draw_background()

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
                        glob.hsm_active.local_pin_entered(self.digits)
                        self.digits = ''
                elif ch == numpad.ABORT_KEY:
                    # important to eat these and fully suppress them
                    pass
                elif ch:
                    if len(self.digits) < LOCAL_PIN_LENGTH:
                        # allow only 6 digits
                        self.digits += ch[0]
                    if len(self.digits) == LOCAL_PIN_LENGTH:
                        # send it, even if they didn't press OK yet
                        glob.hsm_active.local_pin_entered(self.digits)

                # do immediate screen update
                continue

            except QueueEmpty:
                await sleep_ms(100)
            except BaseException as exc:
                # just in case, keep going
                # sys.print_exception(exc)
                continue

            # do the interactions, but don't let user actually press anything
            req = UserAuthorizedAction.active_request
            if req and not req.ux_done:
                try:
                    await req.interact()
                except AbortInteraction:
                    pass

        # This code only reachable on the simulator and modified devices under test,
        # and when the "boot_to_hsm" feature is used and successfully unlock near
        # boottime.
        from actions import goto_top_menu
        glob.hsm_active = None
        goto_top_menu()

        # restore normal operation of UX
        from display import Display
        glob.dis.fullscreen = orig_fullscreen
        glob.dis.progress_bar = orig_progress_bar
        glob.dis.progress_bar_show = orig_progress_bar_show

        return

# singleton
hsm_ux_obj = hsmUxInteraction()

# EOF
