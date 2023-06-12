# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# login.py - UX related to PIN code entry/login.
#
import pincodes, version, random
from glob import dis
from ux import PressRelease, ux_wait_keyup, ux_show_story, ux_show_pin
from callgate import show_logout
from pincodes import pa
from uasyncio import sleep_ms
from charcodes import KEY_DELETE, KEY_SELECT, KEY_CANCEL, KEY_CLEAR

MAX_PIN_PART_LEN = 6
MIN_PIN_PART_LEN = 2

if not version.has_qwerty:
    KEY_SELECT = 'y'
    KEY_CANCEL = 'x'
    KEY_DELETE = 'x'

class LoginUX:

    def __init__(self, randomize=False, kill_btn=None):
        self.is_setting = False
        self.is_repeat = False
        self.subtitle = False
        self.kill_btn = kill_btn
        self.reset()
        self.randomize = randomize

    def shuffle_keys(self):
        keys = [str(i) for i in range(10)]
        random.shuffle(keys)
        self.randomize = keys

    def reset(self):
        self.pin = ''       # just the part we're showing
        self.pin_prefix = None
        self.words_ok = False
        self.footer = None

    def show_pin(self, force_draw=False):
        # redraw screen with prompting
        ux_show_pin(dis, self.pin, self.subtitle, not self.pin_prefix, self.is_repeat,
                        force_draw, footer=self.footer, randomize=self.randomize)

    def _show_words(self):
        # Show the anti-phising words, but coordinate w/ the large delay from the SE.

        # - show prompt w/o any words first
        dis.clear()
        prompt = "Recognize these?" if (not self.is_setting) or self.is_repeat \
                            else "Write these down:"
        dis.text(None, 2 if dis.has_lcd else 0, prompt)

        dis.show()

        # - show as busy for 1-2 seconds
        dis.busy_bar(True)
        words = pincodes.PinAttempt.prefix_words(self.pin.encode())

        # - show rest of screen and CTA
        if dis.has_lcd:
            # Q1
            x = 12
            y = 4
            dis.text(x, y,   words[0])
            dis.text(x, y+1, words[1])
            dis.text(None, -1, "CANCEL or SELECT to continue")
        else:
            # Old style
            from display import FontLarge, FontTiny
            y = 15
            x = 18
            dis.text(x, y,    words[0], FontLarge)
            dis.text(x, y+18, words[1], FontLarge)
            dis.text(None, -1, "X to CANCEL, or OK to CONTINUE", FontTiny)

        dis.busy_bar(False)     # includes a dis.show()

    def cancel(self):
        self.reset()
        self.show_pin(True)

    async def interact(self):
        # Prompt for prefix and pin. Returns string or None if the abort.
        if self.randomize:
            self.shuffle_keys()

        self.show_pin(True)
        pr = PressRelease('y')
        while 1:
            ch = await pr.wait()

            if ch == KEY_DELETE:
                if self.pin:
                    self.pin = self.pin[:-1]
                    self.show_pin()
            elif ch == KEY_CLEAR:
                self.pin = ''
                self.show_pin()
            elif ch == KEY_CANCEL:
                if not self.pin and self.pin_prefix:
                    # cancel on empty 2nd-stage: start over
                    self.reset()
                    self.show_pin()
                    continue

                if not self.pin and not self.pin_prefix:
                    # X on blank first screen: stop
                    return None
                    
                if KEY_CANCEL == KEY_DELETE:
                    # do a backspace
                    if self.pin:
                        self.pin = self.pin[:-1]
                        self.show_pin()

            elif ch == KEY_SELECT:
                if len(self.pin) < MIN_PIN_PART_LEN:
                    # they haven't given enough yet
                    continue

                if self.pin_prefix:
                    # done!
                    return (self.pin_prefix + '-' + self.pin)

                self._show_words()

                pattern = KEY_SELECT + KEY_CANCEL
                if self.kill_btn:
                    pattern += self.kill_btn

                nxt = await ux_wait_keyup(pattern)

                if not self.is_setting and nxt == self.kill_btn:
                    # wipe the seed if they press a special key
                    import callgate
                    callgate.fast_wipe(False)
                    # not reached

                if nxt == KEY_SELECT:
                    self.pin_prefix = self.pin
                    self.pin = ''

                    if self.randomize:
                        self.shuffle_keys()
                elif nxt == KEY_CANCEL:
                    self.reset()

                self.show_pin(True)

            elif '0' <= ch <= '9':
                # digit pressed
                if self.randomize and ch:
                    ch = self.randomize[int(ch)]

                if len(self.pin) == MAX_PIN_PART_LEN:
                    self.pin = self.pin[:-1] + ch
                else:
                    self.pin += ch

                self.show_pin()
            else:
                # other key on Q1? Ignore
                pass

    async def we_are_ewaste(self, num_fails):
        msg = '''After %d failed PIN attempts this Coldcard is locked forever. \
By design, there is no way to reset or recover the secure element, and its contents \
are now forever inaccessible.

Restore your seed words onto a new Coldcard.''' % num_fails

        while 1:
            ch = await ux_show_story(msg, title='I Am Brick!', escape='6')
            if ch == '6': break

    async def confirm_attempt(self, attempts_left, num_fails, value):

        ch = await ux_show_story('''You have %d attempts left before this Coldcard BRICKS \
ITSELF FOREVER.

Check and double-check your entry:\n\n  %s\n
Maybe even take a break and come back later.\n
Press OK to continue, X to stop for now.
''' % (attempts_left, value), title="WARNING")

        if ch == 'x':
            show_logout()
            # no return
        

    async def try_login(self, bypass_pin=None):
        while 1:

            if version.has_608 and not pa.attempts_left:
                # tell them it's futile
                await self.we_are_ewaste(pa.num_fails)

            self.reset()

            if pa.num_fails:
                self.footer = '%d failures, %d tries left' % (pa.num_fails, pa.attempts_left)

            pin = await self.interact()

            if pin is None:
                # pressed X on empty screen ... RFU
                continue
            
            dis.fullscreen("Wait...")
            pa.setup(pin)

            if pa.num_fails > 3:
                # they are approaching brickage, so warn them each attempt
                await self.confirm_attempt(pa.attempts_left, pa.num_fails, pin)
                dis.fullscreen("Wait...")

            # do the actual login attempt now
            try:
                dis.busy_bar(True)
                if bypass_pin and pin == bypass_pin:
                    return True

                ok = pa.login()
                if ok: 
                    return      # success, leave
            except RuntimeError as exc:
                # I'm a brick and other stuff can happen here
                # - especially AUTH_FAIL when pin is just wrong.
                ok = False
                if exc.args[0] == pincodes.EPIN_I_AM_BRICK:
                    await self.we_are_ewaste(pa.num_fails)
                    continue
            finally:
                dis.busy_bar(False)

            pa.num_fails += 1
            if version.has_608:
                pa.attempts_left -= 1

            msg = ""
            nf = '1 failure' if pa.num_fails <= 1 else ('%d failures' % pa.num_fails)
            if version.has_608:
                if not pa.attempts_left:
                    await self.we_are_ewaste(pa.num_fails)
                    continue

                msg += '%d attempts left' % (pa.attempts_left)
            else:
                msg += '%s' % nf

            msg += '''\n\nPlease check all digits carefully, and that prefix versus \
suffix break point is correct.'''
            if version.has_608:
                msg += '\n\n' + nf

            await ux_show_story(msg, title='WRONG PIN')

    async def prompt_pin(self):
        # ask for an existing PIN
        self.reset()
        return await self.interact()
            

    async def get_new_pin(self, title, story=None, allow_clear=False):
        # Do UX flow to get new (or change) PIN. Always does the double-entry thing
        self.is_setting = True

        if story:
            # give them background
            ch = await ux_show_story(story, title=title)

            if ch == 'x': return None

        # first first one
        first_pin = await self.interact()
        if first_pin is None: return None

        if allow_clear and first_pin == '999999-999999':
            # don't make them repeat the 'clear pin' value
            return first_pin

        self.is_repeat = True

        while 1:
            self.reset()
            second_pin = await self.interact()
            if second_pin is None: return None

            if first_pin == second_pin:
                return first_pin

            ch = await ux_show_story('''\
You gave two different PIN codes and they don't match.

Press (2) to try the second one again, X or OK to give up for now.''',
                        title="PIN Mismatch", escape='2')

            if ch != '2':
                return None


# EOF
