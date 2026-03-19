# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# login.py - UX related to PIN code entry/login.
#
import pincodes, version, random
from glob import dis
from ux import ux_wait_keyup, ux_wait_keydown, ux_show_story, ux_show_pin, ux_show_phish_words, X, OK, ux_confirm
from callgate import show_logout
from pincodes import pa
from uasyncio import sleep_ms
from charcodes import KEY_DELETE, KEY_ENTER, KEY_CANCEL, KEY_CLEAR, KEY_LEFT, KEY_RIGHT, KEY_TAB
from version import has_qwerty

MAX_PIN_PART_LEN = 6
MIN_PIN_PART_LEN = 2

if not has_qwerty:
    KEY_ENTER = 'y'
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
        ux_show_pin(dis, self.pin, self.subtitle, self.pin_prefix, self.is_repeat,
                        force_draw, footer=self.footer, randomize=self.randomize)

    def _show_words(self):
        # Show the anti-phising words, but coordinate w/ the large delay from the SE.

        # - show prompt w/o any words first
        if not has_qwerty:
            dis.clear()
            prompt = "Recognize these?" if (not self.is_setting) or self.is_repeat \
                                else "Write these down:"
            dis.text(None, 0, prompt)
            dis.show()

        # - show as busy for 1-2 seconds
        dis.busy_bar(True)
        words = pincodes.PinAttempt.prefix_words(self.pin.encode())
        dis.busy_bar(False)

        # - show rest of screen and CTA
        ux_show_phish_words(dis, words)

        dis.busy_bar(False)     # includes a dis.show()

    def cancel(self):
        self.reset()
        self.show_pin(True)

    async def interact(self):
        # Prompt for prefix and pin. Returns string or None if the abort.
        if self.randomize:
            self.shuffle_keys()

        self.show_pin(True)
        while 1:
            ch = await ux_wait_keydown()
            if ch is None: continue     # not expected

            # Check for factory reset option: press '0' on empty PIN screen
            if not self.is_setting and not self.pin and not self.pin_prefix and ch == '0':
                # User pressed '0' on empty PIN screen - offer factory reset
                await self.factory_reset_option()
                self.show_pin(True)
                continue

            if has_qwerty and not self.is_setting and ch.upper() == self.kill_btn:
                # wipe the seed if they press a special key
                import callgate
                callgate.fast_wipe(False)
                # NOT REACHED

            if has_qwerty and ch in KEY_DELETE+KEY_LEFT:
                if self.pin:
                    self.pin = self.pin[:-1]
                    self.show_pin()
                elif self.pin_prefix:
                    # trying to delete past start of second half, take them
                    # to first part again. Q only
                    ux_show_phish_words(dis, None)
                    self.pin = self.pin_prefix
                    self.pin_prefix = None
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
                else:
                    # clear input, because they have a BS key
                    self.pin = ''
                    self.show_pin()

            elif ch in KEY_ENTER+' -_'+KEY_RIGHT+KEY_TAB:
                if len(self.pin) < MIN_PIN_PART_LEN:
                    # they haven't given enough yet - ignore
                    continue

                if self.pin_prefix:
                    # done!
                    return (self.pin_prefix + '-' + self.pin)

                self._show_words()

                if not has_qwerty:
                    # Mk4
                    pattern = KEY_ENTER + KEY_CANCEL
                    if self.kill_btn:
                        pattern += self.kill_btn

                    nxt = await ux_wait_keyup(pattern, flush=True)

                    if not self.is_setting and nxt == self.kill_btn:
                        # wipe the seed if they press a special key
                        import callgate
                        callgate.fast_wipe(False)
                        # not reached

                    if nxt == KEY_ENTER:
                        self.pin_prefix = self.pin
                        self.pin = ''

                        if self.randomize:
                            self.shuffle_keys()
                    elif nxt == KEY_CANCEL:
                        self.reset()

                    self.show_pin(True)
                else:
                    # Q: not confirming the words, they see them and continue or not
                    self.pin_prefix = self.pin
                    self.pin = ''
                    self.show_pin(False)

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
are now forever inaccessible.\n\n''' % num_fails

        if has_qwerty:
            msg += 'Calculator mode starts now.'
        else:
            msg += 'Restore your seed words onto a new Coldcard.'

        while 1:
            ch = await ux_show_story(msg, title='I Am Brick!', escape='6')
            if ch == '6': break

            if has_qwerty:
                from calc import login_repl
                await login_repl()


    async def confirm_attempt(self, attempts_left, value):

        ch = await ux_show_story('''You have %d attempts left before this Coldcard BRICKS \
ITSELF FOREVER.

Check and double-check your entry:\n\n  %s\n
Maybe even take a break and come back later.\n
Press %s to continue, %s to stop for now.
''' % (attempts_left, value, OK, X), title="WARNING")

        if ch == 'x':
            show_logout()
            # no return

    async def factory_reset_option(self):
        # Offer factory reset option for users who forgot their PIN
        # This will wipe all data and allow setting up a new wallet
        ch = await ux_show_story(
            "Forgot your PIN?\n\n"
            "If you cannot remember your PIN prefix and suffix, you can factory "
            "reset this device.\n\n"
            "WARNING: This will WIPE all seed words, settings, and wallet data! "
            "You will need to restore from your backup seed phrase.\n\n"
            "Press (0) to factory reset, or %s to continue trying your PIN." % X,
            title="FACTORY RESET?",
            escape='0'
        )

        if ch == '0':
            # Double confirm
            if not await ux_confirm("FACTORY RESET?\n\n"
                "This will completely wipe this Coldcard. All seed words, PIN codes, "
                "and settings will be permanently deleted.\n\n"
                "You will need your seed phrase to recover your funds."):
                return False

            if not await ux_confirm("ARE YOU SURE?\n\n"
                "Press (1) to confirm factory reset. There is NO way to undo this.",
                confirm_key="1"):
                return False

            # Perform the factory reset
            import callgate
            callgate.fast_wipe(False)
            # NOT REACHED

        return False
        

    async def try_login(self, bypass_pin=None):
        while 1:

            if not pa.attempts_left:
                # tell them it's futile
                await self.we_are_ewaste(pa.num_fails)

            self.reset()

            if pa.num_fails:
                self.footer = '%d failures, %d tries left' % (pa.num_fails, pa.attempts_left)

            pin = await self.interact()

            if pin is None:
                # pressed X on empty screen ... RFU
                continue

            if pa.num_fails > 3:
                # they are approaching brickage, so warn them each attempt
                await self.confirm_attempt(pa.attempts_left, pin)
            
            dis.fullscreen("Loading...")
            pa.setup(pin)

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
            pa.attempts_left -= 1

            msg = ""
            if not pa.attempts_left:
                await self.we_are_ewaste(pa.num_fails)
                continue

            msg += '%d attempts left' % (pa.attempts_left)

            msg += '''\n\nPlease check all digits carefully, and that prefix versus \
suffix break point is correct.\n\n'''
            msg += '1 failure' if pa.num_fails <= 1 else ('%d failures' % pa.num_fails)
            msg += '''\n\nPress (0) to factory reset this device if you have forgotten your PIN.'''

            ch = await ux_show_story(msg, title='WRONG PIN', escape='0')

            if ch == '0':
                # User chose factory reset
                await self.factory_reset_option()

    async def prompt_pin(self):
        # ask for an existing PIN
        self.reset()
        return await self.interact()
            

    async def get_new_pin(self, title=None, story=None):
        # Do UX flow to get new (or change) PIN. Always does the double-entry thing
        self.is_setting = True

        if story:
            # give them background
            ch = await ux_show_story(story, title=title)
            if ch == 'x': return None

        # first first one
        first_pin = await self.interact()
        if first_pin is None: return None

        self.is_repeat = True

        while 1:
            self.reset()
            second_pin = await self.interact()
            if second_pin is None: return None

            if first_pin == second_pin:
                return first_pin

            ch = await ux_show_story('''\
You gave two different PIN codes and they don't match.

Press (2) to try the second one again, %s to give up for now.''' % X,
                        title="PIN Mismatch", escape='2')

            if ch != '2':
                return None


# EOF
