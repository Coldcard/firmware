# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# actions.py
#
# Every function here is called directly by a menu item. They should all be async.
#
import ckcc, pyb, version
from ux import ux_show_story, the_ux, ux_confirm, ux_dramatic_pause, ux_aborted
from ux import ux_enter_number
from utils import imported, pretty_short_delay, problem_file_line
import uasyncio
from uasyncio import sleep_ms
from files import CardSlot, CardMissingError, needs_microsd
from utils import xfp2str
from glob import settings
from pincodes import pa
from menu import start_chooser

CLEAR_PIN = '999999-999999'

async def start_selftest(*args):

    if len(args) and not version.is_factory_mode:
        # called from inside menu, not directly
        # - mk4 doesn't damage settings, only earlier marks
        if not await ux_confirm('''Selftest may destroy settings on other profiles (not seeds). Requires MicroSD card and might have other consequences. Recommended only for factory.'''):
            return await ux_aborted()

    with imported('selftest') as st:
        await st.start_selftest()

    settings.save()


async def needs_primary():
    # Standard msg shown if action can't be done w/o main PIN
    await ux_show_story("Only the holder of the main PIN (not the secondary) can perform this function. Please start over with the main PIN.")

async def show_bag_number(*a):
    import callgate
    bn = callgate.get_bag_number() or 'UNBAGGED!'

    await ux_show_story('''\
Your new Coldcard should have arrived SEALED in a bag with the above number. Please take a moment to confirm the number and look for any signs of tampering.
\n
Take pictures and contact support@coinkite if you have concerns.''', title=bn)

async def accept_terms(*a):
    # do nothing if they have accepted the terms once (ever), otherwise
    # force them to read message...

    if settings.get('terms_ok'):
        return 

    while 1:
        ch = await ux_show_story("""\
By using this product, you are accepting our Terms of Sale and Use.

Read the full document at:

https://
  coldcardwallet
  .com/legal

Press OK to accept terms and continue.""", escape='7')

        if ch == 'y':
            break

    await show_bag_number()

    # Note fact they accepted the terms. Annoying to do more than once.
    settings.set('terms_ok', 1)
    settings.save()

async def view_ident(*a):
    # show the XPUB, and other ident on screen
    import callgate, stash

    tpl = '''\
Master Key Fingerprint:

  {xfp}

USB Serial Number:

  {serial}

Extended Master Key:

{xpub}
'''
    my_xfp = settings.get('xfp', 0)
    xpub = settings.get('xpub', None)
    msg = tpl.format(xpub=(xpub or '(none yet)'),
                            xfp=xfp2str(my_xfp),
                            serial=version.serial_number())

    if pa.is_secondary:
        msg += '\n(Secondary wallet)\n'

    if stash.bip39_passphrase:
        msg += '\nBIP-39 passphrase is in effect.\n'

    if pa.tmp_value:
        msg += '\nEphemeral seed is in effect.\n'

    bn = callgate.get_bag_number()
    if bn:
        msg += '\nShipping Bag:\n  %s\n' % bn

    if not version.has_fatram:
        # can't support on mk2
        xpub = None
    if xpub:
        msg += '\nPress 3 to show QR code of xpub.'

    ch = await ux_show_story(msg, escape=('3' if xpub else None))

    if ch == '3':
        # show the QR
        from ux import show_qr_code
        await show_qr_code(xpub, False)
    

async def show_settings_space(*a):

    await ux_show_story('Settings storage space in use:\n\n       %d%%' % int(settings.get_capacity() * 100))

async def show_mcu_keys_left(*a):
    import callgate
    avail, used, total = callgate.mcu_key_usage()
    await ux_show_story('MCU key slots remaining:\n\n    %d of %d' % (avail, total))


async def maybe_dev_menu(*a):
    from version import is_devmode

    if not is_devmode:
        ok = await ux_confirm('Developer features could be used to weaken security or release key material.\n\nDo not proceed unless you know what you are doing and why.')

        if not ok:
            return None

    from flow import DevelopersMenu
    return DevelopersMenu

async def dev_enable_vcp(*a):
    # Enable USB serial port emulation, for devs.
    # Mk3 and earlier only.
    #
    from usb import is_vcp_active

    if is_vcp_active():
        await ux_show_story("""The USB virtual serial port is already enabled.""")
        return

    was = pyb.usb_mode()
    pyb.usb_mode(None)
    if was and 'MSC' in was:
        pyb.usb_mode('VCP+MSC')
    else:
        pyb.usb_mode('VCP+HID')

    # allow REPL access
    ckcc.vcp_enabled(True)

    await ux_show_story("""\
The USB virtual serial port has now been enabled. Use a real computer to connect to it.""")

async def dev_enable_disk(*a):
    # Enable disk emulation, which allows them to change code.
    # Mk3 and earlier only.
    #
    cur = pyb.usb_mode()

    if cur and 'MSC' in cur:
        await ux_show_story("""The USB disk emulation is already enabled.""")
        return

    # serial port and disk (but no HID-based USB protocol)
    pyb.usb_mode(None)
    pyb.usb_mode('VCP+MSC')

    await ux_show_story("""\
The disk emulation has now been enabled. Your code can go into /lib. \
Keep tmp files and other junk out!""")


async def dev_enable_protocol(*a):
    # Turn off disk emulation. Keep VCP enabled, since they are still devs.
    # Mk3 and earlier
    cur = pyb.usb_mode()
    if cur and 'HID' in cur:
        await ux_show_story('Coldcard USB protocol is already enabled (HID mode)')
        return

    if settings.get('du', 0):
        await ux_show_story('USB disabled in settings.')
        return

    # might need to reset stuff?
    from usb import enable_usb

    # reset and re-enable
    pyb.usb_mode(None)
    enable_usb()

    # enable REPL
    ckcc.vcp_enabled(True)

    await ux_show_story('Back to normal USB mode.')

async def microsd_upgrade(*a):
    # Upgrade vis MicroSD card
    # - search for a particular file
    # - verify it lightly
    # - erase serial flash
    # - copy it over (slow)
    # - reboot into bootloader, which finishes install

    fn = await file_picker('Pick firmware image to use (.DFU)', suffix='.dfu', min_size=0x7800)

    if not fn: return

    failed = None

    with CardSlot() as card:
        with card.open(fn, 'rb') as fp:
            from version import has_psram
            if has_psram:
                from glob import PSRAM as SF
            else:
                from sflash import SF
            from glob import dis
            from files import dfu_parse
            from utils import check_firmware_hdr

            offset, size = dfu_parse(fp)

            # we also put a copy of special signed heaer at the end of the flash
            from sigheader import FW_HEADER_OFFSET, FW_HEADER_SIZE

            # read just the signature header
            hdr = bytearray(FW_HEADER_SIZE)
            fp.seek(offset + FW_HEADER_OFFSET)
            rv = fp.readinto(hdr)
            assert rv == FW_HEADER_SIZE

            # check header values
            failed = check_firmware_hdr(hdr, size)

            if not failed:
                # copy binary into serial flash / PSRAM
                fp.seek(offset)

                dis.fullscreen("Loading...")

                buf = bytearray(256 if not has_psram else 0x20000)
                pos = 0
                while pos < size:
                    dis.progress_bar_show(pos/size)

                    here = fp.readinto(buf)
                    if not here: break

                    if has_psram:
                        SF.write(pos, buf)
                    else:
                        if pos % 4096 == 0:
                            # erase here
                            SF.sector_erase(pos)
                            while SF.is_busy():
                                await sleep_ms(10)

                        SF.write(pos, buf)

                        # full page write: 0.6 to 3ms
                        while SF.is_busy():
                            await sleep_ms(1)

                    pos += here

    if failed:
        await ux_show_story(failed, title='Sorry!')
        return

    # continue process...
    from auth import FirmwareUpgradeRequest
    m = FirmwareUpgradeRequest(hdr, size, psram_offset=(0 if has_psram else None))
    the_ux.push(m)

async def start_dfu(*a):
    from callgate import enter_dfu
    enter_dfu(0)
    # NOT REACHED

async def reset_self(*a):
    import machine
    machine.soft_reset()
    # NOT REACHED

async def initial_pin_setup(*a):
    # First time they select a PIN of any type.
    from login import LoginUX
    lll = LoginUX()
    title = 'Choose PIN'

    ch = await ux_show_story('''\
Pick the main wallet's PIN code now. Be more clever, but an example:

123-4567

It has two parts: prefix (123-) and suffix (-4567). \
Each part must be between 2 to 6 digits long. Total length \
can be as long as 12 digits.

The prefix part determines the anti-phishing words you will \
see each time you login.

Your new PIN protects access to \
this Coldcard device and is not a factor in the wallet's \
seed words or private keys.

THERE IS ABSOLUTELY NO WAY TO RECOVER A FORGOTTEN PIN! Write it down.
''', title=title)
    if ch != 'y': return

    while 1:
        ch = await ux_show_story('''\
There is ABSOLUTELY NO WAY to 'reset the PIN' or 'factory reset' the Coldcard if you forget the PIN.

DO NOT FORGET THE PIN CODE.
 
Press 6 to prove you read to the end of this message.''', title='WARNING', escape='6')

        if ch == 'x': return
        if ch == '6': break

    # do the actual picking
    pin = await lll.get_new_pin(title)
    del lll

    if pin is None: return

    # A new pin is to be set!
    from glob import dis
    dis.fullscreen("Saving...")

    try:
        dis.busy_bar(True)
        assert pa.is_blank()

        pa.change(new_pin=pin)

        # check it? kinda, but also get object into normal "logged in" state
        pa.setup(pin)
        ok = pa.login()
        assert ok

        # must re-read settings after login, because they are encrypted
        # with a key derived from the main secret.
        settings.set_key()
        settings.load()
    except Exception as e:
        print("Exception: %s" % e)
    finally:
        dis.busy_bar(False)

    # Allow USB protocol, now that we are auth'ed
    from usb import enable_usb
    enable_usb()

    from menu import MenuSystem
    from flow import EmptyWallet
    return MenuSystem(EmptyWallet)

async def login_countdown(sec):
    # Show a countdown, which may need to
    # run for multiple **days**
    from glob import dis
    from display import FontSmall, FontLarge
    from utime import ticks_ms, ticks_diff

    # pre-render fixed parts
    dis.clear()
    y = 0
    dis.text(None, y, 'Login countdown in', font=FontSmall); y += 14
    dis.text(None, y, 'effect. Must wait:', font=FontSmall); y += 14
    y += 5
    dis.save()

    st = ticks_ms()
    while sec > 0:
        dis.restore()
        dis.text(None, y, pretty_short_delay(sec), font=FontLarge)

        dis.show()
        dis.busy_bar(1)

        # this should be more accurate, errors were accumulating
        now = ticks_ms()
        dt = 1000 - ticks_diff(now, st)
        await sleep_ms(dt)
        st = ticks_ms()

        sec -= 1

    dis.busy_bar(0)

async def block_until_login():
    #
    # Force user to enter a valid PIN.
    # - or accept a bogus one and return T iff mk<4 and "countdown" pin used
    # 
    from login import LoginUX
    from ux import AbortInteraction

    # mk4 does differently, as a "trick pin"
    cd_pin = settings.get('cd_pin', None) if not version.has_se2 else None

    # do they want a randomized (shuffled) keypad?
    rnd_keypad = settings.get('rngk', 0)

    # single key that "kills" self if pressed on "words" screen
    kill_btn = settings.get('kbtn', None)

    rv = None       # might already be logged-in if _skip_pin used

    while not pa.is_successful():
        lll = LoginUX(rnd_keypad, kill_btn)

        try:
            rv = await lll.try_login(bypass_pin=cd_pin)
            if rv: break
        except AbortInteraction:
            # not allowed!
            pass

    return rv

async def show_nickname(nick):
    # Show a nickname for this coldcard (as a personalization)
    # - no keys here, just show it until they press anything
    from glob import dis
    from display import FontLarge, FontTiny, FontSmall
    from ux import ux_wait_keyup

    dis.clear()

    if dis.width(nick, FontLarge) <= dis.WIDTH:
        dis.text(None, 21, nick, font=FontLarge)
    else:
        dis.text(None, 27, nick, font=FontSmall)

    dis.show()

    await ux_wait_keyup()

async def pick_killkey(*a):
    # Setting: kill seed sometimes (requires mk4)
    if await ux_show_story('''\
If you press this key while the anti- phishing words are shown during login, \
your seed phrase will be immediately wiped.

Best if this does not match the first number of the second half of your PIN.''') != 'y':
        return

    from choosers import kill_key_chooser
    start_chooser(kill_key_chooser)

async def pick_scramble(*a):
    # Setting: scrambled keypad or normal
    if await ux_show_story("When entering PIN, randomize the order of the key numbers, "
            "so that cameras and shoulder-surfers are defeated.") != 'y':
        return

    from choosers import scramble_keypad_chooser
    start_chooser(scramble_keypad_chooser)

async def pick_nickname(*a):
    # from settings menu, enter a nickname
    from nvstore import SettingsObject

    # Value is not stored with normal settings, it's part of "prelogin" settings
    # which are encrypted with zero-key.
    s = SettingsObject()
    nick = s.get('nick', '')

    if not nick:
        ch = await ux_show_story('''\
You can give this Coldcard a nickname and it will be shown before login.''')
        if ch != 'y': return

    from seed import spinner_edit
    nn = await spinner_edit(nick, confirm_exit=False)

    nn = nn.strip() if nn else None
    s.set('nick', nn)
    s.save()
    del s


async def logout_now(*a):
    # wipe memory and lock up
    from utils import clean_shutdown
    clean_shutdown()

async def login_now(*a):
    # wipe memory and reboot
    from utils import clean_shutdown
    clean_shutdown(2)
    

async def virgin_help(*a):
    await ux_show_story("""\
8 = Down (do it!)
5 = Up
OK = Checkmark
X = Cancel/Back
0 = Go to top

More on our website:

 coldcardwallet
           .com
""")

async def start_b39_pw(menu, label, item):
    if not settings.get('b39skip', False):
        ch = await ux_show_story('''\
You may add a passphrase to your BIP-39 seed words. \
This creates an entirely new wallet, for every possible passphrase.

By default, the Coldcard uses an empty string as the passphrase.

On the next menu, you can enter a passphrase by selecting \
individual letters, choosing from the word list (recommended), \
or by typing numbers.

Please write down the fingerprint of all your wallets, so you can \
confirm when you've got the right passphrase. (If you are writing down \
the passphrase as well, it's okay to put them together.) There is no way for \
the Coldcard to know if your password is correct, and if you have it wrong, \
you will be looking at an empty wallet.

Limitations: 100 characters max length, ASCII \
characters 32-126 (0x20-0x7e) only.

OK to start.
X to go back. Or press 2 to hide this message forever.
''', escape='2')
        if ch == '2':
            settings.set('b39skip', True)
        if ch == 'x':
            return

    import seed
    return seed.PassphraseMenu()

async def start_seed_import(menu, label, item):
    import seed
    return seed.WordNestMenu(item.arg)

def pick_new_seed(menu, label, item):
    import seed
    return seed.make_new_wallet(item.arg)

def new_from_dice(menu, label, item):
    import seed
    return seed.new_from_dice(item.arg)

async def convert_bip39_to_bip32(*a):
    import seed, stash

    if not await ux_confirm('''This operation computes the extended master private key using your BIP-39 seed words and passphrase, and then saves the resulting value (xprv) as the wallet secret.

The seed words themselves are erased forever, but effectively there is no other change. If a BIP-39 passphrase is currently in effect, its value is captured during this process and will be 'in effect' going forward, but the passphrase itself is erased and unrecoverable. The resulting wallet cannot be used with any other passphrase.

A reboot is part of this process. PIN code, and funds are not affected.
'''):
        return await ux_aborted()

    if not stash.bip39_passphrase:
        if not await ux_confirm('''You do not have a BIP-39 passphrase set right now, so this command does little except forget the seed words. It does not enhance security.'''):
            return

    await seed.remember_bip39_passphrase()

    settings.save()

    await login_now()

async def clear_seed(*a):
    # Erase the seed words, and private key from this wallet!
    # This is super dangerous for the customer's money.
    import seed

    if pa.has_duress_pin():
        await ux_show_story('''Please empty the duress wallet, and clear the duress PIN before clearing main seed.''')
        return

    if version.has_se2:
        from trick_pins import tp
        if any(tp.get_duress_pins()):
            await ux_show_story('''You have one or more duress wallets defined under Trick PINs. Please empty them, and clear associated Trick PINs before clearing main seed.''')
            return

    if not await ux_confirm('''Wipe seed words and reset wallet. All funds will be lost. You better have a backup of the seed words.'''):
        return await ux_aborted()

    ch = await ux_show_story('''Are you REALLY sure though???\n\n\
This action will certainly cause you to lose all funds associated with this wallet, \
unless you have a backup of the seed words and know how to import them into a \
new wallet.\n\nPress 4 to prove you read to the end of this message and accept all \
consequences.''', escape='4')
    if ch != '4': 
        return await ux_aborted()

    seed.clear_seed()
    # NOT REACHED -- reset happens


def render_master_secrets(mode, raw, node):
    # Render list of words, or XPRV / master secret to text.
    import stash

    qr_alnum = False

    if mode == 'words':
        import bip39
        words = bip39.b2a_words(raw).split(' ')

        # This optimization make the QR very nice, and space for
        # all the words too
        qr = ' '.join(w[0:4] for w in words)
        qr_alnum = True

        msg = 'Seed words (%d):\n' % len(words)
        msg += '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))

        pw = stash.bip39_passphrase
        if pw:
            msg += '\n\nBIP-39 Passphrase:\n%s' % pw
    elif mode == 'xprv':
        import chains
        msg = chains.current_chain().serialize_private(node)
        qr = msg

    elif mode == 'master':
        from ubinascii import hexlify as b2a_hex

        msg = '%d bytes:\n\n' % len(raw)
        qr = str(b2a_hex(raw), 'ascii')
        msg += qr
    else:
        raise ValueError(mode)

    return msg, qr, qr_alnum

async def view_seed_words(*a):
    import stash

    if not await ux_confirm('''The next screen will show the seed words (and if defined, your BIP-39 passphrase).\n\nAnyone with knowledge of those words can control all funds in this wallet.''' ):
        return

    from glob import dis
    dis.fullscreen("Wait...")
    dis.busy_bar(True)

    with stash.SensitiveValues() as sv:
        if sv.deltamode:
            # give up and wipe self rather than show true seed values.
            import callgate
            callgate.fast_wipe()

        dis.busy_bar(False)
        msg, qr, qr_alnum = render_master_secrets(sv.mode, sv.raw, sv.node)

        if version.has_fatram:
            msg += '\n\nPress 1 to view as QR Code.'

        while 1:
            ch = await ux_show_story(msg, sensitive=True, escape='1')
            if ch == '1':
                from ux import show_qr_code
                await show_qr_code(qr, qr_alnum)
                continue
            break

        stash.blank_object(qr)
        stash.blank_object(msg)

async def damage_myself():
    # called when it's time to disable ourselves due to various
    # features related to duress and so on
    # - mk2 cannot do this
    # - mk4 doesn't call this, done by bootrom
    mode = settings.get('cd_mode', 0)
    #['Brick', 'Final PIN', 'Test Mode']

    if mode == 2:
        # test mode, do no damage
        return

    from glob import dis
    dis.fullscreen("Wait...")
    dis.busy_bar(True)

    if mode == 1:
        # leave single attempt; careful!
        # - always consume one attempt, regardless
        todo = max(1, pa.attempts_left - 1)
    else:
        # brick ourselves, by consuming all PIN attempts
        todo = pa.attempts_left

    # do a bunch of failed attempts
    pa.setup('hfsp', False)
    for i in range(todo):
        try:
            pa.login()
        except:
            # expecting EPIN_AUTH_FAIL
            pass

        # Try to keep UX responsive? But callgate stuff blocks everything,
        # so just go as fast as possible.

    dis.busy_bar(False)

async def version_migration():
    # Handle changes between upgrades, and allow downgrades when possible.
    # - long term we generally cannot delete code from here, because we
    #   never know when a user might skip a bunch of intermediate versions

    # Data migration issue: 
    # - "login countdown" feature now stored elsewhere [mk3]
    had_delay = settings.get('lgto', 0)
    if had_delay:
        from nvstore import SettingsObject
        settings.remove_key('lgto')
        s = SettingsObject()
        s.set('lgto', had_delay)
        s.save()
        del s

    # Disable vdisk so it is off by default until re-enabled, after 
    # version 5.0.6 is installed
    settings.remove_key('vdsk')
        
async def version_migration_prelogin():
    # same, but for setting before login
    if version.has_se2:
        # these have moved into SE2 for Mk4 and so can be removed
        for n in [ 'cd_lgto', 'cd_mode', 'cd_pin' ]:
            settings.remove_key(n)

async def start_login_sequence():
    # Boot up login sequence here.
    #
    # - easy to brick units here, so catch and ignore errors where possible/appropriate
    #
    from ux import idle_logout
    from glob import dis
    import callgate

    if version.mk_num < 4:
        # Block very obsolete versions.
        try:
            MIN_WATERMARK = b'!\x03)\x19\'"\x00\x00'    #  b2a_hex('2103291927220000')
            now = callgate.get_highwater()
            if now < MIN_WATERMARK:
                callgate.set_highwater(MIN_WATERMARK)
        except: pass

    if pa.is_blank():
        # Blank devices, with no PIN set all, can continue w/o login

        # Do green-light set immediately after firmware upgrade [not after mk3]
        if version.is_fresh_version() and version.mk_num <=3:
            pa.greenlight_firmware()
            dis.show()

        goto_top_menu()
        return

    # data migration on settings that are used pre-login
    try:
        await version_migration_prelogin()
    except: pass

    # maybe show a nickname before we do anything
    try:
        nickname = settings.get('nick', None)
        if nickname:
            await show_nickname(nickname)
    except: pass

    # Allow impatient devs and crazy people to skip the PIN
    guess = settings.get('_skip_pin', None)
    if guess is not None:
        try:
            dis.fullscreen("(Skip PIN)")
            pa.setup(guess)
            pa.login()
        except: pass

    # If that didn't work, or no skip defined, force
    # them to login successfully.

    try:
        # Get a PIN and try to use it to login
        # - does warnings about attempt usage counts
        wants_countdown = await block_until_login()

        # Do we need to do countdown delay? (real or otherwise)
        delay = 0
        if wants_countdown:
            # Mk3 and earlier
            await damage_myself()
            delay = settings.get('cd_lgto', 60)
        elif version.has_se2:
            # Mk4 approach:
            # - wiping has already occured if that was picked
            # - delay is variable, stored in tc_arg
            from trick_pins import tp
            delay = tp.was_countdown_pin()

        # Maybe they do know the right PIN, but do a delay anyway, because they wanted that
        if not delay:
            delay = settings.get('lgto', 0)

        if delay:
            # kill some time, with countdown, and get "the" PIN again for real login
            pa.reset()
            await login_countdown(delay * (60 if not version.is_devmode else 1))

            if version.has_se2:
                # keep it simple for Mk4+: just challenge again for any PIN
                # - if it's the same countdown pin, it will be accepted and they
                #   get in (as most trick pins would do)
                await block_until_login()
            else:
                # second PIN challenge; but only if first one was actually legit
                wants_countdown = await block_until_login()

                # whenever they use the countdown pin on second screen, kill ourselves
                if wants_countdown:
                    await damage_myself()

                if wants_countdown:
                    # crash
                    dis.fullscreen("ERROR")
                    callgate.show_logout(1)

    except BaseException as exc:
        # Robustness: any logic errors/bugs in above will brick the Coldcard
        # even for legit owner, since they can't login. Try to recover, when it's
        # safe to do so. Remember the bootrom checks PIN on every access to
        # the secret, so "letting" them past this point is harmless if they don't know
        # the true pin.
        if not pa.is_successful():
            raise

        print("Bug recovery!")
        import sys
        sys.print_exception(exc)

    # Successful login...

    # Must re-read settings after login
    dis.fullscreen("Startup...")
    settings.set_key()
    settings.load(dis)

    # handle upgrades/downgrade issues
    try:
        await version_migration()
    except:
        pass

    # implement idle timeout now that we are logged-in
    from imptask import IMPT
    IMPT.start_task('idle', idle_logout()) 

    # Do green-light set immediately after firmware upgrade
    # - mk4 doesn't work this way, light will already be green
    if version.mk_num <= 3:
        if version.is_fresh_version() and not pa.is_secondary:
            pa.greenlight_firmware()
            dis.show()

    # Populate xfp/xpub values, if missing.
    # - can happen for first-time login of duress wallet
    # - may indicate lost settings, which we can easily recover from
    # - these values are important to USB protocol
    if not (settings.get('xfp', 0) and settings.get('xpub', 0)) and not pa.is_secret_blank():
        try:
            import stash

            # Recalculate xfp/xpub values (depends both on secret and chain)
            with stash.SensitiveValues() as sv:
                sv.capture_xpub()
        except Exception as exc:
            # just in case, keep going; we're not useless and this
            # is early in boot process
            print("XFP save failed: %s" % exc)

    # If HSM policy file is available, offer to start that,
    # **before** the USB is even enabled.
    if version.has_fatram:
        # do not offer HSM if wallet is blank -> HSM needs secret
        if not pa.is_secret_blank():
            try:
                import hsm, hsm_ux

                if hsm.hsm_policy_available():
                    settings.put("hsmcmd", True)
                    ar = await hsm_ux.start_hsm_approval(usb_mode=False, startup_mode=True)
                    if ar:
                        await ar.interact()
            except: pass

    if version.mk_num >= 4:
        if version.has_nfc and settings.get('nfc', 0):
            # Maybe allow NFC now
            import nfc
            nfc.NFCHandler.startup()

        if settings.get('vidsk', 0):
            # Maybe start virtual disk
            import vdisk
            vdisk.VirtDisk()

    # Allow USB protocol, now that we are auth'ed
    if not settings.get('du', 0):
        from usb import enable_usb
        enable_usb()

def make_top_menu():
    from menu import MenuSystem
    from flow import VirginSystem, NormalSystem, EmptyWallet, FactoryMenu
    from glob import hsm_active

    if hsm_active:
        from hsm_ux import hsm_ux_obj
        m = hsm_ux_obj
    elif version.is_factory_mode:
        m = MenuSystem(FactoryMenu)
    elif pa.is_blank():
        # let them play a little before picking a PIN first time
        m = MenuSystem(VirginSystem, should_cont=lambda: pa.is_blank())
    else:
        assert pa.is_successful(), "nonblank but wrong pin"

        m = MenuSystem(EmptyWallet if pa.is_secret_blank() else NormalSystem)
    return m

def goto_top_menu(first_time=False):
    # Start/restart menu system
    m = make_top_menu()
    the_ux.reset(m)

    if first_time and not pa.is_secret_blank():
        # guide new user thru some setup stuff
        from ftux import FirstTimeUX
        the_ux.push(FirstTimeUX())

    return m

SENSITIVE_NOT_SECRET = '''

The file created is sensitive--in terms of privacy--but should not \
compromise your funds directly.'''

PICK_ACCOUNT = '''\n\nPress 1 to enter a non-zero account number.'''


async def dump_summary(*A):
    # save addresses, and some other public details into a file
    if not await ux_confirm('''\
Saves a text file with a summary of the *public* details \
of your wallet. For example, this gives the XPUB (extended public key) \
that you will need to import other wallet software to track balance.''' + SENSITIVE_NOT_SECRET):
        return

    # pick a semi-random file name, save it.
    import export
    await export.make_summary_file()

async def export_xpub(label, _2, item):
    # provide bare xpub in a QR/NFC for import into simple wallets.
    import chains, glob, stash
    from public_constants import AF_CLASSIC
    from ux import show_qr_code

    chain = chains.current_chain()
    acct = 0

    # decode menu code => standard derivation
    mode = item.arg
    if mode == -1:
        # XFP shortcut
        xfp = xfp2str(settings.get('xfp', 0))
        await show_qr_code(xfp, True)
        return 

    elif mode == 0:
        path = "m"
        addr_fmt = AF_CLASSIC
    else:
        remap = {44:0, 49:1, 84:2}[mode]
        _, path, addr_fmt = chains.CommonDerivations[remap]
        path = path.format(account='{acct}', coin_type=chain.b44_cointype, change=0, idx=0)[:-4]

    # always show SLIP-132 style, because defacto
    show_slip132 = (addr_fmt != AF_CLASSIC)

    while 1:
        msg = '''Show QR of the XPUB for path:\n\n%s\n\n''' % path

        if '{acct}' in path:
            msg += "Press 1 to select account other than zero. "
        if glob.NFC:
            msg += "Press 3 to share over NFC. "

        ch = await ux_show_story(msg, escape='13')
        if ch == 'x': return
        if ch == '1':
            acct = await ux_enter_number('Account Number:', 9999) or 0
            path = path.format(acct=acct)
            continue

        # assume zero account if not picked
        path = path.format(acct=acct)

        from glob import dis
        dis.fullscreen('Wait...')

        # render xpub/ypub/zpub
        with stash.SensitiveValues() as sv:
            node = sv.derive_path(path) if path != 'm' else sv.node
            xpub = chain.serialize_public(node, addr_fmt)

        if ch == '3' and glob.NFC:
            await glob.NFC.share_text(xpub)
        else:
            from ux import show_qr_code
            await show_qr_code(xpub, False)

        break
        

def electrum_export_story(background=False):
    # saves memory being in a function
    return ('''\
This saves a skeleton Electrum wallet file. \
You can then open that file in Electrum without ever connecting this Coldcard to a computer.\n
''' 
        + (background or 'Choose an address type for the wallet on the next screen.'+PICK_ACCOUNT)
        + SENSITIVE_NOT_SECRET)

async def electrum_skeleton(*a):
    # save xpub, and some other public details into a file: NOT MULTISIG

    ch = await ux_show_story(electrum_export_story(), escape='1')

    account_num = 0
    if ch == '1':
        account_num = await ux_enter_number('Account Number:', 9999) or 0
    elif ch != 'y':
        return

    # pick segwit or classic derivation+such
    from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
    from menu import MenuSystem, MenuItem

    # Ordering and terminology from similar screen in Electrum. I prefer
    # 'classic' instead of 'legacy' personallly.
    rv = []

    rv.append(MenuItem("Legacy (P2PKH)", f=electrum_skeleton_step2, arg=(AF_CLASSIC, account_num)))
    rv.append(MenuItem("P2SH-Segwit", f=electrum_skeleton_step2, arg=(AF_P2WPKH_P2SH, account_num)))
    rv.append(MenuItem("Native Segwit", f=electrum_skeleton_step2, arg=(AF_P2WPKH, account_num)))

    return MenuSystem(rv)

async def bitcoin_core_skeleton(*A):
    # save output descriptors into a file
    # - user has no choice, it's going to be bech32 with  m/84'/{coin_type}'/0' path

    ch = await ux_show_story('''\
This saves commands and instructions into a file, including the public keys (xpub). \
You can then run the commands in Bitcoin Core's console window, \
without ever connecting this Coldcard to a computer.\
''' + PICK_ACCOUNT + SENSITIVE_NOT_SECRET, escape='1')

    account_num = 0
    if ch == '1':
        account_num = await ux_enter_number('Account Number:', 9999) or 0
    elif ch != 'y':
        return

    # no choices to be made, just do it.
    import export
    await export.make_bitcoin_core_wallet(account_num)


async def electrum_skeleton_step2(_1, _2, item):
    # pick a semi-random file name, render and save it.
    import export
    addr_fmt, account_num = item.arg
    await export.make_json_wallet('Electrum wallet',
                                    lambda: export.generate_electrum_wallet(addr_fmt, account_num))

async def generic_skeleton(*A):
    # like the Multisig export, make a single JSON file with
    # basically all useful XPUB's in it.

    if await ux_show_story('''\
Saves JSON file, with XPUB values that are needed to watch typical \
single-signer UTXO associated with this Coldcard.''' + SENSITIVE_NOT_SECRET) != 'y':
        return

    account_num = await ux_enter_number('Account Number:', 9999) or 0

    # no choices to be made, just do it.
    import export
    await export.make_json_wallet('Generic Export',
                                    lambda: export.generate_generic_export(account_num),
                                    'coldcard-export.json')


async def wasabi_skeleton(*A):
    # save xpub, and some other public details into a file
    # - user has no choice, it's going to be bech32 with  m/84'/0'/0' path

    if await ux_show_story('''\
This saves a skeleton Wasabi wallet file. \
You can then open that file in Wasabi without ever connecting this Coldcard to a computer.\
''' + SENSITIVE_NOT_SECRET) != 'y':
        return

    # no choices to be made, just do it.
    import export
    await export.make_json_wallet('Wasabi wallet', lambda: export.generate_wasabi_wallet(), 'new-wasabi.json')

async def unchained_capital_export(*a):
    # they were using our airgapped export, and the BIP-45 path from that
    #
    if await ux_show_story('''\
This saves multisig XPUB information required to setup on the Unchained Capital platform. \
''' + SENSITIVE_NOT_SECRET) != 'y':
        return

    xfp = xfp2str(settings.get('xfp', 0))
    fname = 'unchained-%s.json' % xfp

    import export
    await export.make_json_wallet('Unchained Capital', lambda: export.generate_unchained_export(), fname)


async def backup_everything(*A):
    # save everything, using a password, into single encrypted file, typically on SD
    import backups

    await backups.make_complete_backup()

async def verify_backup(*A):
    # check most recent backup is "good"
    # read 7z header, and measure checksums
    import backups

    fn = await file_picker('Select file containing the backup to be verified. No password will be required.', suffix='.7z', max_size=backups.MAX_BACKUP_FILE_SIZE)

    if not fn:
        return

    # do a limited CRC-check over encrypted file
    await backups.verify_backup_file(fn)

async def import_xprv(*A):
    # read an XPRV from a text file and use it.
    import ngu, chains, ure
    from stash import SecretStash
    from ubinascii import hexlify as b2a_hex
    from backups import restore_from_dict

    assert pa.is_secret_blank() # "must not have secret"

    def contains_xprv(fname):
        # just check if likely to be valid; not full check
        try:
            with open(fname, 'rt') as fd:
                for ln in fd:
                    # match tprv and xprv, plus y/zprv etc
                    if 'prv' in ln: return True
                return False
        except OSError:
            # directories?
            return False

    # pick a likely-looking file.
    fn = await file_picker('Select file containing the XPRV to be imported.',
                                min_size=50, max_size=2000, taster=contains_xprv)

    if not fn: return

    node, chain, addr_fmt = None, None, None

    # open file and do it
    pat = ure.compile(r'.prv[A-Za-z0-9]+')
    node = None
    with CardSlot() as card:
        with open(fn, 'rt') as fd:
            for ln in fd.readlines():
                if 'prv' not in ln: continue

                found = pat.search(ln)
                if not found: continue
                found = found.group(0)

                try:
                    node, chain, addr_fmt, is_priv = chains.slip32_deserialize(found)
                    break
                except:
                    continue

    if not node:
        # unable
        await ux_show_story('''\
Sorry, wasn't able to find an extended private key to import. It should be at \
the start of a line, and probably starts with "xprv".''', title="FAILED")
        return

    # encode it in our style
    d = dict(chain=chain.ctype, raw_secret=b2a_hex(SecretStash.encode(xprv=node)))
    node.blank()

    # Should capture the address format implied by SLIP32 version bytes
    # (addr_fmt var here) but no means to store that in our settings, and we're
    # not supposed to care anyway.
    # TODO: would be nice for addr explorer tho

    # restore as if it was a backup (code reuse)
    await restore_from_dict(d)
   
    # not reached; will do reset. 
                            
EMPTY_RESTORE_MSG = '''\
You must clear the wallet seed before restoring a backup because it replaces \
the seed value and the old seed would be lost.\n\n\
Visit the advanced menu and choose 'Destroy Seed'.'''

async def restore_everything(*A):

    if not pa.is_secret_blank():
        await ux_show_story(EMPTY_RESTORE_MSG)
        return

    # restore everything, using a password, from single encrypted 7z file
    fn = await file_picker('Select file containing the backup to be restored, and '
                            'then enter the password.', suffix='.7z', max_size=10000)

    if fn:
        import backups
        await backups.restore_complete(fn)

async def restore_everything_cleartext(*A):
    # Asssume no password on backup file; devs and crazy people only

    if not pa.is_secret_blank():
        await ux_show_story(EMPTY_RESTORE_MSG)
        return

    # restore everything, using NO password, from single text file, like would be wrapped in 7z
    fn = await file_picker('Select the cleartext file containing the backup to be restored.',
                             suffix='.txt', max_size=10000)

    if fn:
        import backups
        prob = await backups.restore_complete_doit(fn, [])
        if prob:
            await ux_show_story(prob, title='FAILED')

async def wipe_filesystem(*A):
    if not await ux_confirm('''\
Erase internal filesystem and rebuild it. Resets contents of internal flash area \
used for settings and HSM config file. Does not affect funds, or seed words but \
will reset settings used with other BIP39 passphrases. \
Does not affect MicroSD card, if any.'''):
        return

    from files import wipe_flash_filesystem
    wipe_flash_filesystem()

async def wipe_vdisk(*A):
    if not await ux_confirm('''\
Erases and reformats shared RAM disk. This is a secure erase that blanks every byte.'''):
        return

    import glob
    await glob.VD.wipe_disk()

async def wipe_sd_card(*A):
    if not await ux_confirm('''\
Erases and reformats MicroSD card. This is not a secure erase but more of a quick format.'''):
        return

    from files import wipe_microsd_card
    wipe_microsd_card()


async def nfc_share_file(*A):
    # Mk4: Share txt, txn and PSBT files over NFC.
    from glob import NFC
    if NFC: 
        await NFC.share_file()


async def nfc_recv_ephemeral(*A):
    # Mk4: Share txt, txn and PSBT files over NFC.
    from glob import NFC
    if NFC:
        await NFC.import_ephemeral_seed_words_nfc()


async def list_files(*A):
    # list files, don't do anything with them?
    fn = await file_picker('Lists all files, select one and SHA256(file contents) will be shown.', min_size=0)
    if not fn: return

    from uhashlib import sha256
    from utils import B2A
    chk = sha256()

    try:
        with CardSlot() as card:
            with card.open(fn, 'rb') as fp:
                while 1:
                    data = fp.read(1024)
                    if not data: break
                    chk.update(data)
    except CardMissingError:
        await needs_microsd()
        return

    basename = fn.rsplit('/', 1)[-1]

    ch = await ux_show_story('''SHA256(%s)\n\n%s\n\nPress 6 to delete.''' % (basename, B2A(chk.digest())), escape='6')

    if ch == '6':
        with CardSlot() as card:
            card.securely_blank_file(fn)

    return

async def file_picker(msg, suffix=None, min_size=1, max_size=1000000, taster=None, choices=None, escape=None, none_msg=None, title=None):
    # present a menu w/ a list of files... to be read
    # - optionally, enforce a max size, and provide a "tasting" function
    # - if msg==None, don't prompt, just do the search and return list
    # - if choices is provided; skip search process
    # - escape: allow these chars to skip picking process
    from menu import MenuSystem, MenuItem
    import uos
    from utils import get_filesize

    if choices is None:
        choices = []
        try:
            with CardSlot() as card:
                sofar = set()

                for path in card.get_paths():
                    for fn, ftype, *var in uos.ilistdir(path):
                        if ftype == 0x4000:
                            # ignore subdirs
                            continue

                        if suffix and not fn.lower().endswith(suffix):
                            # wrong suffix
                            continue

                        if fn[0] == '.': continue

                        full_fname = path + '/' + fn

                        # Conside file size
                        # sigh, OS/filesystem variations
                        file_size = var[1] if len(var) == 2 else get_filesize(full_fname)

                        if not (min_size <= file_size <= max_size):
                            continue

                        if taster is not None:
                            try:
                                yummy = taster(full_fname)
                            except IOError:
                                #print("fail: %s" % full_fname)
                                yummy = False

                            if not yummy:
                                continue

                        label = fn
                        while label in sofar:
                            # just the file name isn't unique enough sometimes?
                            # - shouldn't happen anymore now that we dno't support internal FS
                            # - unless we do muliple paths
                            label += path.split('/')[-1] + '/' + fn

                        sofar.add(label)
                        choices.append((label, path, fn))

        except CardMissingError:
            # don't show anything if we're just gathering data
            if msg is not None:
                await needs_microsd()
            return None

    if msg is None:
        return choices

    if not choices:
        msg = none_msg or 'Unable to find any suitable files for this operation. '

        if not none_msg:
            if suffix:
                msg += 'The filename must end in "%s". ' % suffix

            msg += '\n\nMaybe insert (another) SD card and try again?'

        await ux_show_story(msg)
        return

    # tell them they need to pick; can quit here too, but that's obvious.
    if len(choices) != 1:
        msg += '\n\nThere are %d files to pick from.' % len(choices)
    else:
        msg += '\n\nThere is only one file to pick from.'

    ch = await ux_show_story(msg, escape=escape, title=title)
    if escape and ch in escape: return ch
    if ch == 'x': return

    picked = []
    async def clicked(_1,_2,item):
        picked.append('/'.join(item.arg))
        the_ux.pop()

    choices.sort()

    items = [MenuItem(label, f=clicked, arg=(path, fn)) for label, path, fn in choices]

    menu = MenuSystem(items)
    the_ux.push(menu)

    await menu.interact()

    return picked[0] if picked else None

async def debug_assert(*a):
    assert False, "failed assertion"

async def debug_except(*a):
    print(34 / 0)

async def check_firewall_read(*a):
    import uctypes
    ps = uctypes.bytes_at(0x7800, 32)       # off the mark for mk4, but still valid test
    assert False        # should not be reached

async def bless_flash(*a):
    # make green LED turn on
    from glob import dis

    if pa.is_secondary:
        await needs_primary()
        return

    # do it
    pa.greenlight_firmware()
    dis.show()


async def ready2sign(*a):
    # Top menu choice of top menu! Signing!
    # - check if any signable in SD card, if so do it
    # - if no card, check virtual disk for PSBT
    # - if still nothing, then talk about USB connection
    from version import MAX_TXN_LEN
    import stash
    from glob import NFC

    def is_psbt(filename):
        if '-signed' in filename.lower():       # XXX problem: multi-signers?
            return False

        with open(filename, 'rb') as fd:
            taste = fd.read(10)
            if taste[0:5] == b'psbt\xff':
                return True
            if taste[0:10] == b'70736274ff':        # hex-encoded
                return True
            if taste[0:6] == b'cHNidP':             # base64-encoded
                return True
            return False

    # just check if we have candidates, no UI
    choices = await file_picker(None, suffix='psbt', min_size=50,
                            max_size=MAX_TXN_LEN, taster=is_psbt)
    
    if stash.bip39_passphrase:
        title = '[%s]' % settings.get('xfp')
    else:
        title = None

    if not choices:
        msg = '''Coldcard is ready to sign spending transactions!

Put the proposed transaction onto MicroSD card \
in PSBT format (Partially Signed Bitcoin Transaction) \
or upload a transaction to be signed \
from your desktop wallet software or command line tools.\n\n'''

        if NFC:
            msg += 'Press 3 to send PSBT using NFC.\n\n'
    
        msg += "You will always be prompted to confirm the details before \
any signature is performed."

        ch = await ux_show_story(msg, title=title, escape='3')
        if ch == '3' and NFC:
            await NFC.start_psbt_rx()

        return

    if len(choices) == 1:
        # skip the menu
        label,path,fn = choices[0]
        input_psbt = path + '/' + fn
    else:
        input_psbt = await file_picker('Choose PSBT file to be signed.', choices=choices, title=title)
        if not input_psbt:
            return

    # start the process
    from auth import sign_psbt_file

    await sign_psbt_file(input_psbt)


async def sign_message_on_sd(*a):
    # Menu item: choose a file to be signed (as a short text message)
    #
    def is_signable(filename):
        if '-signed' in filename.lower():
            return False
        with open(filename, 'rt') as fd:
            lines = fd.readlines()
            return (1 <= len(lines) <= 5)

    fn = await file_picker('Choose text file to be signed.',
                            suffix='txt', min_size=2,
                            max_size=500, taster=is_signable,
            none_msg='No suitable files found. Must be one line of text, in a .TXT file, optionally followed by a subkey derivation path on a second line.')

    if not fn:
        return

    # start the process
    from auth import sign_txt_file
    await sign_txt_file(fn)


async def pin_changer(_1, _2, item):
    # Help them to change pins with appropriate warnings.
    # - forcing them to drill-down to get warning about secondary is on purpose
    # - the bootloader maybe lying to us about weather we are main vs. duress
    # - there is a duress wallet for both main/sec pins, and you need to know main pin for that(mk3)
    # - what may look like just policy here, is in fact enforced by the bootrom code
    #
    from glob import dis
    from login import LoginUX
    from pincodes import BootloaderError, EPIN_OLD_AUTH_FAIL

    mode = item.arg

    # NOTE: for mk4, only "main" is applicable.

    warn = {'main': ('Main PIN',
                    'You will be changing the main PIN used to unlock your Coldcard. '
                    "It's the one you just used a moment ago to get in here."),
            'duress': ('Duress PIN',
                        'This PIN leads to a bogus wallet. Funds are recoverable '
                        'from main seed backup, but not as easily.'),
            'secondary': ('Second PIN',
                        'This PIN protects the "secondary" wallet that can be used to '
                         'segregate funds or other banking purposes. This other wallet is '
                         'completely independant of the primary.'),
            'brickme': ('Brickme PIN',
                       'Use of this special PIN code at any prompt will destroy the '
                       'Coldcard completely. It cannot be reused or salvaged, and '
                       'the secrets it held are destroyed forever.\n\nDO NOT TEST THIS!'),
    }

    if pa.is_secondary:
        # secondary wallet user can only change their own password, and the secondary
        # duress pin... 
        # - now excluded from menu, but keep for Mark1/2 hardware!
        if mode == 'main' or mode == 'brickme':
            await needs_primary()
            return

    if mode == 'duress' and pa.is_secret_blank():
        await ux_show_story("Please set wallet seed before creating duress wallet.")
        return

    # are we changing the pin used to login?
    is_login_pin = (mode == 'main') or (mode == 'secondary' and pa.is_secondary)

    lll = LoginUX()
    lll.offer_second = False
    title, msg = warn[mode]

    async def incorrect_pin():
        await ux_show_story('You provided an incorrect value for the existing %s.' % title, 
                                title='Wrong PIN')
        return

    # standard threats for all PIN's
    msg += '''\n\n\
THERE IS ABSOLUTELY NO WAY TO RECOVER A FORGOTTEN PIN! Write it down.

We strongly recommend all PIN codes used be unique between each other.
'''
    if not is_login_pin:
        msg += '''\nUse 999999-999999 to clear existing PIN.'''

    ch = await ux_show_story(msg, title=title)
    if ch != 'y': return

    args = {}

    need_old_pin = True

    if is_login_pin:
        # Challenge them for old password; they probably have it, and we have it
        # in memory already, because we wouldn't be here otherwise... but 
        # challenge them anyway as a policy choice.
        need_old_pin = True
    else:
        # There may be no existing PIN, and we need to learn that

        if mode == 'secondary':
            args['is_secondary'] = True

        elif mode == 'duress':

            args['is_duress'] = True

            need_old_pin = bool(pa.has_duress_pin())

        elif mode == 'brickme':
            args['is_brickme'] = True

            need_old_pin = bool(pa.has_brickme_pin())

        if need_old_pin and not version.has_608:
            # Do an expensive check (mostly for secondary pin case?)
            try:
                dis.fullscreen("Check...")
                pa.change(old_pin=b'', new_pin=b'', **args)
                need_old_pin = False
            except BootloaderError as exc:
                # not an error: old pin in non-blank
                need_old_pin = True

    if not need_old_pin:
        # It is blank
        old_pin = ''
    else:
        # We need the existing pin, so prompt for that.
        lll.subtitle = 'Old ' + title

        old_pin = await lll.prompt_pin()
        if old_pin is None:
            return await ux_aborted()

    args['old_pin'] = old_pin.encode()

    # we can verify the main pin right away here. Be nice.
    if is_login_pin and args['old_pin'] != pa.pin:
        return await incorrect_pin()

    while 1:
        lll.reset()
        lll.subtitle = "New " + title
        pin = await lll.get_new_pin(title, allow_clear=True)

        if pin is None:
            return await ux_aborted()

        is_clear = (pin == CLEAR_PIN)

        args['new_pin'] = pin.encode() if not is_clear else b''

        if args['new_pin'] == pa.pin and not is_login_pin:
            await ux_show_story("Your new PIN matches the existing PIN used to get here. "
                                "It would be a bad idea to use it for another purpose.",
                                title="Try Again")
            continue

        if version.mk_num >= 4:
            from trick_pins import tp
            prob = tp.check_new_main_pin(pin)
            if prob:
                await ux_show_story(prob, title="Try Again")
                continue

        break

    # install it.
    try:
        dis.fullscreen("Clearing..." if is_clear else "Saving...")
        dis.busy_bar(True)

        pa.change(**args)
        dis.busy_bar(False)
    except Exception as exc:
        dis.busy_bar(False)

        code = exc.args[1]

        if code == EPIN_OLD_AUTH_FAIL:
            # likely: wrong old pin, on anything but main PIN
            return await incorrect_pin()
        else:
            return await ux_show_story("Unexpected low-level error: %s" % exc.args[0],
                                            title='Error')

    # Main pin is changed, and we use it lots, so update pa
    # - also we need pa.has_duress_pin() and has_brickme_pin() to be correct
    # - this step can be super slow with 608, unfortunately
    try:
        dis.fullscreen("Verify...")
        dis.busy_bar(True)

        pa.setup(args['new_pin'] if is_login_pin else pa.pin, pa.is_secondary)

        if not pa.is_successful():
            # typical: do need login, but if we just cleared the main PIN,
            # we cannot/need not login again
            pa.login()

        if version.mk_num >= 4:
            # Deltamode trick pins need to track main pin
            from trick_pins import tp
            tp.main_pin_has_changed(pa.pin.decode())

        if mode == 'duress':
            # program the duress secret now... it's derived from real wallet contents
            from stash import SensitiveValues, SecretStash, AE_SECRET_LEN

            if is_clear:
                # clear secret, using the new pin, which is empty string
                pa.change(is_duress=True, new_secret=b'\0' * AE_SECRET_LEN, old_pin=b'')
            else:
                with SensitiveValues() as sv:
                    # derive required key
                    node, _ = sv.duress_root()
                    d_secret = SecretStash.encode(xprv=node)
                    sv.register(d_secret)
        
                    # write it out.
                    pa.change(is_duress=True, new_secret=d_secret, old_pin=args['new_pin'])

    finally:
        dis.busy_bar(False)

async def show_version(*a):
    # show firmware, bootload versions.
    import callgate, version
    from ubinascii import hexlify as b2a_hex
    from glob import NFC

    built, rel, *_ = version.get_mpy_version()
    bl = callgate.get_bl_version()[0]
    chk = str(b2a_hex(callgate.get_bl_checksum(0))[-8:], 'ascii')

    if version.has_se2:
        se = '\n  '.join(callgate.get_se_parts())
    else:
        se = 'ATECC'
        if version.has_608:
            se += '608B' if callgate.has_608b() else '608A'
        else:
            se += '508A'

    # exposed over USB interface:
    serial = version.serial_number()

    # this UID is exposed over NFC interface, but only when enabled and in active use
    if NFC:
        serial += '\n\nNFC UID:\n' + NFC.get_uid().replace(':', '')

    hw = version.hw_label
    if not version.has_nfc and version.mk_num >= 4:
        hw += ' (no NFC)'

    msg = '''\
Coldcard Firmware

  {rel}
  {built}


Bootloader:
  {bl}
  {chk}

Serial:
  {ser}

Hardware:
  {hw}

Secure Element{ses}:
  {se}
'''

    await ux_show_story(msg.format(rel=rel, built=built, bl=bl, chk=chk, se=se,
                            ser=serial, hw=hw, 
                ses='s' if version.has_se2 else ''))

async def ship_wo_bag(*a):
    # Factory command: for dev and test units that have no bag number, and never will.
    ok = await ux_confirm('''Not recommended! DO NOT USE for units going to paying customers.''')
    if not ok: return

    import callgate
    from glob import dis 
    from version import is_devmode

    failed = callgate.set_bag_number(b'NOT BAGGED')      # 32 chars max

    if failed:
        await ux_dramatic_pause('FAILED', 30)
    else:
        # lock the bootrom firmware forever
        callgate.set_rdp_level(2 if not is_devmode else 0)

        # bag number affects green light status (as does RDP level)
        pa.greenlight_firmware()
        dis.fullscreen('No Bag. DONE')
        callgate.show_logout(1)

async def set_highwater(*a):
    # rarely? used command
    import callgate

    have = version.get_mpy_version()[0]
    ts = version.get_header_value('timestamp')

    hw = callgate.get_highwater()

    if hw == ts:
        await ux_show_story('''Current version (%s) already marked as high-water mark.''' % have)
        return

    ok = await ux_confirm('''Mark current version (%s) as the minimum, and prevent any downgrades below this version.

Rarely needed as critical security updates will set this automatically.''' % have)

    if not ok: return

    rv = callgate.set_highwater(ts)

    # add error display here? meh.

    assert rv == 0, "Failed: %r" % rv

async def start_hsm_menu_item(*a):
    from hsm_ux import start_hsm_approval 
    await start_hsm_approval(sf_len=0, usb_mode=False)

async def wipe_hsm_policy(*A):
    # deep in danger zone menu; no background story, nor confirmation
    # - sends them back to top menu, so that dynamic contents are fixed
    from hsm import hsm_delete_policy
    hsm_delete_policy()
    goto_top_menu()

async def wipe_ovc(*a):
    # Factory command: for dev and test units that have no bag number, and never will.
    ok = await ux_confirm('''Clear history of segwit UTXO input values we have seen already. \
This data protects you against specific attacks. Use this only if certain a false-positive \
has occured in the detection logic.''')
    if not ok: return

    import history
    history.OutptValueCache.clear()

    await ux_dramatic_pause("Cleared.", 3)

async def change_usb_disable(dis):
    # user has disabled USB port (or re-enabled)
    import pyb
    cur = pyb.usb_mode()

    from usb import enable_usb, disable_usb
    if cur and dis:
        # usb enabled, but should not be now
        disable_usb()
    elif not cur and not dis:
        # USB disabled, but now should be
        enable_usb()

async def usb_keyboard_emulation(enable):
    # just sets emu flag on and adds Entry Password into top menu
    # no USB switching at this point
    # - need to force reload of main menu, so it shows/hides
    new_top_menu = make_top_menu()
    the_ux.stack[0] = new_top_menu  # top menu is always element 0

async def change_nfc_enable(enable):
    # NFC enable / disable
    import glob
    from glob import NFC
    import nfc

    if not enable:
        if glob.NFC:
            glob.NFC.shutdown()
    else:
        nfc.NFCHandler.startup()

async def change_virtdisk_enable(enable):
    # NOTE: enable can be 0,1,2
    import glob, vdisk
    from usb import enable_usb, disable_usb

    if bool(enable) == bool(glob.VD):
        # not a change in state, do nothing
        return

    if enable:
        # just showing up as new media is enough (MacOS) to make it show up
        vdisk.VirtDisk()
        assert glob.VD
    else:
        assert glob.VD
        glob.VD.shutdown()
        assert not glob.VD

async def change_which_chain(name):
    # setting already changed, but reflect that value in other settings
    try:
        # update xpub stored in settings
        import stash
        with stash.SensitiveValues() as sv:
            sv.capture_xpub()
    except ValueError:
        # no secrets yet, not an error
        pass


# EOF
