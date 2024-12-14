# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# actions.py
#
# Every function here is called directly by a menu item. They should all be async.
#
import ckcc, pyb, version, uasyncio, sys, uos
from uhashlib import sha256
from uasyncio import sleep_ms
from ubinascii import hexlify as b2a_hex
from utils import imported, problem_file_line, get_filesize, encode_seed_qr
from utils import xfp2str, B2A, addr_fmt_label, txid_from_fname
from ux import ux_show_story, the_ux, ux_confirm, ux_dramatic_pause, ux_aborted
from ux import ux_enter_bip32_index, ux_input_text, import_export_prompt, OK, X
from export import make_json_wallet, make_summary_file, make_descriptor_wallet_export
from export import make_bitcoin_core_wallet, generate_wasabi_wallet, generate_generic_export
from export import generate_unchained_export, generate_electrum_wallet
from files import CardSlot, CardMissingError, needs_microsd
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR, MAX_TXN_LEN_MK4
from glob import settings
from pincodes import pa
from menu import start_chooser, MenuSystem, MenuItem
from version import MAX_TXN_LEN
from charcodes import KEY_NFC, KEY_QR, KEY_CANCEL


CLEAR_PIN = '999999-999999'

async def start_selftest(*args):
    # selftest is harmless, no need to warn anymore,
    # but this layer saves memory in typical cases
    with imported('selftest') as st:
        await st.start_selftest()

async def show_bag_number(*a):
    import callgate
    bn = callgate.get_bag_number() or 'UNBAGGED!'

    await ux_show_story('''\
Your new Coldcard should have arrived SEALED in a bag with the above number. Please take a moment to confirm the number and look for any signs of tampering.

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
  coldcard.com/legal

Press %s to accept terms and continue.""" % OK, escape='7')

        if ch == 'y':
            break

    await show_bag_number()

    # Note fact they accepted the terms. Annoying to do more than once.
    settings.set('terms_ok', 1)
    settings.save()

async def view_ident(*a):
    # show the XPUB, and other ident on screen
    import callgate, stash

    msg = ""
    if stash.bip39_passphrase:
        msg += 'BIP-39 passphrase is in effect.\n\n'
    elif pa.tmp_value:
        msg += 'Temporary seed is in effect.\n\n'

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
    msg += tpl.format(xpub=(xpub or '(none yet)'),
                      xfp=xfp2str(my_xfp),
                      serial=version.serial_number())

    bn = callgate.get_bag_number()
    if bn:
        msg += '\nShipping Bag:\n  %s\n' % bn

    if xpub:
        msg += '\nPress %s to show QR code of xpub.' % (
            KEY_QR if version.has_qwerty else "(3)"
        )

    ch = await ux_show_story(msg, escape=('3'+KEY_QR if xpub else None))

    if ch in '3'+KEY_QR:
        # show the QR
        from ux import show_qr_code
        await show_qr_code(xpub, False)


async def show_settings_space(*a):
    percentage_capacity = int(settings.get_capacity() * 100)
    if percentage_capacity < 10:
        percentage_capacity = 10
    await ux_show_story('Settings storage space in use:\n\n'
                        '       %d%%' % percentage_capacity)

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

async def microsd_upgrade(menu, label, item):
    # Upgrade vis MicroSD card
    # - search for a particular file
    # - verify it lightly
    # - erase serial flash
    # - copy it over (slow)
    # - reboot into bootloader, which finishes install
    from glob import dis, PSRAM
    from files import dfu_parse
    from utils import check_firmware_hdr
    from sigheader import FW_HEADER_OFFSET, FW_HEADER_SIZE, FW_MAX_LENGTH_MK4

    if version.has_battery:
        import battery
        lvl = battery.get_batt_threshold()
        if lvl is not None and lvl <= 1:
            await ux_show_story("Battery power is somewhat low right now. "
"Please install fresh batteries or connect USB power during upgrade process.", title="Low Battery")
            return

    force_vdisk = item.arg
    fn = await file_picker(suffix='.dfu', min_size=0x7800, max_size=FW_MAX_LENGTH_MK4,
                           force_vdisk=force_vdisk)

    if not fn: return

    failed = None
    with CardSlot(force_vdisk=force_vdisk) as card:
        with card.open(fn, 'rb') as fp:
            try:
                offset, size = dfu_parse(fp)

                # read just the signature header
                hdr = bytearray(FW_HEADER_SIZE)
                fp.seek(offset + FW_HEADER_OFFSET)
                rv = fp.readinto(hdr)
                assert rv == FW_HEADER_SIZE

                # check header values
                failed = check_firmware_hdr(hdr, size)
            except Exception as exc:
                # recover from garbage DFU files.
                failed = "Failed: " + str(exc)

            if not failed:
                # copy binary into PSRAM
                fp.seek(offset)

                dis.fullscreen("Loading...")

                buf = bytearray(0x20000)
                pos = 0
                while pos < size:
                    dis.progress_bar_show(pos/size)

                    here = fp.readinto(buf)
                    if not here: break

                    PSRAM.write(pos, buf)
                    pos += here

    if failed:
        await ux_show_story(failed, title='Sorry!')
        return

    # continue process...
    from auth import FirmwareUpgradeRequest
    m = FirmwareUpgradeRequest(hdr, size, psram_offset=0)
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

Your new PIN protects access to 
this Coldcard device and is not a factor in the wallet's \
seed words or private keys.

THERE IS ABSOLUTELY NO WAY TO RECOVER A FORGOTTEN PIN! Write it down.
''', title=title)
    if ch != 'y': return

    while 1:
        ch = await ux_show_story('''\
There is ABSOLUTELY NO WAY to 'reset the PIN' or 'factory reset' the Coldcard if you forget the PIN.

DO NOT FORGET THE PIN CODE.

Press (6) to prove you read to the end of this message.''', title='WARNING', escape='6')

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

    from flow import EmptyWallet
    return MenuSystem(EmptyWallet)

async def block_until_login():
    #
    # Force user to enter a valid PIN.
    # 
    from login import LoginUX
    from ux import AbortInteraction

    # maybe show a calculator rather than login screen
    try:
        if version.has_qwerty and settings.get('calc', 0):
            with imported('calc') as calc:
                await calc.login_repl()
            return 
    except:
        pass

    # do they want a randomized (shuffled) keypad?
    rnd_keypad = settings.get('rngk', 0)

    # single key that "kills" self if pressed on "words" screen
    kill_btn = settings.get('kbtn', None)

    rv = None       # might already be logged-in if _skip_pin used

    while not pa.is_successful():
        lll = LoginUX(rnd_keypad, kill_btn)

        try:
            rv = await lll.try_login(bypass_pin=None)
            if rv: break
        except AbortInteraction:
            # not allowed!
            pass

    return rv

async def show_nickname(nick):
    # Show a nickname for this coldcard (as a personalization)
    # - no keys here, just show it until they press anything
    from glob import dis
    from ux import ux_wait_keyup
    import callgate

    dis.clear()

    if dis.has_lcd:
        from lcd_display import CHARS_W, CHARS_H
        from utils import word_wrap

        lines = list(word_wrap(nick, CHARS_W))
        y = ((CHARS_H - len(lines) + 1) // 2) - 1
        for n, ln in enumerate(lines):
            dis.text(None, y+n, ln)
    else:
        from display import FontLarge, FontSmall

        if dis.width(nick, FontLarge) <= dis.WIDTH:
            dis.text(None, 21, nick, font=FontLarge)
        else:
            dis.text(None, 27, nick, font=FontSmall)

    dis.show()

    ch = await ux_wait_keyup(flush=True)

    if ch.upper() == settings.get('kbtn', None):
        # support kill btn on nick screen too
        callgate.fast_wipe(False)
        

async def pick_killkey(*a):
    # Setting: kill seed sometimes (requires mk4)
    if version.has_qwerty:
        msg = '''\
If you press this key at any point during login, your seed phrase will be immediately wiped.'''
    else:
        msg = '''\
If you press this key while the anti- phishing words are shown during login, \
your seed phrase will be immediately wiped.

Best if this does not match the first number of the second half of your PIN.'''

    if await ux_show_story(msg) != 'y':
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
    s = SettingsObject.prelogin()
    nick = s.get('nick', '')

    if not nick:
        ch = await ux_show_story('''\
You can give this Coldcard a nickname and it will be shown before login.''')
        if ch != 'y': return

    nn = await ux_input_text(nick, confirm_exit=False, prompt="Enter Nickname")

    from glob import dis
    dis.fullscreen("Saving...")
    dis.busy_bar(True)

    nn = nn.strip() if nn else None
    s.set('nick', nn)
    s.save()
    dis.busy_bar(False)
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

async def start_seed_import(menu, label, item):
    import seed
    if version.has_qwerty:
        from ux_q1 import seed_word_entry
        await seed_word_entry('Enter Seed Words', item.arg,
                                            done_cb=seed.commit_new_words)
    else:
        return seed.WordNestMenu(item.arg)

async def pick_new_seed(menu, label, item):
    import seed
    return await seed.make_new_wallet(item.arg)

async def new_from_dice(menu, label, item):
    import seed
    return await seed.new_from_dice(item.arg)

async def any_active_duress_ux():
    from trick_pins import tp
    tp.reload()
    if any(tp.get_duress_pins()):
        await ux_show_story('You have one or more duress wallets defined '
                            'under Trick PINs. Please empty them, and clear '
                            'associated Trick PINs before continuing.')
        return True
    return False

async def convert_ephemeral_to_master(*a):
    import seed
    from stash import bip39_passphrase

    words = settings.get("words", True)
    _type = 'BIP-39 passphrase' if bip39_passphrase else 'temporary seed'
    msg = 'Convert currently used %s to master seed. Old master seed' % _type
    if words or bip39_passphrase:
        msg += ' words themselves are erased forever, '
    else:
        msg += ' is erased forever, '

    msg += ('and its settings blanked. This action is destructive '
            'and may affect funds, if any, on old master seed. '
            'Make sure all duress wallets associated with previous '
            'seed are deleted, otherwise they will be carried forward '
            'without being properly generated from new master seed. '
            'Saved temporary seed settings and Seed Vault are lost. ')

    if bip39_passphrase:
        msg += ('BIP-39 passphrase '
                'is captured during this process and will be in effect '
                'going forward, but the passphrase itself is erased '
                'and unrecoverable. ')
    if not words:
        msg += 'The resulting wallet cannot be used with any other passphrase. '

    msg += 'A reboot is part of this process. '
    msg += 'PIN code, and %s funds are not affected.' % _type
    if not await ux_confirm(msg):
        return await ux_aborted()

    # settings.save is part of re-building fs
    await seed.remember_ephemeral_seed()
    await login_now()

async def clear_seed(*a):
    # Erase the seed words, and private key from this wallet!
    # This is super dangerous for the customer's money.
    import seed

    if await any_active_duress_ux():
        return await ux_aborted()

    if not await ux_confirm('Wipe seed words and reset wallet. '
                            'All funds will be lost. '
                            'You better have a backup of the seed words.'
                            'All settings like multisig wallets are also wiped. '
                            'Saved temporary seed settings and Seed Vault are lost.'):
        return await ux_aborted()

    ch = await ux_show_story('''Are you REALLY sure though???\n\n\
This action will certainly cause you to lose all funds associated with this wallet, \
unless you have a backup of the seed words and know how to import them into a \
new wallet.\n\nPress (4) to prove you read to the end of this message and accept all \
consequences.''', escape='4')
    if ch != '4':
        return await ux_aborted()

    # clear settings, address cache, settings from tmp seeds / seedvault seeds
    from files import wipe_flash_filesystem
    wipe_flash_filesystem(False)

    seed.clear_seed()
    # NOT REACHED -- reset happens


def render_master_secrets(mode, raw, node):
    # Render list of words, or XPRV / master secret to text.
    import stash, chains
    from ux import ux_render_words

    c = chains.current_chain()
    qr_alnum = False

    if mode == 'words':
        import bip39
        words = bip39.b2a_words(raw).split(' ')

        # This optimization make the QR very nice, and space for
        # all the words too
        qr = ' '.join(w[0:4] for w in words)
        qr_alnum = True

        msg = 'Seed words (%d):\n' % len(words)
        msg += ux_render_words(words)

        if stash.bip39_passphrase:
            msg += '\n\nBIP-39 Passphrase:\n    *****'
            if node:
                msg += '\n\nSeed+Passphrase:\n%s' % c.serialize_private(node)


    elif mode == 'xprv':
        msg = c.serialize_private(node)
        qr = msg

    elif mode == 'master':
        msg = '%d bytes:\n\n' % len(raw)
        qr = str(b2a_hex(raw), 'ascii')
        msg += qr
    else:
        raise ValueError(mode)

    return msg, qr, qr_alnum

async def view_seed_words(*a):
    import stash

    if not await ux_confirm('The next screen will show the seed words'
                            ' (and if defined, your BIP-39 passphrase).'
                            '\n\nAnyone with knowledge of those words '
                            'can control all funds in this wallet.'):
        return

    from glob import dis
    dis.fullscreen("Wait...")
    dis.busy_bar(True)

    # preserve old UI where we show words + passphrase
    # instead of just calculated seed + passphrase = extended privkey
    # new: calculated xprv is now also shown for BIP39 passphrase wallet
    raw = mode = None
    if stash.bip39_passphrase:
        # get main secret - bypass tmp
        with stash.SensitiveValues(bypass_tmp=True) as sv:
            if not sv.deltamode:
                assert sv.mode == "words"
                raw = sv.raw[:]
                mode = sv.mode

        stash.SensitiveValues.clear_cache()

    with stash.SensitiveValues(bypass_tmp=False) as sv:
        if sv.deltamode:
            # give up and wipe self rather than show true seed values.
            import callgate
            callgate.fast_wipe()

        dis.busy_bar(False)
        msg, qr, qr_alnum = render_master_secrets(mode or sv.mode,
                                                  raw or sv.raw,
                                                  sv.node)

        if not version.has_qwerty:
            msg += '\n\nPress (1) to view as QR Code.'

        while 1:
            ch = await ux_show_story(msg, sensitive=True, escape='1'+KEY_QR)
            if ch in '1'+KEY_QR:
                from ux import show_qr_code
                await show_qr_code(qr, qr_alnum)
                continue
            break

    stash.blank_object(qr)
    stash.blank_object(msg)
    stash.blank_object(raw)

async def export_seedqr(*a):
    # see standard: <https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md>
    import bip39, stash

    if not await ux_confirm('The next screen will show the seed words in a QR code.'
                            '\n\nAnyone with knowledge of those words '
                            'can control all funds in this wallet.'):
        return

    from glob import dis
    dis.fullscreen("Wait...")
    dis.busy_bar(True)

    # Note: cannot reach this menu item if no words. If they are tmp, that's cool.

    with stash.SensitiveValues(bypass_tmp=False) as sv:
        if sv.deltamode:
            # give up and wipe self rather than show true seed values.
            import callgate
            callgate.fast_wipe()

        if sv.mode != 'words':
            raise ValueError(sv.mode)

        words = bip39.b2a_words(sv.raw).split(' ')

        dis.busy_bar(False)
        qr = encode_seed_qr(words)

        del words

    from ux import show_qr_code
    await show_qr_code(qr, True, msg="SeedQR")

    stash.blank_object(qr)

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
        s = SettingsObject.prelogin()
        s.set('lgto', had_delay)
        s.save()
        del s

    # Disable vdisk so it is off by default until re-enabled, after
    # version 5.0.6 is installed
    settings.remove_key('vdsk')

async def version_migration_prelogin():
    # same, but for setting before login
    # these have moved into SE2 for Mk4 and so can be removed
    for n in [ 'cd_lgto', 'cd_mode', 'cd_pin' ]:
        settings.remove_key(n)

async def start_login_sequence():
    # Boot up login sequence here.
    #
    # - easy to brick units here, so catch and ignore errors where possible/appropriate
    #
    from ux import idle_logout, ux_login_countdown
    from glob import dis
    from imptask import IMPT

    if pa.is_blank():
        # Blank devices, with no PIN set all, can continue w/o login
        goto_top_menu()
        return

    # data migration on settings that are used pre-login
    try:
        await version_migration_prelogin()
    except: pass

    if version.has_battery:
        from battery import batt_idle_logout
        IMPT.start_task('b-idle', batt_idle_logout())

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
            dis.fullscreen("Skip PIN...")
            pa.setup(guess)
            pa.login()
        except: pass

    # If that didn't work, or no skip defined, force
    # them to login successfully.

    try:
        # Get a PIN and try to use it to login
        # - does warnings about attempt usage counts
        await block_until_login()

        # Do we need to do countdown delay? (real or otherwise)
        # Q/Mk4 approach:
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
            await ux_login_countdown(delay * (60 if not version.is_devmode else 1))

            # keep it simple for Mk4+: just challenge again for any PIN
            # - if it's the same countdown pin, it will be accepted and they
            #   get in (as most trick pins would do)
            await block_until_login()

    except BaseException as exc:
        # Robustness: any logic errors/bugs in above will brick the Coldcard
        # even for legit owner, since they can't login. So try to recover, when it's
        # safe to do so. Remember the bootrom checks PIN on every access to
        # the secret, so "letting" them past this point is harmless if they don't know
        # the true pin.
        sys.print_exception(exc)
        if not pa.is_successful():
            raise

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

    # Maybe insist on the "right" microSD being already installed?
    try:
        from pwsave import MicroSD2FA
        MicroSD2FA.enforce_policy()
    except BaseException as exc:
        # robustness: keep going!
        sys.print_exception(exc)

    # implement idle timeout now that we are logged-in
    IMPT.start_task('idle', idle_logout())

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

    # Version warning before HSM is offered
    if version.is_edge and not ckcc.is_simulator():
        await ux_show_story(
             "This preview version of firmware has not yet been qualified and "
             "tested to the same standard as normal Coinkite products."
             "\n\nIt is recommended only for developers and early adopters for experimental use. "
             "DO NOT use for large Bitcoin amounts.", title="Edge Version")

    dis.draw_status(xfp=settings.get('xfp'))

    # If HSM policy file is available, offer to start that,
    # **before** the USB is even enabled.
    if version.supports_hsm:
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


async def restore_main_secret(*a):
    from glob import dis
    from seed import restore_to_main_secret, in_seed_vault

    escape = None
    msg = "Restore main wallet and its settings?\n\n"
    if not in_seed_vault(pa.tmp_value):
        msg += (
            "Press %s to forget current temporary seed "
            "settings, or press (1) to save & keep "
            "those settings if same seed is later restored." % OK
        )
        escape = "1"

    ch = await ux_show_story(msg, escape=escape)
    if ch == "x": return

    dis.fullscreen("Working...")

    ps = True
    if escape and (ch == "y"):
        ps = False

    await restore_to_main_secret(preserve_settings=ps)
    goto_top_menu()

def make_top_menu():
    from flow import VirginSystem, NormalSystem, EmptyWallet, FactoryMenu
    from glob import hsm_active, settings
    from pincodes import pa

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

        if pa.has_secrets():
            _cls = NormalSystem[:]
            if pa.tmp_value or settings.get("hmx", False):
                active_xfp = settings.get("xfp", 0)
                sl, sr = ("[", "]") if pa.tmp_value else ("<", ">")
                if active_xfp:
                    ui_xfp = sl + xfp2str(active_xfp) + sr
                    _cls.insert(0, MenuItem(ui_xfp, f=ready2sign))
                if pa.tmp_value:
                    _cls.append(MenuItem("Restore Master", f=restore_main_secret, shortcut='m'))
        else:
            _cls = EmptyWallet

        m = MenuSystem(_cls)
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

PICK_ACCOUNT = '''\n\nPress (1) to enter a non-zero account number.'''


async def dump_summary(*A):
    # save addresses, and some other public details into a file
    if not await ux_confirm('''\
Saves a text file with a summary of the *public* details \
of your wallet. For example, this gives the XPUB (extended public key) \
that you will need to import other wallet software to track balance.''' + SENSITIVE_NOT_SECRET):
        return

    # pick a semi-random file name, save it.
    await make_summary_file()

async def export_xpub(label, _2, item):
    # provide bare xpub in a QR/NFC for import into simple wallets.
    import chains, glob, stash
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
        remap = {44:0, 49:1, 84:2,86:3}[mode]
        _, path, addr_fmt = chains.CommonDerivations[remap]
        path = path.format(account='{acct}', coin_type=chain.b44_cointype, change=0, idx=0)[:-4]

    # always show SLIP-132 style, because defacto
    show_slip132 = (addr_fmt != AF_CLASSIC)

    while 1:
        msg = '''Show QR of the XPUB for path:\n\n%s\n\n''' % path

        if '{acct}' in path:
            msg += "Press (1) to select account other than zero. "
        if glob.NFC:
            msg += "Press %s to share via NFC. " % (KEY_NFC if version.has_qwerty else "(3)")

        ch = await ux_show_story(msg, escape='13')
        if ch == 'x': return
        if ch == '1':
            acct = await ux_enter_bip32_index('Account Number:') or 0
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

        from ownership import OWNERSHIP
        OWNERSHIP.note_wallet_used(addr_fmt, acct)

        if glob.NFC and ch in '3'+KEY_NFC:
            await glob.NFC.share_text(xpub)
        else:
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
        account_num = await ux_enter_bip32_index('Account Number:') or 0
    elif ch != 'y':
        return

    rv = [
        MenuItem(addr_fmt_label(af), f=electrum_skeleton_step2,
                 arg=(af, account_num))
        for af in [AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH]
    ]
    the_ux.push(MenuSystem(rv))

def ss_descriptor_export_story(addition="", background="", acct=True):
    # saves memory being in a function
    return ("This saves a ranged xpub descriptor" + addition
            + background
            + (PICK_ACCOUNT if acct else "")
            + SENSITIVE_NOT_SECRET)

async def ss_descriptor_skeleton(_0, _1, item):
    # Export of descriptor data (wallet)
    int_ext, addition, f_pattern = None, "", "descriptor.txt"
    allowed_af = [AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH, AF_P2TR]
    if item.arg:
        int_ext, allowed_af, ll, f_pattern = item.arg
        addition = " for " + ll

    ch = await ux_show_story(ss_descriptor_export_story(addition), escape='1')

    account_num = 0
    if ch == '1':
        account_num = await ux_enter_bip32_index('Account Number:', unlimited=True) or 0
    elif ch != 'y':
        return

    if int_ext is None:
        ch = await ux_show_story(
            "To export receiving and change descriptors in one descriptor "
            "(<0;1> notation) press %s, press (1) to export "
            "receiving and change descriptors separately." % OK, escape='1')
        if ch == "x": return
        int_ext = False if ch == "1" else True

    if len(allowed_af) == 1:
        await make_descriptor_wallet_export(allowed_af[0], account_num,
                                            int_ext=int_ext,
                                            fname_pattern=f_pattern)
    else:
        rv = [
            MenuItem(addr_fmt_label(af), f=descriptor_skeleton_step2,
                     arg=(af, account_num, int_ext, f_pattern))
            for af in allowed_af
        ]
        the_ux.push(MenuSystem(rv))

async def samourai_post_mix_descriptor_export(*a):
    name = "POST-MIX"
    post_mix_acct_num = 2147483646
    await samourai_account_descriptor(name, post_mix_acct_num)

async def samourai_pre_mix_descriptor_export(*a):
    name = "PRE-MIX"
    pre_mix_acct_num = 2147483645
    await samourai_account_descriptor(name, pre_mix_acct_num)

# async def samourai_bad_bank_descriptor_export(*a):
#     name = "PRE-MIX"
#     pre_mix_acct_num = 2147483644
#     await samourai_account_descriptor(name, pre_mix_acct_num)

async def samourai_account_descriptor(name, account_num):
    ch = await ux_show_story(
        ss_descriptor_export_story(
            addition=" for Samourai %s account." % name,
            acct=False)
    )

    if ch != 'y':
        return
    fn_pattern = "samourai-%s.txt" % name.lower()
    await make_descriptor_wallet_export(AF_P2WPKH, account_num, fname_pattern=fn_pattern)

async def descriptor_skeleton_step2(_1, _2, item):
    # pick a semi-random file name, render and save it.
    addr_fmt, account_num, int_ext, f_pattern = item.arg
    await make_descriptor_wallet_export(addr_fmt, account_num, int_ext=int_ext,
                                        fname_pattern=f_pattern)


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
        account_num = await ux_enter_bip32_index('Account Number:') or 0
    elif ch != 'y':
        return

    # no choices to be made, just do it.
    await make_bitcoin_core_wallet(account_num)


async def electrum_skeleton_step2(_1, _2, item):
    # pick a semi-random file name, render and save it.
    addr_fmt, account_num = item.arg
    await make_json_wallet('Electrum wallet',
                           lambda: generate_electrum_wallet(addr_fmt, account_num),
                           "new-electrum.json")

async def _generic_export(prompt, label, f_pattern):
    # like the Multisig export, make a single JSON file with
    # basically all useful XPUB's in it.
    ch = await ux_show_story(prompt + PICK_ACCOUNT + SENSITIVE_NOT_SECRET, escape="1")
    account_num = 0
    if ch == '1':
        account_num = await ux_enter_bip32_index('Account Number:') or 0
    elif ch != 'y':
        return

    await make_json_wallet(label, lambda: generate_generic_export(account_num), f_pattern)

async def generic_skeleton(*A):
    # like the Multisig export, make a single JSON file with
    # basically all useful XPUB's in it.
    prompt = '''\
Saves JSON file, with XPUB values that are needed to watch typical \
single-signer UTXO associated with this Coldcard.'''

    await _generic_export(prompt, 'Generic Export', 'coldcard-export.json')


async def named_generic_skeleton(menu, label, item):
    name = item.arg
    # make a single JSON file with basically all useful XPUB's in it.
    # identical to generic_skeleton but with different story and filename.
    prompt = ('This saves a JSON file to use with %s Wallet. '
              'Works for both single signature and multisig wallets.') % name

    await _generic_export(prompt, '%s Wallet' % name,
                          '%s-export.json' % name.lower())


async def wasabi_skeleton(*A):
    # save xpub, and some other public details into a file
    # - user has no choice, it's going to be bech32 with  m/84'/0'/0' path

    ch = await ux_show_story('''\
This saves a skeleton Wasabi wallet file. \
You can then open that file in Wasabi without ever connecting this Coldcard to a computer.\
''' + SENSITIVE_NOT_SECRET)
    if ch != 'y':
        return

    # no choices to be made, just do it.
    await make_json_wallet('Wasabi wallet', lambda: generate_wasabi_wallet(), 'new-wasabi.json')

async def unchained_capital_export(*a):
    # they were using our airgapped export, and the BIP-45 path from that
    #
    ch = await ux_show_story('''\
This saves multisig XPUB information required to setup on the Unchained platform. \
''' + PICK_ACCOUNT + SENSITIVE_NOT_SECRET, escape="1")
    account_num = 0
    if ch == '1':
        account_num = await ux_enter_bip32_index('Account Number:') or 0
    elif ch != 'y':
        return

    xfp = xfp2str(settings.get('xfp', 0))
    fname = 'unchained-%s.json' % xfp

    await make_json_wallet('Unchained',
                           lambda: generate_unchained_export(account_num),
                           fname)


async def backup_everything(*A):
    # save everything, using a password, into single encrypted file, typically on SD
    import backups

    await backups.make_complete_backup()

async def verify_backup(*A):
    # check most recent backup is "good"
    # read 7z header, and measure checksums
    import backups

    fn = await file_picker(suffix='.7z', max_size=backups.MAX_BACKUP_FILE_SIZE)

    if not fn:
        return

    # do a limited CRC-check over encrypted file
    await backups.verify_backup_file(fn)

async def import_extended_key_as_secret(extended_key, ephemeral, meta=None):
    try:
        import seed
        if ephemeral:
            await seed.set_ephemeral_seed_extended_key(extended_key, meta=meta)
        else:
            await seed.set_seed_extended_key(extended_key)
    except ValueError:
        msg = ("Sorry, wasn't able to find a valid extended private key to import. "
               "It should be at the start of a line, and probably starts with 'xprv'.")
        await ux_show_story(title="FAILED", msg=msg)
    except Exception as e:
        await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

async def import_xprv(_1, _2, item):
    # read an XPRV from a text file and use it.
    from glob import NFC

    extended_key = None
    label = "extended private key"

    ephemeral = item.arg
    if not ephemeral:
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

    choice = await import_export_prompt("%s file" % label, is_import=True)

    if choice == KEY_CANCEL:
        return
    elif choice == KEY_NFC:
        extended_key = await NFC.read_extended_private_key()
        if not extended_key:
            # failed to get any data - exit
            # error already displayed in nfc.py
            return
    elif choice == KEY_QR:
        from ux_q1 import QRScannerInteraction
        extended_key = await QRScannerInteraction.scan('Scan XPRV from a QR code')
        if not extended_key:
            # press pressed CANCEL
            return
    else:
        # only get here if NFC was not chosen
        # pick a likely-looking file.
        fn = await file_picker(suffix='txt', min_size=50, max_size=2000, taster=contains_xprv,
                               none_msg="Must contain " + label + ".", **choice)

        if not fn: return

        with CardSlot(readonly=True, **choice) as card:
            with open(fn, 'rt') as fd:
                for ln in fd.readlines():
                    if 'prv' in ln:
                        extended_key = ln
                        break

    await import_extended_key_as_secret(extended_key, ephemeral, meta='Imported XPRV')
    # not reached; will do reset.

EMPTY_RESTORE_MSG = '''\
You must clear the wallet seed before restoring a backup because it replaces \
the seed value and the old seed would be lost.\n\n\
Visit the advanced menu and choose 'Destroy Seed'.'''

async def restore_temporary(*A):

    fn = await file_picker(suffix=".7z")

    if fn:
        import backups
        await backups.restore_complete(fn, temporary=True)

async def restore_everything(*A):

    if not pa.is_secret_blank():
        await ux_show_story(EMPTY_RESTORE_MSG)
        return

    # restore everything, using a password, from single encrypted 7z file
    fn = await file_picker(suffix='.7z')

    if fn:
        import backups
        await backups.restore_complete(fn)

async def restore_everything_cleartext(*A):
    # Asssume no password on backup file; devs and crazy people only

    if not pa.is_secret_blank():
        await ux_show_story(EMPTY_RESTORE_MSG)
        return

    # restore everything, using NO password, from single text file, like would be wrapped in 7z
    fn = await file_picker(suffix='.txt')

    if fn:
        import backups
        prob = await backups.restore_complete_doit(fn, [])
        if prob:
            await ux_show_story(prob, title='FAILED')

async def wipe_filesystem(*A):
    if not await ux_confirm('''\
Erase internal filesystem and rebuild it. Resets contents of internal flash area \
used for settings, address search cache, and HSM config file. Does not affect funds, \
or seed words but will reset settings used with other BIP-39 passphrases. \
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


async def qr_share_file(*A):
    # Pick file from SD card and share as (BB)Qr
    from files import CardSlot, CardMissingError, needs_microsd
    from export import export_by_qr

    def is_suitable(fname):
        f = fname.lower()
        return f.endswith('.psbt') or f.endswith('.txn') \
            or f.endswith('.txt') or f.endswith(".json") or fname.endswith(".sig")

    while 1:
        txid = None
        fn = await file_picker(min_size=10, max_size=MAX_TXN_LEN_MK4, taster=is_suitable)
        if not fn: return

        basename = fn.split('/')[-1]
        ext = fn.split('.')[-1].lower()

        try:
            with CardSlot() as card:
                with open(fn, 'rb') as fp:
                    data = fp.read()

        except CardMissingError:
            await needs_microsd()
            return

        if ext == "txn":
            tc = "T"
            txid = txid_from_fname(basename)
            if data[2:8] == b'000000':
                # it's a txn, and we wrote as hex
                data = data.decode()
            else:
                assert data[2:8] == bytes(6)
                data = b2a_hex(data).decode()
        elif data[0:5] == b'psbt\xff':
            tc = "P"
        elif data[0:6] in (b'cHNidP', b'707362'):
            tc = "U"
            data = data.decode().strip()
        elif ext in ('txt', 'json', 'sig'):
            tc = "U"
            if ext == "json":
                tc = "J"
            data = data.decode()
        else:
            raise ValueError(ext)

        await export_by_qr(data, txid, tc)


async def nfc_share_file(*A):
    # Share txt, txn and PSBT files over NFC.
    from glob import NFC
    try:
        await NFC.share_file()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg="Failed to share file.\n\n%s\n%s" % (e, problem_file_line(e))
        )

async def nfc_pushtx_file(*A):
    # Share a signed txn over NFC using PushTx technology
    # - requires a signed txn, perhaps from another system on SD card
    from glob import NFC
    try:
        await NFC.push_tx_from_file()
    except Exception as e:
        await ux_show_story(title="ERROR", msg="Failed to share file. %s" % str(e))


async def nfc_show_address(*A):
    from glob import NFC
    try:
        await NFC.address_show_and_share()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg="Failed to show address.\n\n%s\n%s" % (e, problem_file_line(e))
        )


async def nfc_sign_msg(*A):
    # Receive data over NFC (text - follow sign txt file format)
    #      User approval on device
    #      Send signature RFC armored format back over NFC
    from glob import NFC
    try:
        await NFC.start_msg_sign()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg="Failed to sign message.\n\n%s\n%s" % (e, problem_file_line(e))
        )

async def nfc_sign_verify(*A):
    # Receive armored data over NFC
    from glob import NFC
    try:
        await NFC.verify_sig_nfc()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg="Failed to verify signed message.\n\n%s\n%s" % (e, problem_file_line(e))
        )

async def nfc_address_verify(*A):
    # Receive any random address (just the address) and find out if we own it.
    from glob import NFC
    try:
        await NFC.verify_address_nfc()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg='Address verification failed.\n\n%s\n%s' % (e, problem_file_line(e))
        )

async def nfc_recv_ephemeral(*A):
    # Mk4: Share txt, txn and PSBT files over NFC.
    from glob import NFC
    try:
        await NFC.import_ephemeral_seed_words_nfc()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg="Failed to import temporary seed via NFC.\n\n%s\n%s" % (e, problem_file_line(e))
        )

async def nfc_sign_psbt(*A):
    from glob import NFC
    try:
        await NFC.start_psbt_rx()
    except Exception as e:
        await ux_show_story(
            title="ERROR",
            msg='Failed to sign PSBT.\n\n%s\n%s' % (e, problem_file_line(e))
        )

async def list_files(*A):
    fn = await file_picker(min_size=0)
    if not fn: return

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

    from pincodes import pa

    digest = chk.digest()
    basename = fn.rsplit('/', 1)[-1]
    msg_base = 'SHA256(%s)\n\n%s\n\nPress ' % (basename, B2A(digest))
    escape = "6"
    if pa.has_secrets():
        msg_sign = '(4) to sign file digest and export detached signature, '
        escape += "4"
    else:
        msg_sign = ""
    msg_delete = '(6) to delete.'
    msg = msg_base + msg_sign + msg_delete
    while True:
        ch = await ux_show_story(msg, escape=escape)
        if ch == "x": break
        if ch in '46':
            with CardSlot() as card:
                if ch == '6':
                    card.securely_blank_file(fn)
                    break
                else:
                    from auth import write_sig_file

                    sig_nice = write_sig_file([(digest, fn)])
                    await ux_show_story("Signature file %s written." % sig_nice)
                    msg = msg_base + msg_delete
    return

async def file_picker(suffix=None, min_size=1, max_size=1000000, taster=None,
                      choices=None, none_msg=None, force_vdisk=False, slot_b=None,
                      allow_batch_sign=False, ux=True):
    # present a menu w/ a list of files... to be read
    # - optionally, enforce a max size, and provide a "tasting" function
    # - if msg==None, don't prompt, just do the search and return list
    # - if choices is provided; skip search process
    # - escape: allow these chars to skip picking process
    # - slot_b: None=>pick slot w/ card in it, or A if both.

    if choices is None:
        choices = []
        try:
            with CardSlot(force_vdisk=force_vdisk, slot_b=slot_b, readonly=True) as card:
                sofar = set()

                for path in card.get_paths():
                    for fn, ftype, *var in uos.ilistdir(path):
                        if ftype == 0x4000:
                            # ignore subdirs
                            continue

                        if suffix:
                            if not isinstance(suffix, list):
                                suffix = [suffix]
                            if not any([fn.lower().endswith(s) for s in suffix]):
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
                            except OSError:
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
            if ux is not False:
                await needs_microsd()
            return None

    if ux is False:
        return choices

    if not choices:
        msg = 'No suitable files found. '

        if none_msg:
            msg += none_msg
        if suffix:
            msg += '\n\nThe filename must end in "%s". ' % suffix

        msg += '\n\nMaybe insert (another) SD card and try again?'

        await ux_show_story(msg)
        return

    picked = []
    async def clicked(_1,_2,item):
        picked.append('/'.join(item.arg))
        the_ux.pop()

    choices.sort()

    items = [MenuItem(label, f=clicked, arg=(path, fn)) for label, path, fn in choices]
    if allow_batch_sign and len(choices) > 1:
        # we know that each choices member is psbt as allow_batch_sign is only True
        # in Ready To Sign
        items.insert(0, MenuItem("[Sign All]", f=batch_sign, arg=choices))

    menu = MenuSystem(items)
    the_ux.push(menu)

    await menu.interact()

    return picked[0] if picked else None

async def debug_assert(*a):
    assert False, "failed assertion"

async def debug_bbqr_test(*a):
    # Q only: test BBQr w/ lots of data
    from ux_q1 import show_bbqr_codes
    from gpu_binary import BINARY
    await show_bbqr_codes('B', BINARY*3, 'GPU binary')

async def debug_except(*a):
    print(34 / 0)

async def check_firewall_read(*a):
    import uctypes
    ps = uctypes.bytes_at(0x7800, 32)       # off the mark for mk4, but still valid test
    assert False        # should not be reached

async def bless_flash(*a):
    # make green LED turn on
    from glob import dis

    # impt: bugfix
    dis.bootrom_takeover()

    # do it
    pa.greenlight_firmware()

    # redraw our screen
    dis.show()


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

async def _batch_sign(choices=None):
    if not choices:
        picked = await import_export_prompt("PSBTs", is_import=True, no_nfc=True, no_qr=True)

        if picked == KEY_CANCEL:
            return
        assert isinstance(picked, dict)

        choices = await file_picker(suffix='psbt', min_size=50, ux=False,
                                    max_size=MAX_TXN_LEN, taster=is_psbt, **picked)

    if not choices:
        await ux_show_story("No PSBTs found. Need to have '.psbt' suffix.")
        return

    from auth import sign_psbt_file
    from ux import the_ux
    for label, path, fn in choices:
        ch = await ux_show_story("Sign %s ??\n\nPress %s to sign, (1) to skip this PSBT,"
                                 " %s to quit and exit." % (fn, OK, X), escape="1")
        if ch == "x": break
        elif ch == "y":
            input_psbt = path + '/' + fn
            await sign_psbt_file(input_psbt)
            await sleep_ms(100)
            await the_ux.top_of_stack().interact()

async def batch_sign(_1, _2, item):
    try:
        await _batch_sign(item.arg)
    except Exception as e:
        import sys
        await ux_show_story("FAILURE: batch sign failed\n\n" + problem_file_line(e))


async def ready2sign(*a):
    # Top menu choice of top menu! Signing!
    # - check if any signable in SD card, if so do it
    # - if no card, check virtual disk for PSBT
    # - if still nothing, then talk about USB connection
    from pincodes import pa
    from glob import NFC

    opt = {}

    # just check if we have candidates, no UI
    choices = await file_picker(suffix='psbt', min_size=50, ux=False,
                                max_size=MAX_TXN_LEN, taster=is_psbt)

    if pa.tmp_value:
        title = '[%s]' % xfp2str(settings.get('xfp'))
    else:
        title = None

    if not choices:
        msg = '''Coldcard is ready to sign spending transactions!

Put the proposed transaction onto MicroSD card \
in PSBT format (Partially Signed Bitcoin Transaction) \
or upload a transaction to be signed \
from your desktop wallet software or command line tools.\n\n'''

        footnotes = ("\n\nYou will always be prompted to confirm the details "
                     "before any signature is performed.")

        # if we have only one SD card inserted, at this point, we know no PSBTs on them
        # as above file_picker already checked
        # if we have both inserted, A was already checked - so only care about B
        picked = await import_export_prompt("PSBT", is_import=True, intro=msg,
                                            footnotes=footnotes, slot_b_only=True,
                                            title=title)
        if isinstance(picked, dict):
            opt = picked  # reset options to what was chosen by user
            choices = await file_picker(suffix='psbt', min_size=50, ux=False,
                                        max_size=MAX_TXN_LEN, taster=is_psbt,
                                        **opt)
            if not choices:
                await ux_show_story('Unable to find any suitable files for this operation.'
                                    ' The filename must end in psbt.')
                return
        else:
            if NFC and picked == KEY_NFC:
                await NFC.start_psbt_rx()
            if picked == KEY_QR:
                await _scan_any_qr()

            return

    if len(choices) == 1:
        # single - skip the menu
        label,path,fn = choices[0]
        input_psbt = path + '/' + fn
    else:
        # multiples - ask which, and offer batch to sign them all
        input_psbt = await file_picker(choices=choices, allow_batch_sign=True)
        if not input_psbt:
            return

    # start the process
    from auth import sign_psbt_file

    await sign_psbt_file(input_psbt, **opt)


async def sign_message_on_sd(*a):
    # Menu item: choose a file to be signed (as a short text message)
    #
    def is_signable(filename):
        if '-signed' in filename.lower():
            return False
        with open(filename, 'rt') as fd:
            lines = fd.readlines()
            # min 1 line max 3 lines
            return 1 <= len(lines) <= 3

    fn = await file_picker(suffix='txt', min_size=2, max_size=500, taster=is_signable,
                           none_msg=('Must be one line of text, optionally '
                                     'followed by a subkey derivation path on a second line '
                                     'and/or address format on third line.'))

    if not fn:
        return

    # start the process
    from auth import sign_txt_file
    await sign_txt_file(fn)


async def verify_sig_file(*a):
    def is_sig_file(filename):
        with open(filename, 'rt') as fd:
            line0 = fd.readline()
            if "SIGNED MESSAGE" in line0:
                return True
            return False

    fn = await file_picker(min_size=220, max_size=10000, taster=is_sig_file,
                           none_msg='Must be file with ascii armor.')

    if not fn:
        return

    # start the process
    from auth import verify_txt_sig_file
    await verify_txt_sig_file(fn)


async def main_pin_changer(*a):
    # Help them to change the main (true) PIN with appropriate warnings.
    # - the bootloader maybe lying to us about main vs trick pin
    # - what may look like just policy here, is in fact enforced by the bootrom code
    #
    from glob import dis
    from login import LoginUX
    from pincodes import BootloaderError, EPIN_OLD_AUTH_FAIL

    lll = LoginUX()
    title = 'Main PIN'
    msg = '''\
You will be changing the main PIN used to unlock your Coldcard.

THERE IS ABSOLUTELY NO WAY TO RECOVER A FORGOTTEN PIN!\n
Write it down.'''

    ch = await ux_show_story(msg, title=title)
    if ch != 'y': return


    async def incorrect_pin():
        await ux_show_story('You provided an incorrect value for the existing PIN.',
                                title='Wrong PIN')
        return

    args = {}

    # We need the existing pin, so prompt for that.
    lll.subtitle = 'Old ' + title
    old_pin = await lll.prompt_pin()
    if old_pin is None:
        return await ux_aborted()

    args['old_pin'] = old_pin.encode()

    # we can verify the main pin right away here. Be nice.
    if args['old_pin'] != pa.pin:
        return await incorrect_pin()

    while 1:
        lll.reset()
        lll.subtitle = "New " + title
        pin = await lll.get_new_pin(title, allow_clear=False)

        if pin is None:
            return await ux_aborted()

        from trick_pins import tp
        prob = tp.check_new_main_pin(pin)
        if prob:
            await ux_show_story(prob, title="Try Again")
            continue

        args['new_pin'] = pin.encode()
        break

    # install it.
    try:
        dis.fullscreen("Saving PIN...")
        dis.busy_bar(True)

        pa.change(**args)
        dis.busy_bar(False)
    except Exception as exc:
        dis.busy_bar(False)

        code = exc.args[1]

        if code == EPIN_OLD_AUTH_FAIL:
            # unlikely: but maybe we got tricked?
            return await incorrect_pin()
        else:
            return await ux_show_story("Unexpected low-level error: %s" % exc.args[0],
                                            title='Error')

    # Main pin is changed, and we use it lots, so update pa
    # - this step can be super slow with 608, unfortunately
    try:
        dis.fullscreen("Verify...")
        dis.busy_bar(True)

        pa.setup(args['new_pin'])

        if not pa.is_successful():
            # typical: do need login, but if we just cleared the main PIN,
            # we cannot/need not login again
            pa.login()

        # Deltamode trick pins need to track main pin
        from trick_pins import tp
        tp.main_pin_has_changed(pa.pin.decode())

    finally:
        dis.busy_bar(False)

async def show_version(*a):
    # show firmware, bootload versions.
    import callgate, version
    from glob import NFC

    built, rel, *_ = version.get_mpy_version()
    bl = callgate.get_bl_version()
    bl_dev = dict(bl[1]).get('DEV', 0)
    chk = str(b2a_hex(callgate.get_bl_checksum(0))[-8:], 'ascii')

    se = '\n  '.join(callgate.get_se_parts())

    # exposed over USB interface:
    serial = version.serial_number()

    # this UID is exposed over NFC interface, but only when enabled and in active use
    if NFC:
        serial += '\n\nNFC UID:\n  ' + NFC.get_uid().replace(':', '')

    hw = version.hw_label
    if not version.has_nfc:
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

Secure Elements:
  {se}
'''

    msg = msg.format(rel=rel, built=built, bl=bl[0]+(' DEV' if bl_dev else''), chk=chk,
                     se=se, ser=serial, hw=hw)
    if version.has_qr:
        from glob import SCAN, dis
        msg += '\nQR Scanner:\n  %s\n' % (SCAN.version or 'missing')

        msg += '\nGPU:\n  %s\n' % dis.gpu.get_version()

    await ux_show_story(msg)

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
        callgate.set_rdp_level(2)

        # bag number affects green light status (as does RDP level)
        dis.bootrom_takeover()
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

async def wipe_address_cache(*a):
    ok = await ux_confirm('''Clear cached addresses used in ownership search. Harmless to erase, just costs time.''')
    if not ok: return

    from ownership import OWNERSHIP
    OWNERSHIP.wipe_all()

    await ux_dramatic_pause("Cleared.", 3)

async def wipe_ovc(*a):
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
    from glob import NFC
    import nfc

    if not enable:
        if NFC:
            NFC.shutdown()
    else:
        nfc.NFCHandler.startup()

async def change_virtdisk_enable(enable):
    # NOTE: enable can be 0,1,2
    import glob, vdisk

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

async def change_seed_vault(is_enabled):
    # user has changed seed vault enable/disable flag
    from glob import settings

    if (not is_enabled) and settings.master_get('seeds'):
        # problem: they still have some seeds... also this path blocks
        # disable from within a tmp seed
        settings.set('seedvault', 1)        # restore it
        await ux_show_story("Please remove all seeds from the vault before disabling.")

        return

    goto_top_menu()

async def change_which_chain(*a):
    # setting already changed, but reflect that value in other settings
    try:
        # update xpub stored in settings
        import stash
        with stash.SensitiveValues() as sv:
            sv.capture_xpub()
    except ValueError:
        # no secrets yet, not an error
        pass

async def microsd_2fa(*a):
    # Feature: enforce special MicroSD being inserted at login time (a 2FA)
    from pwsave import MicroSD2FA
    
    if not settings.get('sd2fa'):
        msg = ('When enabled, this feature requires a specially prepared MicroSD card '
               'to be inserted during login process. After correct PIN is provided, '
               'if card slot is empty or unknown card present, the seed is wiped.')

        if version.num_sd_slots > 1:
            msg += ("\n\nIf multiple SD cards are present during login, make sure that"
                    " authorized card is in the top slot (slot A).")

        ch = await ux_show_story(msg)
        if ch != 'y':
            return

    return MicroSD2FA.menu()


async def keyboard_test(*a):
    # to aid keyboard testing/dev
    from ux import ux_input_text
    await ux_input_text('', max_len=128, scan_ok=True, confirm_exit=False,
                        prompt='Keyboard Test', placeholder='(type whatever)')

#
# Q wrappers; these will be present, but are very short on mk4
#
async def reflash_gpu(*a):
    from glob import dis
    await dis.gpu.reflash_gpu_ux()

async def scan_any_qr(menu, label, item):
    expect_secret, tmp = item.arg
    await _scan_any_qr(expect_secret, tmp)

async def _scan_any_qr(expect_secret=False, tmp=False):
    from ux_q1 import QRScannerInteraction
    x = QRScannerInteraction()
    await x.scan_anything(expect_secret=expect_secret, tmp=tmp)


PUSHTX_SUPPLIERS = [
    # (label, URL)
    ('coldcard.com', 'https://coldcard.com/pushtx#'),
    # from https://github.com/mempool/mempool/pull/5132
    ('mempool.space', 'https://mempool.space/pushtx#'),
]

async def pushtx_setup_menu(*a):
    # let them pick a URL from menu to enable "pushtx" feature, and provide
    # some background, and even let them enter a custom URL.

    if not settings.get("ptxurl", False):
        # force a warning on them, unless they are already doing it.
        ch = await ux_show_story(
            "When this is enabled, immediately after transaction signing, you can "
            "tap any NFC-enabled phone on the COLDCARD and your newly-signed "
            "transaction will be immediately broadcast on the public network.\n\n"
            "You must choose a provider by URL here, or give your own URL. "
            "\n\nYour phone's IP address vs. transaction details could be linked by the service. "
            "Requires NFC.",
            title="PUSH TX",
        )
        if ch != "y":
            return

    if not settings.get('nfc'):
        # force on NFC, so it works... but they can still turn it off later, etc.
        if not await ux_confirm("This feature requires NFC to be enabled. %s to enable." % OK):
            return
        settings.set("nfc", 1)
        await change_nfc_enable(1)

    async def doit(menu, picked, xx_self):
        # using stock values, or Disable 
        val = xx_self.arg[0]

        if val:
            settings.set('ptxurl', val)
        else:
            settings.remove_key('ptxurl')

        menu.chosen = picked
        menu.show()
        await sleep_ms(100)     # visual feedback that we changed it
        the_ux.pop()

    async def edit_custom(menu, picked, xx_self):
        val = xx_self.arg[0]
        while 1:
            nv = await ux_input_text(val, confirm_exit=True, scan_ok=True, prompt="Enter URL")
            # cleanup? URL validation? 
            if nv:
                prob = None
                if (not nv.startswith('http://')) and (not nv.startswith('https://')):
                    prob = "Must start with http:// or https://."
                elif len(nv) < 12:
                    prob = "Too short."
                elif nv[-1] not in '#?&':
                    prob = "Final char must be # or ? or &."

                if prob:
                    await ux_show_story(prob + " Try again.")
                    val = nv
                    continue
            break

        if nv:
            settings.set('ptxurl', nv)
            # force menu redraw
            m = await pushtx_setup_menu()
            the_ux.replace(m)
        else:
            settings.remove_key('ptxurl')
            the_ux.pop()

    was = settings.get("ptxurl", None)
    try:
        cur = [n for n, (l, u) in enumerate(PUSHTX_SUPPLIERS) if u == was][0]
    except IndexError:
        cur = None

    choices = [MenuItem(l, f=doit, arg=(u,)) for l,u in PUSHTX_SUPPLIERS]

    if was and cur is None:
        # they have a non-standard choice
        label = was.split("/")[2]  # pull out domain (netloc)
        choices.append(MenuItem(label, f=edit_custom, arg=(was,)))
        cur = len(choices)-1
    else:
        choices.append(MenuItem("Custom URL...", f=edit_custom, arg=('http',)))

    choices.append(MenuItem("Disable", f=doit, arg=(None,)))

    return MenuSystem(choices, chosen=cur)

# EOF
