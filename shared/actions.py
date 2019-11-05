# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# actions.py
#
# Every function here is called directly by a menu item. They should all be async.
#
import ckcc, pyb, version
from ux import ux_show_story, the_ux, ux_confirm, ux_dramatic_pause, ux_poll_once, ux_aborted
from utils import imported
from main import settings
from uasyncio import sleep_ms
from files import CardSlot, CardMissingError
from utils import xfp2str

async def start_selftest(*args):

    if len(args) and not version.is_factory_mode():
        # called from inside menu, not directly
        if not await ux_confirm('''Selftest destroys settings on other profiles (not seeds). Requires MicroSD card and might have other consequences. Recommended only for factory.'''):
            return await ux_aborted()

    with imported('selftest') as st:
        await st.start_selftest()

    settings.save()


async def needs_microsd():
    # Standard msg shown if no SD card detected when we need one.
    await ux_show_story("Please insert a MicroSD card before attempting this operation.")

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
    from main import settings, pa
    import callgate, stash

    tpl = '''\
Master Key Fingerprint:

  {xfp}

as LE32:
  0x{xfp_le:08x}

USB Serial Number:

  {serial}

Extended Master Key:

{xpub}
'''
    my_xfp = settings.get('xfp', 0)
    msg = tpl.format(xpub=settings.get('xpub', '(none yet)'),
                            xfp=xfp2str(my_xfp), xfp_le=my_xfp,
                            serial=version.serial_number())

    if pa.is_secondary:
        msg += '\n(Secondary wallet)\n'

    if stash.bip39_passphrase:
        msg += '\nBIP39 passphrase is in effect.\n'

    bn = callgate.get_bag_number()
    if bn:
        msg += '\nShipping Bag:\n  %s\n' % bn

    await ux_show_story(msg)

async def maybe_dev_menu(*a):
    from main import is_devmode

    if not is_devmode:
        ok = await ux_confirm('Developer features could be used to weaken security or release key material.\n\nDo not proceed unless you know what you are doing and why.')

        if not ok:
            return None

    from flow import DevelopersMenu
    return DevelopersMenu

async def dev_enable_vcp(*a):
    # Enable USB serial port emulation, for devs.
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
    from main import loop

    cur = pyb.usb_mode()
    if cur and 'HID' in cur:
        await ux_show_story('Coldcard USB protocol is already enabled (HID mode)')
        return

    # might need to reset stuff?
    from usb import enable_usb

    # reset / re-enable
    pyb.usb_mode(None)
    enable_usb(loop, True)

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
        with open(fn, 'rb') as fp:
            from main import sf, dis
            from files import dfu_parse
            from ustruct import unpack_from

            offset, size = dfu_parse(fp)

            # get a copy of special signed heaer at the end of the flash as well
            from sigheader import FW_HEADER_OFFSET, FW_HEADER_SIZE, FW_HEADER_MAGIC, FWH_PY_FORMAT
            hdr = bytearray(FW_HEADER_SIZE)
            fp.seek(offset + FW_HEADER_OFFSET)

            # basic checks only: for confused customers, not attackers.
            try:
                rv = fp.readinto(hdr)
                assert rv == FW_HEADER_SIZE

                magic_value, timestamp, version_string, pk, fw_size = \
                                unpack_from(FWH_PY_FORMAT, hdr)[0:5]
                assert magic_value == FW_HEADER_MAGIC
                assert fw_size == size

                # TODO: maybe show the version string? Warn them that downgrade doesn't work?

            except Exception as exc:
                failed = "Sorry! That does not look like a firmware " \
                            "file we would want to use.\n\n\n%s" % exc

            if not failed:
            
                # copy binary into serial flash
                fp.seek(offset)

                buf = bytearray(256)        # must be flash page size
                pos = 0
                dis.fullscreen("Loading...")
                while pos <= size + FW_HEADER_SIZE:
                    dis.progress_bar_show(pos/size)

                    if pos == size:
                        # save an extra copy of the header (also means we got done)
                        buf = hdr
                    else:
                        here = fp.readinto(buf)
                        if not here: break

                    if pos % 4096 == 0:
                        # erase here
                        sf.sector_erase(pos)
                        while sf.is_busy():
                            await sleep_ms(10)

                    sf.write(pos, buf)

                    # full page write: 0.6 to 3ms
                    while sf.is_busy():
                        await sleep_ms(1)

                    pos += here

    if failed:
        await ux_show_story(failed, title='Corrupt')
        return

    # continue process...
    import machine
    machine.reset()
        

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
Each part must between 2 to 6 digits long. Total length \
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
    from main import pa, dis, settings, loop
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
    enable_usb(loop, False)

    from menu import MenuSystem
    from flow import EmptyWallet
    return MenuSystem(EmptyWallet)


async def block_until_login(*a):
    #
    # Force user to enter a valid PIN.
    # 
    from login import LoginUX
    from main import pa, loop, settings
    from ux import AbortInteraction

    while not pa.is_successful():
        lll = LoginUX()

        try:
            await lll.try_login()
        except AbortInteraction:
            # not allowed!
            pass

async def show_nickname(nick):
    # Show a nickname for this coldcard (as a personalization)
    # - no keys here, just show it until they press anything
    from main import dis
    from display import FontLarge, FontTiny, FontSmall
    from ux import ux_wait_keyup

    dis.clear()

    if dis.width(nick, FontLarge) <= dis.WIDTH:
        dis.text(None, 21, nick, font=FontLarge)
    else:
        dis.text(None, 27, nick, font=FontSmall)

    #dis.text(None, -1, "ANY KEY to CONTINUE", FontTiny)
    dis.show()

    await ux_wait_keyup()

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
    from callgate import show_logout
    from main import sf
    sf.wipe_most()
    show_logout()

async def login_now(*a):
    # wipe memory and reboot
    from callgate import show_logout
    from main import sf
    sf.wipe_most()
    show_logout(2)
    

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
    return seed.WordNestMenu(item.arg)

async def start_b39_pw(menu, label, item):
    if not settings.get('b39skip', False):
        ch = await ux_show_story('''\
You may add a passphrase to your BIP39 seed words. \
This creates an entirely new wallet, for every possible passphrase.

By default, the Coldcard uses an empty string as the passphrase.

On the next menu, you can enter a passphrase by selecting \
individual lettters, choosing from the word list (recommended), \
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

def pick_new_wallet(*a):
    import seed
    return seed.make_new_wallet()

async def convert_bip39_to_bip32(*a):
    import seed, stash

    if not await ux_confirm('''This operation computes the extended master private key using your BIP39 seed words and passphrase, and then saves the resulting value (xprv) as the wallet secret.

The seed words themselves are erased forever, but effectively there is no other change. If a BIP39 passphrase is currently in effect, its value is captured during this process and will be 'in effect' going forward, but the passphrase itself is erased and unrecoverable. The resulting wallet cannot be used with any other passphrase.

A reboot is part of this process. PIN code, and funds are not affected.
'''):
        return await ux_aborted()

    if not stash.bip39_passphrase:
        if not await ux_confirm('''You do not have a BIP39 passphrase set right now, so this command does little except forget the seed words. It does not enhance security.'''):
            return

    await seed.remember_bip39_passphrase()

    settings.save()

    await login_now()

async def clear_seed(*a):
    # Erase the seed words, and private key from this wallet!
    # This is super dangerous for the customer's money.
    import seed
    from main import pa

    if pa.has_duress_pin():
        await ux_show_story('''Please empty the duress wallet, and clear the duress PIN before clearing main seed.''')
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

async def view_seed_words(*a):
    import stash, tcc

    if not await ux_confirm('''The next screen will show the seed words (and if defined, your BIP39 passphrase).\n\nAnyone with knowledge of those words can control all funds in this wallet.''' ):
        return

    with stash.SensitiveValues() as sv:
        assert sv.mode == 'words'       # protected by menu item predicate

        words = tcc.bip39.from_data(sv.raw).split(' ')

        msg = 'Seed words (%d):\n' % len(words)
        msg += '\n'.join('%2d: %s' % (i+1, w) for i,w in enumerate(words))

        pw = stash.bip39_passphrase
        if pw:
            msg += '\n\nBIP39 Passphrase:\n%s' % stash.bip39_passphrase

        await ux_show_story(msg, sensitive=True)

        stash.blank_object(msg)

async def start_login_sequence():
    # Boot up login sequence here.
    #
    from main import pa, settings, dis, loop, numpad

    if pa.is_blank():
        # Blank devices, with no PIN set all, can continue w/o login

        # Do green-light set immediately after firmware upgrade
        if version.is_fresh_version():
            pa.greenlight_firmware()
            dis.show()

        goto_top_menu()
        return

    # maybe show a nickname before we do anything
    nickname = settings.get('nick', None)
    if nickname:
        try:
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

    # if that didn't work, or no skip defined, force
    # them to login succefully.
    while not pa.is_successful():
        # always get a PIN and login first
        await block_until_login()

    # Must re-read settings after login
    settings.set_key()
    settings.load()

    # Restore a login preference or two
    numpad.sensitivity = settings.get('sens', numpad.sensitivity)

    # Do green-light set immediately after firmware upgrade
    if not pa.is_secondary:
        if version.is_fresh_version():
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

    # Allow USB protocol, now that we are auth'ed
    from usb import enable_usb
    enable_usb(loop, False)

    goto_top_menu()

        
def goto_top_menu():
    # Start/restart menu system
    from menu import MenuSystem
    from flow import VirginSystem, NormalSystem, EmptyWallet, FactoryMenu
    from main import pa

    if version.is_factory_mode():
        m = MenuSystem(FactoryMenu)
    elif pa.is_blank():
        # let them play a little before picking a PIN first time
        m = MenuSystem(VirginSystem, should_cont=lambda: pa.is_blank())
    else:
        assert pa.is_successful(), "nonblank but wrong pin"

        m = MenuSystem(EmptyWallet if pa.is_secret_blank() else NormalSystem)

    the_ux.reset(m)

    return m

SENSITIVE_NOT_SECRET = '''

The file created is sensitive--in terms of privacy--but should not \
compromise your funds directly.'''


async def dump_summary(*A):
    # save addresses, and some other public details into a file
    if not await ux_confirm('''\
Saves a text file to MicroSD with a summary of the *public* details \
of your wallet. For example, this gives the XPUB (extended public key) \
that you will need to import other wallet software to track balance.''' + SENSITIVE_NOT_SECRET):
        return

    # pick a semi-random file name, save it.
    with imported('backups') as bk:
        await bk.make_summary_file()

def electrum_export_story(background=False):
    # saves memory being in a function
    return ('''\
This saves a skeleton Electrum wallet file onto the MicroSD card. \
You can then open that file in Electrum without ever connecting this Coldcard to a computer.\n
''' 
        + (background or 'Choose an address type for the wallet on the next screen.\n')
        + SENSITIVE_NOT_SECRET)

async def electrum_skeleton(*a):
    # save xpub, and some other public details into a file: NOT MULTISIG

    if not await ux_show_story(electrum_export_story()):
        return

    import chains
    ch = chains.current_chain()

    # pick segwit or classic derivation+such
    from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
    from menu import MenuSystem, MenuItem

    # Ordering and terminology from similar screen in Electrum. I prefer
    # 'classic' instead of 'legacy' personallly.
    rv = []

    if AF_CLASSIC in ch.slip132:
        rv.append(MenuItem("Legacy (P2PKH)", f=electrum_skeleton_step2, arg=AF_CLASSIC))
    if AF_P2WPKH_P2SH in ch.slip132:
        rv.append(MenuItem("P2SH-Segwit", f=electrum_skeleton_step2, arg=AF_P2WPKH_P2SH))
    if AF_P2WPKH in ch.slip132:
        rv.append(MenuItem("Native Segwit", f=electrum_skeleton_step2, arg=AF_P2WPKH))

    return MenuSystem(rv)

async def electrum_skeleton_step2(_1, _2, item):
    # pick a semi-random file name, render and save it.
    with imported('backups') as bk:
        addr_fmt = item.arg
        await bk.make_json_wallet('Electrum wallet', lambda: bk.generate_electrum_wallet(addr_fmt))

async def wasabi_skeleton(*A):
    # save xpub, and some other public details into a file
    # - user has no choice, it's going to be bech32 with  m/84'/0'/0' path
    import chains

    ch = chains.current_chain()

    if await ux_show_story('''\
This saves a skeleton Wasabi wallet file onto the MicroSD card. \
You can then open that file in Wasabi without ever connecting this Coldcard to a computer.\
''' + SENSITIVE_NOT_SECRET) != 'y':
        return

    # no choices to be made, just do it.
    with imported('backups') as bk:
        await bk.make_json_wallet('Wasabi wallet', lambda: bk.generate_wasabi_wallet(), 'new-wasabi.json')

async def backup_everything(*A):
    # save everything, using a password, into single encrypted file, typically on SD
    with imported('backups') as bk:
        await bk.make_complete_backup()

async def verify_backup(*A):
    # check most recent backup is "good"
    # read 7z header, and measure checksums

    # save everything, using a password, into single encrypted file, typically on SD
    fn = await file_picker('Select file containing the backup to be verified. No password will be required.', suffix='.7z', max_size=10000)

    if fn:
        with imported('backups') as bk:
            await bk.verify_backup_file(fn)

def import_from_dice(*a):
    import seed
    return seed.import_from_dice()
        
async def import_xprv(*A):
    # read an XPRV from a text file and use it.
    import tcc, chains, ure
    from main import pa
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
    pat=ure.compile(r'.prv[A-Za-z0-9]+')
    with CardSlot() as card:
        with open(fn, 'rt') as fd:
            for ln in fd.readlines():
                if 'prv' not in ln: continue

                found = pat.search(ln)
                if not found: continue

                found = found.group(0)

                for ch in chains.AllChains:
                    for kk in ch.slip132:
                        if found[0] == ch.slip132[kk].hint:
                            try:
                                node = tcc.bip32.deserialize(found,
                                            ch.slip132[kk].pub, ch.slip132[kk].priv)
                                chain = ch
                                addr_fmt = kk
                                break
                            except ValueError:
                                pass
                if node:
                    break

    if not node:
        # unable
        await ux_show_story('''\
Sorry, wasn't able to find an extended private key to import. It should be at \
the start of a line, and probably starts with "xprv".''', title="FAILED")
        return

    # encode it in our style
    d = dict(chain=chain.ctype, raw_secret=b2a_hex(SecretStash.encode(xprv=node)))
    node.blank()

    # TODO: capture the address format implied by SLIP32 version bytes
    #addr_fmt = 
    

    # restore as if it was a backup (code reuse)
    await restore_from_dict(d)
   
    # not reached; will do reset. 
                            
EMPTY_RESTORE_MSG = '''\
You must clear the wallet seed before restoring a backup because it replaces \
the seed value and the old seed would be lost.\n\n\
Visit the advanced menu and choose 'Destroy Seed'.'''

async def restore_everything(*A):
    from main import pa

    if not pa.is_secret_blank():
        await ux_show_story(EMPTY_RESTORE_MSG)
        return

    # restore everything, using a password, from single encrypted 7z file
    fn = await file_picker('Select file containing the backup to be restored, and '
                            'then enter the password.', suffix='.7z', max_size=10000)

    if fn:
        with imported('backups') as bk:
            await bk.restore_complete(fn)

async def restore_everything_cleartext(*A):
    # Asssume no password on backup file; devs and crazy people only
    from main import pa

    if not pa.is_secret_blank():
        await ux_show_story(EMPTY_RESTORE_MSG)
        return

    # restore everything, using NO password, from single text file, like would be wrapped in 7z
    fn = await file_picker('Select the cleartext file containing the backup to be restored.',
                             suffix='.txt', max_size=10000)

    if fn:
        with imported('backups') as bk:
            prob = await bk.restore_complete_doit(fn, [])
            if prob:
                await ux_show_story(prob, title='FAILED')

async def wipe_filesystem(*A):
    if not await ux_confirm('''\
Erase internal filesystem and rebuild it. Resets contents of internal flash area \
used for code patches. Does not affect funds, settings or seed words. \
Does not affect SD card, if any.'''):
        return

    from files import wipe_flash_filesystem

    wipe_flash_filesystem()


async def list_files(*A):
    # list files, don't do anything with them?
    fn = await file_picker('List files on MicroSD')
    return

async def file_picker(msg, suffix=None, min_size=1, max_size=1000000, taster=None, choices=None, escape=None):
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
        msg = 'Unable to find any suitable files for this operation. '

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

    ch = await ux_show_story(msg, escape=escape)
    if escape and ch in escape: return ch
    if ch == 'x': return

    picked = []
    async def clicked(_1,_2,item):
        picked.append('/'.join(item.arg))
        the_ux.pop()

    items = [MenuItem(label, f=clicked, arg=(path, fn)) for label, path, fn in choices]

    if 0:
        # don't like; and now showing count on previous page
        if len(choices) == 1:
            # if only one choice, we could make the choice for them ... except very confusing
            items.append(MenuItem('  (one file)', f=None))
        else:
            items.append(MenuItem('  (%d files)' % len(choices), f=None))

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
    ps = uctypes.bytes_at(0x7800, 32)
    assert False        # should not be reached

async def bless_flash(*a):
    # make green LED turn on
    from main import pa, dis

    if pa.is_secondary:
        await needs_primary()
        return

    # do it
    pa.greenlight_firmware()
    dis.show()


async def ready2sign(*a):
    # Top menu choice of top menu! Signing!
    # - check if any signable in SD card, if so do it
    # - if nothing, then talk about USB connection
    from public_constants import MAX_TXN_LEN

    def is_psbt(filename):
        if '-signed' in filename.lower():
            return False

        with open(filename, 'rb') as fd:
            return fd.read(5) == b'psbt\xff'

    choices = await file_picker(None, suffix='psbt', min_size=50,
                            max_size=MAX_TXN_LEN, taster=is_psbt)

    if not choices:
        await ux_show_story("""\
Coldcard is ready to sign spending transactions!

Put the proposed transaction onto MicroSD card \
in PSBT format (Partially Signed Bitcoin Transaction) \
or upload a transaction to be signed \
from your wallet software (Electrum) or command line tools. \

You will always be prompted to confirm the details before any signature is performed.
""")
        return

    if len(choices) == 1:
        # skip the menu
        label,path,fn = choices[0]
        input_psbt = path + '/' + fn
    else:
        input_psbt = await file_picker('Choose PSBT file to be signed.', choices=choices)
        if not input_psbt:
            return

    # start the process
    from auth import sign_psbt_file

    await sign_psbt_file(input_psbt)


async def pin_changer(_1, _2, item):
    # Help them to change pins with appropriate warnings.
    # - forcing them to drill-down to get warning about secondary is on purpose
    # - the bootloader maybe lying to us about weather we are main vs. duress
    # - there is a duress wallet for both main/sec pins, and you need to know main pin for that
    # - what may look like just policy here, is in fact enforced by the bootrom code
    #
    from main import pa, dis
    from login import LoginUX
    from pincodes import BootloaderError, EPIN_OLD_AUTH_FAIL

    mode = item.arg

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

        is_clear = (pin == '999999-999999')

        args['new_pin'] = pin.encode() if not is_clear else b''

        if args['new_pin'] == pa.pin and not is_login_pin:
            await ux_show_story("Your new PIN matches the existing PIN used to get here. "
                                "It would be a bad idea to use it for another purpose.",
                                title="Try Again")
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

        if mode == 'duress':
            # program the duress secret now... it's derived from real wallet contents
            from stash import SensitiveValues, SecretStash, AE_SECRET_LEN

            if is_clear:
                # clear secret, using the new pin, which is empty string
                pa.change(is_duress=True, new_secret=b'\0' * AE_SECRET_LEN, old_pin=b'')
            else:
                with SensitiveValues() as sv:
                    # derive required key
                    node = sv.duress_root()
                    d_secret = SecretStash.encode(xprv=node)
                    sv.register(d_secret)
        
                    # write it out.
                    pa.change(is_duress=True, new_secret=d_secret, old_pin=args['new_pin'])

    finally:
        dis.busy_bar(False)

async def show_version(*a):
    # show firmware, bootload versions.
    from main import settings
    import callgate, version
    from ubinascii import hexlify as b2a_hex

    built, rel, *_ = version.get_mpy_version()
    bl = callgate.get_bl_version()[0]
    chk = str(b2a_hex(callgate.get_bl_checksum(0))[-8:], 'ascii')

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
'''

    await ux_show_story(msg.format(rel=rel, built=built, bl=bl, chk=chk,
                            ser=version.serial_number(), hw=version.hw_label))

async def ship_wo_bag(*a):
    # Factory command: for dev and test units that have no bag number, and never will.
    ok = await ux_confirm('''Not recommended! DO NOT USE for units going to paying customers.''')
    if not ok: return

    import callgate
    from main import dis, pa, is_devmode

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

async def import_multisig(*a):
    # pick text file from SD card, import as multisig setup file

    def possible(filename):
        with open(filename, 'rt') as fd:
            for ln in fd:
                if 'pub' in ln:
                    return True

    fn = await file_picker('Pick multisig wallet file to import (.txt)', suffix='.txt',
                                    min_size=100, max_size=20*200, taster=possible)

    if not fn: return

    try:
        with CardSlot() as card:
            with open(fn, 'rt') as fp:
                data = fp.read()
    except CardMissingError:
        await needs_microsd()
        return

    from auth import maybe_enroll_xpub
    try:
        possible_name = (fn.split('/')[-1].split('.'))[0]
        maybe_enroll_xpub(config=data, name=possible_name)
    except Exception as e:
        await ux_show_story('Failed to import.\n\n\n'+str(e))

# EOF
