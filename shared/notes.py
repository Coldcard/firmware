# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# notes.py - Store some short notes, securely.
#
import ngu, bip39
from menu import MenuItem, MenuSystem, ShortcutItem
from ux import ux_show_story, ux_dramatic_pause, ux_confirm, the_ux
from ux import ux_input_text, show_qr_code, import_export_prompt
from ux_q1 import QRScannerInteraction
from actions import goto_top_menu
from glob import settings, dis
from files import CardMissingError, needs_microsd, CardSlot
from charcodes import KEY_QR, KEY_NFC, KEY_CANCEL
from charcodes import KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6
from lcd_display import CHARS_W
from utils import problem_file_line, url_unquote, wipe_if_deltamode

# title, username and such are limited that they fit on the one line both in
# text entry (W-2) and also in menu display (W-3)
# - but W-3 is not centered .. so just lose some extra chars on right side if too long in menu
ONE_LINE = CHARS_W-2

async def make_notes_menu(*a):

    if not settings.get('secnap', False):
        # Explain feature, and then enable if interested. Drop them into menu.
        ch = await ux_show_story('''\
Enable this feature to store short text notes and passwords inside the Coldcard.

The notes are encrypted along with your other settings and will be backed-up with them.

Press ENTER to enable and get started otherwise CANCEL.''',
                title="Secure Notes")

        if ch != 'y':
            return

        # mark as enabled
        settings.set('secnap', True)
        if settings.get('notes', None) is None:
            settings.set('notes', [])

        # need to correct top menu now, so this choice is there.
        goto_top_menu()

    return NotesMenu(NotesMenu.construct())

async def get_a_password(old_value, min_len=0, max_len=128):
    # Get a (new) password as a string.
    # - does some fun generation as well.

    from seed import generate_seed
    from drv_entro import bip85_pwd, pick_bip85_password
    from random import randbelow, shuffle

    async def _pick_12(was):
        # 128 bits
        seed = generate_seed()[0:16]
        return bip39.b2a_words(seed)

    async def _pick_24(was):
        # 256 bits
        seed = generate_seed()
        return ' '.join(w[0:4] for w in bip39.b2a_words(seed).split())

    async def _pick_dense(was):
        # 126 bits, 21 chars ... base64 but no symbols
        seed = generate_seed() + generate_seed()
        return bip85_pwd(seed).replace('+', 'P').replace('/', 's')

    async def _do_dumb(was):
        # mixed case, number and symbol for bullshit site rules
        # entropy:  11+11 + (3.8*3) + 16 = 49 bits
        rv = ''
        for n in range(2):
            w = bip39.wordlist_en[randbelow(2048)]
            rv += w[0].upper() + w[1:]
        s = list('!@#$%^&*-=|+~?')      # opinionated
        shuffle(s)
        rv += ''.join(s[0:3])
        rv += '%04d' % randbelow(100000)
        return rv

    async def _bip85(was):
        s = dis.save_state()
        rv = await pick_bip85_password()
        dis.restore_state(s)
        return rv

    async def _toggle_case(was):
        # undocumented, not very useful
        if not was: return ''
        return was.upper() if was[0].islower() else was.lower()
        

    fmsg = (KEY_F1 + ' 12 ' + KEY_F2 + ' 24 word '
                            + KEY_F3 + KEY_F4 + ' random '
                            + KEY_F5 + 'B85')
    handlers = {KEY_F1: _pick_12, KEY_F2: _pick_24, KEY_F3: _pick_dense,
                KEY_F4: _do_dumb, KEY_F6: _toggle_case, KEY_F5: _bip85}

    return await ux_input_text(old_value, confirm_exit=False, max_len=max_len, min_len=min_len,
                               scan_ok=True, b39_complete=True, prompt='Password',
                               placeholder='(optional)', funct_keys=(fmsg, handlers))

class NotesMenu(MenuSystem):

    @classmethod
    def construct(cls):
        # Dynamic menu with user-defined names of notes shown

        news = [ MenuItem('New Note', f=cls.new_note, arg='n'),
                 MenuItem('New Password', f=cls.new_note, arg='p'),
                 ShortcutItem(KEY_QR, f=cls.quick_create)]

        cnt = NoteContent.count()
        if not cnt:
            rv = news + [ MenuItem('Disable Feature', f=cls.disable_notes) ]
        else:
            wipe_if_deltamode()

            rv = []
            for note in NoteContent.get_all():
                rv.append(MenuItem('%d: %s' % (note.idx+1, note.title), menu=note.make_menu))

            rv.extend(news)

            rv.append(MenuItem('Export All', f=cls.export_all))

            if cnt >= 2:
                rv.append(MenuItem('Sort By Title', f=cls.sort_titles))

        rv.append(MenuItem('Import', f=import_from_other))

        return rv

    @classmethod
    async def export_all(cls, *a):
        await start_export(NoteContent.get_all())

    @classmethod
    async def sort_titles(cls, menu, _, item):
        # sort by title, one time and then reconstruct menu
        NoteContent.sort_all()

        # force redraw
        menu.update_contents()

    @classmethod
    async def quick_create(cls, menu, _, item):
        # using QR, created a Note (never a password) with auto-generated title.
        # - we are auto-detecting some common QR formats here but only to get a title
        tmp = NoteContent()
        tmp.title = 'Scanned'

        zz = QRScannerInteraction()
        got = await zz.scan_text('Scan any QR or Barcode for text.')
        if not got or len(got) < 5: return

        # aways save it, and attempt to guess a nice name for it too
        tmp.misc = got

        if got.startswith('otpauth://totp/'):
            # see <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
            tmp.title = url_unquote(got[15:]).split('?', 1)[0]
        elif got.startswith('otpauth-migration://offline'):
            # see <https://github.com/qistoph/otp_export>
            tmp.title = 'Google Auth'
        elif '://' in got[0:20]:
            # might be a URL, try to get the domain name as title
            try:
                tmp.title = (got.split('://', 1)[1].split('/', 1)[0])[0:32]
            except:
                tmp.title = 'Scanned URL'

        await tmp._save_ux(menu)
        await cls.drill_to(menu, tmp)

    def update_contents(self):
        # Reconstruct the list of notes on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)

    @classmethod
    async def disable_notes(cls, *a):
        # they don't want feature anymore; already checked no notes in effect
        # - no need for confirm, they aren't loosing anything
        settings.remove_key('secnap')
        settings.remove_key('notes')
        settings.save()

        goto_top_menu()

    @classmethod
    async def new_note(cls, menu, _, item):
        # Create a new note. Wizard style
        tmp = PasswordContent() if item.arg == 'p' else NoteContent()
        didit = await tmp.edit(menu, _, item)

        if didit:
            await cls.drill_to(menu, tmp)

    @classmethod
    async def drill_to(cls, menu, item):
        # make it so looks like we drilled down into the new note
        menu.goto_idx(item.idx)
        m = MenuSystem(await item.make_menu())
        the_ux.push(m)


class NoteContentBase:
    def __init__(self, json={}, idx=-1):
        # no args will make a blank record, else we are deserializing json
        # - called only by subclasses
        for fld in self.flds:
            setattr(self, fld, json.get(fld, ''))
        self.idx = idx

    @classmethod
    def constructor(cls, j, idx):
        # create correct class based on JSON content
        return PasswordContent(j, idx) if 'user' in j else NoteContent(j, idx)

    def serialize(self):
        return {fld:getattr(self, fld, '') for fld in self.flds}

    to_json = serialize

    @classmethod
    def get_all(cls):
        # list of all notes/passwords
        rv = []
        for idx, j in enumerate(settings.get('notes', [])):
            rv.append(cls.constructor(j, idx))
        return rv

    @classmethod
    def count(cls):
        # how many do we have?
        return len(settings.get('notes', []))

    @classmethod
    def sort_all(cls):
        # sort and resave all notes based on title
        # - careful: self.idx values will be wrong for any existing instances
        # - 'title' is only common field to subclasses
        notes = cls.get_all()
        notes.sort(key=lambda j: j.title.lower())

        settings.put('notes', [n.serialize() for n in notes])
        settings.save()

    async def delete(self, *a):
        # Remove note
        ok = await ux_confirm("Everything about this note/password will be lost.")
        if not ok:
            await ux_dramatic_pause('Aborted.', 3)
            return

        was = list(settings.get('notes', []))
        assert self.idx >= 0
        assert self.idx < len(was)

        del was[self.idx]

        settings.put('notes', was)
        settings.save()

        # go to (updated) parent menu
        the_ux.pop()
        m = the_ux.top_of_stack()
        m.update_contents()

        await ux_dramatic_pause('Deleted.', 3)

    async def share_nfc(self, a, b, item):
        # share something via NFC -- if small enough and enabled
        from glob import NFC

        if not NFC: return

        v = getattr(self, item.arg)
        if len(v) < 8000:       # see MAX_NFC_SIZE
            await NFC.share_text(v)

    async def view_qr(self, k):
        # full screen QR
        try:
            await show_qr_code(getattr(self, k), msg=self.title, is_secret=True)
        except Exception as exc:
            # - not all data can be a QR (non-text, binary, zeros)
            # - might be too big for single QR
            # - may be a RuntimeError(n) where n is line number inside uqr
            await ux_show_story("Unable to display as QR.\n\nError: " + str(exc))

    async def view_qr_menu(self, a, b, item):
        await self.view_qr(item.arg)

    async def _save_ux(self, menu):
        is_new = self.save()

        if not is_new:
            # change our own menu contents
            menu.replace_items(await self.make_menu())

            # update parent
            parent = the_ux.parent_of(menu)
            parent.update_contents()
        else:
            menu.update_contents()

        await ux_dramatic_pause('Saved.', 3)

    def save(self):
        was = list(settings.get('notes', []))
        if self.idx == -1:
            was.append(self.serialize())
            self.idx = len(was)-1
            is_new = True
        else:
            was[self.idx] = self.serialize()
            is_new = False
        settings.put('notes', was)
        settings.save()

        return is_new

    async def export(self, *a):
        # single export
        await start_export([self])

    async def sign_txt_msg(self, a, b, item):
        from msgsign import ux_sign_msg, msg_signing_done
        txt = item.arg
        await ux_sign_msg(txt, approved_cb=msg_signing_done, kill_menu=False)

    def sign_misc_menu_item(self):
        return MenuItem("Sign Note Text", f=self.sign_txt_msg, arg=self.misc)


class PasswordContent(NoteContentBase):
    # "Passwords" have a few more fields and are more structured
    flds = ['title', 'user', 'password', 'site', 'misc' ]
    type_label = 'password'

    async def make_menu(self, *a):
        rv = [MenuItem('"%s"' % self.title, f=self.view)]
        if self.user:
            rv.append(MenuItem('↳ %s' % self.user, f=self.view))
        if self.site:
            rv.append(MenuItem('↳ %s' % self.site, f=self.view))
        #if self.misc: rv.append(MenuItem('↳ (notes)', f=self.view))
        return rv + [
            MenuItem('View Password', f=self.view_pw),
            MenuItem('Send Password', f=self.send_pw, predicate=lambda: settings.get('du', True)),
            MenuItem('Export', f=self.export),
            MenuItem('Edit Metadata', f=self.edit),
            MenuItem('Delete', f=self.delete),
            MenuItem('Change Password', f=self.change_pw),
            self.sign_misc_menu_item(),
            ShortcutItem(KEY_QR, f=self.view_qr_menu, arg=self.type_label),
            ShortcutItem(KEY_NFC, f=self.share_nfc, arg=self.type_label),
        ]

    async def view(self, *a):
        pl = len(self.password)
        m = ''
        if self.user:
            m += 'User: %s\n' % self.user

        m += 'Password: (%d chars)\n' % pl

        if self.site:
            m += 'Site: %s\n' % self.site

        if self.misc:
            m += '\nNotes:\n' + self.misc

        await ux_show_story(m, title=self.title)

    async def change_pw(self, *a):
        # Change password
        npw = await get_a_password(self.password)

        if npw == self.password: return
        if npw is None: return

        msg = 'New Password:\n%s\n\nOld Password:\n%s' % (
                    npw or '<EMPTY>', self.password or '<EMPTY>')
        ch = await ux_show_story(msg, title='Confirm Change?')
        if ch == 'y':
            self.password = npw
            self.save()
            await ux_dramatic_pause('Saved.', 3)
        else:
            await ux_dramatic_pause('Aborted.', 3)

    async def view_pw(self, *a):
        msg = self.password or '<EMPTY>'
        ch = await ux_show_story(msg, title=self.title, escape=KEY_QR,
                                 hint_icons=KEY_QR)
        if ch == KEY_QR:
            await self.view_qr(self.type_label)
            
    async def send_pw(self, *a):
        # use USB to send it -- weak at present
        from drv_entro import single_send_keystrokes
        from usb import EmulatedKeyboard

        if not EmulatedKeyboard.can_type(self.password):
            return await ux_show_story("Sorry, your password contains a character that "
                                            "we cannot type at this time.")
        await single_send_keystrokes(self.password)

    async def edit(self, menu, _, item):
        # Edit, also used for add new

        title = await ux_input_text(self.title, max_len=ONE_LINE, confirm_exit=False,
                                    prompt='Title', placeholder='(required for menu)')
        if not title:
            return None

        # blank is OK for all other values

        user = await ux_input_text(self.user, max_len=ONE_LINE, scan_ok=True, confirm_exit=False,
                                   prompt='Username', placeholder='(optional)')
        if user is None:
            user = self.user

        if self.idx == -1:
            # prompt for password only on new records.
            self.password = await get_a_password(self.password)

        site = await ux_input_text(self.site, max_len=ONE_LINE, scan_ok=True, confirm_exit=False,
                                   prompt='Website', placeholder='(optional)')
        if site is None:
            site = self.site

        misc = await ux_input_text(self.misc, max_len=None, scan_ok=True, confirm_exit=False,
                                   prompt='More Notes', placeholder='(optional)')
        if misc is None:
            misc = self.misc

        if self.idx != -1:
            # confirm changes, don't for new records
            chgs = []
            if self.title != title:
                chgs.append('Title')
            if self.site != site:
                chgs.append('Site Name')
            if self.user != user:
                chgs.append('Username')
            if self.misc != misc:
                chgs.append('Other Notes')

            if not chgs:
                await ux_dramatic_pause('No changes.', 3)
                return

            ok = await ux_confirm("Save changes?\n- " + ('\n- '.join(chgs)))
            if not ok:
                return None

        self.title = title
        self.user = user
        self.site = site
        self.misc = misc

        await self._save_ux(menu)
        return self


class NoteContent(NoteContentBase):
    # Pure "notes" have just a title and free-form text
    flds = ['title', 'misc']
    type_label = 'note'

    async def make_menu(self, *a):
        # Details and actions for this Note
        return [
            MenuItem('"%s"' % self.title, f=self.view),
            MenuItem('View Note', f=self.view),
            MenuItem('Edit', f=self.edit),
            MenuItem('Delete', f=self.delete),
            MenuItem('Export', f=self.export),
            self.sign_misc_menu_item(),
            ShortcutItem(KEY_QR, f=self.view_qr_menu, arg="misc"),
            ShortcutItem(KEY_NFC, f=self.share_nfc, arg='misc'),
        ]

    async def view(self, *a):
        ch = await ux_show_story(self.misc, title=self.title, escape=KEY_QR,
                                 hint_icons=KEY_QR)
        if ch == KEY_QR:
            await self.view_qr("misc")

    async def edit(self, menu, _, item):
        # Edit, also used for add new

        title = await ux_input_text(self.title, confirm_exit=False, max_len=CHARS_W-2,
                                    prompt='Title', placeholder='(required for menu)')
        if not title:
            return

        misc = await ux_input_text(self.misc, confirm_exit=False,
                                   max_len=None, scan_ok=True,
                                   prompt='Your Notes', placeholder='(freeform text)')
        if misc is None:
            misc = self.misc

        if self.idx != -1:
            # confirm changes, don't for new records
            chgs = []
            if self.title != title:
                chgs.append('Title')
            if self.misc != misc:
                chgs.append('Note Text')

            if not chgs:
                await ux_dramatic_pause('No changes.', 3)
                return

            ok = await ux_confirm("Save changes?\n- " + ('\n- '.join(chgs)))
            if not ok:
                await ux_dramatic_pause('Not saved. Change aborted.', 3)
                return

        self.title = title
        self.misc = misc

        await self._save_ux(menu)

        return self

async def start_export(notes):
    # Save out notes/passwords
    from glob import NFC
    from msgsign import write_sig_file
    import ujson as json
    from ux_q1 import show_bbqr_codes

    singular = (len(notes) == 1)

    item = notes[0].type_label if singular else  'all notes & passwords'
    choice = await import_export_prompt(item, title="Data Export", no_nfc=True,
                                        footnotes="WARNING: No encryption happens here."
                                                  " Your secrets will be cleartext.")
    if choice == KEY_CANCEL:
        return

    # render it
    data = json.dumps(dict(coldcard_notes=[i.serialize() for i in notes]))

    if choice == KEY_QR:
        # Always do BBRq.
        await show_bbqr_codes('J', data, 'Notes & Passwords Export')
        return

    # ideally, we'd use the title to make a filename, but meh...
    fname_pattern = 'cc-notes.json' if not singular else ('cc-%s.json' % notes[0].type_label)

    try:
        with CardSlot(**choice) as card:
            fname, nice = card.pick_filename(fname_pattern)

            with open(fname, 'w+') as fp:
                fp.write(data)

            h = ngu.hash.sha256s(data)
            sig_nice = write_sig_file([(h, fname)])

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = 'Export file written:\n\n%s\n\nSignature file written:\n\n%s' % (
        nice, sig_nice
    )
    await ux_show_story(msg)


async def import_from_other(menu, *a):
    # Suck in a bunch of notes/passwords. Has to be coming from a Coldcard
    # - but it's also just simple JSON
    from actions import file_picker
    import json

    choice = await import_export_prompt('secure notes and/or passwords', no_nfc=True,
                                            is_import=True, title='Data Import')
    if choice == KEY_CANCEL:
        return

    elif choice == KEY_QR:
        # Always do BBRq.
        zz = QRScannerInteraction()
        records = await zz.scan_json('Scan BBQr from other COLDCARD.')
        if records is None: return

    else:
        def contains_json(fname):
            if not fname.endswith('.json'): return False
            try:
                obj = json.load(open(fname, 'rt'))
                assert 'coldcard_notes' in obj
                return True
            except: pass

        fn = await file_picker(min_size=8, max_size=100000, taster=contains_json, **choice)
        if not fn: return

        with CardSlot(readonly=True, **choice) as card:
            records = json.load(open(fn, 'rt'))

    # We have some JSON, parsed now.
    await import_from_json(records)

    await ux_dramatic_pause('Saved.', 3)
    menu.update_contents()

async def import_from_json(records):
    # should dedup, but we aren't
    try:
        assert 'coldcard_notes' in records, 'Incorrect format'

        # de-and-re-serialize each one (just in case? backwards compat?)
        new = [NoteContentBase.constructor(rec, -1).serialize()
                    for rec in records['coldcard_notes']]

        was = list(settings.get('notes', []))
        was.extend(new)
        settings.set('notes', was)
        settings.set('secnap', True)
        settings.save()

    except Exception as e:
        await ux_show_story(title="Failure", msg=str(e) + '\n\n' + problem_file_line(e))

# EOF
