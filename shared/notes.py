# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# notes.py - Store some short notes, securely.
#
import ngu, bip39
from menu import MenuItem, MenuSystem
from ux import ux_show_story, the_ux, ux_dramatic_pause, ux_confirm, the_ux
from ux import PressRelease, ux_input_numbers, ux_input_text, show_qr_code
from actions import goto_top_menu
from glob import settings, dis
from files import CardMissingError, needs_microsd, CardSlot
from charcodes import KEY_QR, KEY_ENTER, KEY_CANCEL, KEY_CLEAR
from charcodes import KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6
from lcd_display import CHARS_W

ONE_LINE = CHARS_W-2

async def make_notes_menu(*a):
    if settings.get('notes', False) == False:
        # Explain feature, and then enable if interested. Drop them into menu.
        ch = await ux_show_story('''\
Enable this feature to store short text notes and passwords inside the Coldcard.

The notes are encrypted along with your other settings and will be backed-up with them.

Press ENTER to enable and get started otherwise CANCEL.''',
                title="Secure Notes")

        if ch != 'y':
            return

        # mark as enabled (altho empty)
        settings.set('notes', [])

        # need to correct top menu now, so this choice is there.

    return NotesMenu(NotesMenu.construct())

async def get_a_password(old_value):
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

    def _toggle_case(was):
        # undocumented
        return was.upper() if was[0].islower() else was.lower()
        

    fmsg = (KEY_F1 + ' 12 ' + KEY_F2 + ' 24 word '
                            + KEY_F3 + KEY_F4 + ' random '
                            + KEY_F5 + 'B85')
    handlers = {KEY_F1: _pick_12, KEY_F2: _pick_24, KEY_F3: _pick_dense,
                KEY_F4: _do_dumb, KEY_F6: _toggle_case, KEY_F5: _bip85}

    return await ux_input_text(old_value, confirm_exit=True, max_len=128, scan_ok=True,
                    b39_complete=True, prompt='Password',  placeholder='(optional)',
                    funct_keys=(fmsg, handlers))

class NotesMenu(MenuSystem):

    @classmethod
    def construct(cls):
        # Dynamic menu with user-defined names of notes shown

        news = [ MenuItem('New Note', f=cls.new_note, arg='n'),
                 MenuItem('New Password', f=cls.new_note, arg='p') ]

        if not NoteContent.count():
            rv = news + [ MenuItem('Disable Feature', f=cls.disable_notes) ]
        else:
            rv = []
            for note in NoteContent.get_all():
                rv.append(MenuItem('%d: %s' % (note.idx+1, note.title), menu=note.make_menu))

            rv.extend(news)

        rv.append(MenuItem('Import from File', f=None))
        return rv

    def update_contents(self):
        # Reconstruct the list of notes on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)

    @classmethod
    async def disable_notes(cls, *a):
        # they don't want feature anymore; already checked no notes in effect
        # - no need for confirm, they aren't loosing anything
        settings.remove_key('notes')
        settings.save()

        from actions import goto_top_menu
        goto_top_menu()

    @classmethod
    async def new_note(cls, menu, _, item):
        # Create a new note. Wizard style
        tmp = PasswordContent() if item.arg == 'p' else NoteContent()
        await tmp.edit(menu, _, item)


class NoteContentBase:
    def __init__(self, json={}, idx=-1):
        # no args will make a blank record, else we are deserializing json
        for fld in self.flds:
            setattr(self, fld, json.get(fld, ''))
        self.idx = idx

    def serialize(self):
        return {fld:getattr(self, fld, '') for fld in self.flds}

    @classmethod
    def get_all(cls):
        # list of all notes/passwords
        rv = []
        for idx, j in enumerate(settings.get('notes', [])):
            rv.append(PasswordContent(j, idx) if 'user' in j else NoteContent(j, idx))
        return rv

    @classmethod
    def count(cls):
        # how many do we have?
        return len(settings.get('notes', []))

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

    async def export(self, *a):
        pass

    async def _save_ux(self, menu):
        is_new = self.save()

        if not is_new:
            # change our own menu (only one thing: title line)
            menu.items[0].label = '"%s"' % self.title

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

class PasswordContent(NoteContentBase):
    # "Passwords" have a few more fields and are more structured
    flds = ['title', 'user', 'password', 'site', 'misc' ]

    async def make_menu(self, *a):
        return [
            MenuItem('"%s"' % self.title, f=self.view),
            MenuItem('View Password', f=self.view_pw),
            MenuItem('Change Password', f=self.change_pw),
            MenuItem('Send Password', f=self.send_pw),
            MenuItem('Edit', f=self.edit),
            MenuItem('Delete', f=self.delete),
            MenuItem('Export', f=self.export),
        ]

    async def view(self, *a):
        pl = len(self.password)
        m = 'Site: %s''' % self.site
        m = 'User: %s''' % self.user
        m += '\nPassword: (%d chars long)' % pl

        if self.misc:
            m += '\nNotes:\n' + self.misc

        await ux_show_story(m, title=self.title)

    async def change_pw(self, *a):
        # change password
        npw = await get_a_password(self.password)

        if npw == self.password: return

        msg = 'Old Password:\n%s\n\nNew Password:\n%s' % (
                    self.password or '<EMPTY>', npw or '<EMPTY>')
        ch = await ux_show_story(msg, title='Confirm Change')
        if ch == 'y':
            self.password = npw
            self.save()
            await ux_dramatic_pause('Saved.', 3)
        else:
            await ux_dramatic_pause('Aborted.', 3)

    async def view_pw(self, *a):
        msg = self.password or '<EMPTY>'
        msg += '\n\nPress (1) to change, (6) to send over USB.'
        ch = await ux_show_story(msg, title='Password', escape='16')
        if ch == '1':
            await self.change_pw()
        elif ch == '6':
            await self.send_pw()
            

    async def send_pw(self, *a):
        pass

    async def edit(self, menu, _, item):
        # Edit, also used for add new

        title = await ux_input_text(self.title, confirm_exit=False, max_len=ONE_LINE,
                        prompt='Title', placeholder='(required for menu)')
        if not title:
            return

        # blank is OK for all other values

        user = await ux_input_text(self.site, confirm_exit=True, max_len=ONE_LINE, scan_ok=True,
                                prompt='Username', placeholder='(optional)')

        if self.idx == -1:
            # prompt for password only on new records.
            self.password = await get_a_password(self.password)

        site = await ux_input_text(self.site, confirm_exit=True, max_len=ONE_LINE, scan_ok=True,
                                prompt='Website', placeholder='(optional)')

        misc = await ux_input_text(self.misc, confirm_exit=True, max_len=None, scan_ok=True,
                                            prompt='More Notes', placeholder='(optional)')

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

            ok = await ux_confirm("Save changes?\n- " + ('\n - '.join(chgs)))
            if not ok:
                return

        self.title = title
        self.site = site
        self.misc = misc
        self.user = user

        await self._save_ux(menu)


class NoteContent(NoteContentBase):
    # Pure "notes" have just a title and free-form text
    flds = ['title', 'misc' ]

    async def make_menu(self, *a):
        # details and actions for this Note
        # details and actions for this Note
        return [
            MenuItem('"%s"' % self.title, f=self.view),
            MenuItem('View Notes', f=self.view),
            #MenuItem('Send Password', f=self.send_pw),
            MenuItem('Edit', f=self.edit),
            MenuItem('Delete', f=self.delete),
            MenuItem('Export', f=self.export),
        ]

    async def view(self, *a):
        await ux_show_story(self.misc, title=self.title)

    async def edit(self, menu, _, item):
        # Edit, also used for add new

        title = await ux_input_text(self.title, confirm_exit=False, max_len=CHARS_W-2,
                        prompt='Title', placeholder='(required for menu)')
        if not title:
            return

        # blank is OK for all other values

        misc = await ux_input_text(self.misc, confirm_exit=True, max_len=None, scan_ok=True,
                                    prompt='Your Notes', placeholder='(freeform text)')

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

            ok = await ux_confirm("Save changes?\n- " + ('\n - '.join(chgs)))
            if not ok:
                return

        self.title = title
        self.misc = misc

        await self._save_ux(menu)


# EOF


