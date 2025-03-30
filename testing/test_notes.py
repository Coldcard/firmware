# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tests for ../shared/notes.py
#
import pytest, time, json, random, os, pdb
from helpers import prandom
from charcodes import *
from constants import AF_CLASSIC, AF_P2WPKH_P2SH, AF_P2WPKH
from bbqr import split_qrs


# All tests in this file are exclusively meant for Q
#
@pytest.fixture(autouse=True)
def THIS_FILE_requires_q1(is_q1):
    if not is_q1:
        raise pytest.skip('Q1 only')

@pytest.fixture
def goto_notes(cap_story, cap_menu, press_select, goto_home, pick_menu_item):
    # drill to the notes menu
    def doit(item=None):
        mt = 'Secure Notes & Passwords'
        goto_home()  # TODO this is probably why all menus are properly generated
        m = cap_menu()
        if mt in m:
            pick_menu_item(mt)
        else:
            pick_menu_item('Advanced/Tools')
            pick_menu_item(mt)

            title, story = cap_story()
            if title == 'Secure Notes':
                # enable feature
                press_select()

        if item:
            pick_menu_item(item)

    return doit

@pytest.fixture
def need_some_notes(settings_get, settings_set):
    # create a note or use what's there, provide as obj
    def doit(title='Title Here', body='Body'):
        notes = settings_get('notes', [])
        if not notes:
            settings_set('notes', [dict(misc=body, title=title)])
            settings_set('secnap', True)
        return notes
    return doit

@pytest.fixture
def need_some_passwords(settings_get, settings_set):
    def doit():
        notes = settings_get('notes', [])
        if not any(1  for n in notes if n.get('password', False)):
            notes.extend([
                {'misc': 'More Notes AAAA',
                 'password': 'fds65fd5f1sd51s',
                 'site': 'https://a.com',
                 'title': 'A',
                 'user': 'AAA'},
                {'misc': 'More Notes BBB',
                 'password': 'default',
                 'site': 'www.site.b.com',
                 'title': 'B-Title',
                 'user': 'Buzzer'}
            ])
            settings_set('notes', notes)
            settings_set('secnap', True)
        return notes
    return doit

@pytest.fixture
def delete_note(press_select, goto_notes, cap_menu, pick_menu_item,
                cap_story):
    def doit(n_title):
        goto_notes()
        m = cap_menu()
        found = [i for i in m if f': {n_title}' in i]
        assert found
        pick_menu_item(found[-1])

        pick_menu_item('Delete')
        title, story = cap_story()
        assert 'SURE' in title
        assert 'Everything about this' in story

        # back to top notes menu
        press_select()

    return doit

@pytest.fixture
def build_note(goto_notes, pick_menu_item, enter_text, cap_menu, cap_story,
               need_keypress, cap_screen_qr, readback_bbqr, nfc_read_text,
               press_select, press_cancel, is_headless, nfc_disabled):

    def doit(n_title, n_body):
        # we don't try to preserve leading/trailing spaces on note bodies
        n_body= n_body.strip()

        goto_notes('New Note')

        # create
        enter_text(n_title)
        enter_text(n_body, multiline=True)

        # view
        time.sleep(0.1)
        m = cap_menu()
        assert m[0] == f'"{n_title}"'
        assert m[1] == 'View Note'
        assert m[2] == 'Edit'
        assert m[3] == 'Delete'
        assert m[4] == 'Export'

        # test readback
        for mi in ['View Note', f'"{n_title}"']:
            time.sleep(0.1)
            pick_menu_item(mi)
            time.sleep(1)
            title, story = cap_story()
            assert title == n_title
            assert story == n_body

            if not is_headless:
                need_keypress(KEY_QR)
                qr_rb = cap_screen_qr().decode('utf-8')
                assert qr_rb == n_body

            press_cancel()

        # hidden QR button on menu feature
        m = cap_menu()
        assert m[1] == 'View Note'
        if not is_headless:
            need_keypress(KEY_QR)
            qr_rb = cap_screen_qr().decode('utf-8')
            assert qr_rb == n_body
            press_cancel()

        # hidden NFC button on menu feature
        m = cap_menu()
        assert m[1] == 'View Note'
        if not nfc_disabled:
            need_keypress(KEY_NFC)
            time.sleep(.1)
            nfc_rb = nfc_read_text()
            time.sleep(.1)
            assert nfc_rb == n_body
            press_cancel()

        # export
        pick_menu_item('Export')
        title, story = cap_story()
        assert 'Export' in title
        assert 'to save note to SD' in story
        assert 'to show QR' in story
        assert 'WARNING' in story
        assert 'will be cleartext' in story

        need_keypress(KEY_QR)
        file_type, data = readback_bbqr()
        assert file_type == 'J'
        obj = json.loads(data)
        assert obj.keys() == {'coldcard_notes'}
        obj = obj['coldcard_notes']
        assert len(obj) == 1
        obj = obj[0]
        assert obj['title'] == n_title
        assert obj['misc'] == n_body

        # back to top notes menu
        press_select()

    return doit


@pytest.fixture
def build_password(goto_notes, pick_menu_item, enter_text, cap_menu, cap_story,
                   need_keypress, cap_screen_qr, nfc_read_text,
                   cap_text_box, settings_get, settings_set, scan_a_qr,
                   press_select, press_cancel, is_headless):

    def doit(n_title, n_user=None, n_pw='secret', n_site=None, n_body=None, key_pw=None):
        goto_notes('New Password')
        enter_text(n_title)
        if n_user:
            enter_text(n_user)
        else:
            press_select()

        if key_pw and key_pw == KEY_QR:
            need_keypress(KEY_QR)
            time.sleep(1.1)
            scan_a_qr(n_pw)
            time.sleep(1.1)

        elif key_pw:
            # function keys: let it auto gen
            need_keypress(key_pw)
            time.sleep(0.1)
            if key_pw == KEY_F5:       # bip-85
                enter_text('34')
                time.sleep(0.1)
            n_pw = ''.join(cap_text_box()).strip()
            assert n_pw and len(n_pw) > 10
            need_keypress(KEY_ENTER)
        else:
            enter_text(n_pw)

        if n_site:
            enter_text(n_site)
        else:
            press_select()

        if n_body:
            enter_text(n_body, multiline=True)
        else:
            press_cancel()

        # view
        time.sleep(0.1)
        m = cap_menu()
        N = 1
        assert m[0] == f'"{n_title}"'
        if n_user and not n_site:
            assert n_user in m[1]
            N += 1
        elif n_site and not n_user:
            assert n_site in m[1]
            N += 1
        elif n_site and n_user:
            assert n_user in m[1]
            assert n_site in m[2]
            N += 2

        assert 'View Password' in m
        assert 'Send Password' in m
        assert 'Export' in m
        assert 'Edit Metadata' in m
        assert 'Delete' in m
        assert 'Change Password' in m

        # top 3 menu items do same thing: view details
        for idx in range(N):
            pick_menu_item(m[idx])
            title, story = cap_story()
            assert title == n_title
            if n_user:
                assert f'User: {n_user}' in story
            if n_site:
                assert f'Site: {n_site}' in story
            assert 'Password: (' in story
            if n_body:
                assert 'Notes:' in story
                assert story.endswith(n_body)

            need_keypress(KEY_CANCEL)

        # view pw as text and QR
        pick_menu_item('View Password')
        title, story = cap_story()
        assert title == n_title
        assert story == n_pw

        if not is_headless:
            need_keypress(KEY_QR)
            qr_rb = cap_screen_qr().decode('utf-8')
            assert qr_rb == n_pw
            need_keypress(KEY_CANCEL)

    return doit


@pytest.fixture
def change_password(goto_notes, pick_menu_item, enter_text, cap_story,
                    need_keypress, settings_get, press_select, press_cancel,
                    cap_menu):

    def doit(id_title, new_title=None, new_username=None, new_site=None,
             new_misc=None, new_password=None, old_password=None):
        goto_notes()
        m = cap_menu()
        found = [i for i in m if f': {id_title}' in i]
        assert found

        pick_menu_item(found[0])

        if new_title or new_username or new_site or new_misc:
            need_in_story = []
            pick_menu_item('Edit Metadata')
            if new_title:
                enter_text(KEY_CLEAR + new_title)
                need_in_story.append('Title')
            else:
                press_select()
            if new_username:
                enter_text(KEY_CLEAR + new_username)
                need_in_story.append('Username')
            else:
                press_select()
            if new_site:
                enter_text(KEY_CLEAR + new_site)
                need_in_story.append('Site Name')
            else:
                press_select()
            if new_misc:
                enter_text(KEY_CLEAR + new_misc, multiline=True)
                need_in_story.append('Other Notes')
            else:
                press_cancel()

            # approve change
            time.sleep(0.1)
            title, story = cap_story()
            assert 'SURE' in title
            for i in need_in_story:
                assert i in story
            need_keypress(KEY_ENTER)

        if new_password:
            pick_menu_item('Change Password')
            enter_text(KEY_CLEAR + new_password)

            # confirm
            time.sleep(0.1)
            title, story = cap_story()
            assert 'Confirm' in title
            assert 'New Password' in story
            assert 'Old Password' in story
            assert new_password in story

            need_keypress(KEY_ENTER)

        # test changes at low-level
        time.sleep(0.1)
        notes = settings_get('notes')
        note = [n for n in notes if n['title'] == (new_title or id_title)][0]
        assert note
        if new_site:
            assert note['site'] == new_site
        if new_username:
            assert note['user'] == new_username
        if new_misc:
            assert note['misc'] == new_misc
        if new_password:
            assert note['password'] == new_password

    return doit


@pytest.mark.parametrize('n_title', [ 'a', 'aaa', 'b'*32])
@pytest.mark.parametrize('n_body', [ 'short', 'very long '*30, 'mOKa', 'x X x'])
def test_build_note(n_title, n_body, build_note, delete_note):
    build_note(n_title, n_body)
    delete_note(n_title)

    
@pytest.mark.parametrize('size', [ 4000, 30000])
@pytest.mark.parametrize('encoding', '2Z' )
def test_huge_notes(size, encoding, goto_notes, enter_text, cap_menu, need_keypress,
                    scan_a_qr, settings_set, settings_get):

    # Since we don't limit note sizes, by request of NVK ... test them
    
    n_body = ''.join(chr((i%95) + 32) for i in prandom(size))
    n_title = f'Size {size} {random.randint(100000, 999999)}'

    # kill old things, enable feature
    settings_set('notes', [])

    goto_notes('New Note')
    enter_text(n_title)

    # use BBRq to import body -- fast and verbatim
    need_keypress(KEY_QR)

    actual_vers, parts = split_qrs(n_body, 'U',  max_version=20, encoding=encoding)
    random.shuffle(parts)

    for p in parts:
        scan_a_qr(p)
        time.sleep(2.0 / len(parts))       # just so we can watch
    
    time.sleep(.5)      # decompression time in some cases
    m = cap_menu()
    assert m[-2] == 'Export'

    notes = settings_get('notes')
    assert len(notes) == 1
    assert notes[0]['title'] == n_title
    assert notes[0]['misc'] == n_body

    settings_set('notes', [])
    goto_notes()        # redraw


@pytest.mark.parametrize('key', [None, KEY_QR])
@pytest.mark.parametrize('site', ["https://feed.org", None])
@pytest.mark.parametrize('user', [None, "joe"])
@pytest.mark.parametrize('misc', [None, "bla bla bla bla"])
def test_password_flow(key, site, user, misc, build_password, change_password):
    # Test password entry, including all the auto-generation capabilities
    title = os.urandom(4).hex()
    build_password(n_title=title, n_user=user, n_pw='A'*99,
                   n_site=site, n_body=misc,
                   key_pw=None)
    change_password(id_title=title,
                    new_username="changed" if user is None else None,
                    new_site="https://changed.org" if site is None else None,
                    new_misc="new bla newer bla newest bla" if misc is None else None)


@pytest.mark.parametrize('key', [KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5])
def test_password_flow_gen(key, build_password, change_password):
    title = os.urandom(4).hex()
    build_password(n_title=title, n_pw='B'*3, key_pw=key)
    change_password(id_title=title, new_password="changed")


def test_password_change_title(build_password, change_password):
    build_password(n_title="old_title", n_pw="default")
    change_password(id_title="old_title", new_title="new_title")


def test_top_export(goto_notes, pick_menu_item, cap_story, need_keypress, settings_get,
                    readback_bbqr, need_some_notes):

    notes = settings_get('notes', [])
    if not len(notes):
        notes = need_some_notes()

    goto_notes()
    pick_menu_item('Export All')

    title, story = cap_story()
    assert 'Export' in title
    assert 'to SD Card' in story
    assert 'to show QR' in story
    assert 'WARNING' in story
    assert 'will be cleartext' in story

    need_keypress(KEY_QR)
    file_type, data = readback_bbqr()
    assert file_type == 'J'
    obj = json.loads(data)
    assert obj.keys() == {'coldcard_notes'}
    assert obj['coldcard_notes'] == notes
    need_keypress(KEY_ENTER)

def test_sort_by_title(goto_notes, pick_menu_item, cap_story, need_keypress, settings_get,
                    settings_set, build_note, cap_menu, build_password):

    settings_set('notes', [])

    build_note('ZZZ', 'b1')

    goto_notes()
    assert 'Sort By Title' not in cap_menu()

    build_note('MMM', 'b2')
    build_note('AAA', 'b3')
    build_note('mmm', 'b2')
    build_note('Aaa', 'b3')
    build_password('Bbb')

    notes = settings_get('notes')

    goto_notes()
    pick_menu_item('Sort By Title')

    # effect is immedate
    after = settings_get('notes', [])

    assert sorted((i['title'] for i in after), key=lambda i:i.lower()) \
                    == [i['title'] for i in after]

def test_top_import(goto_notes, cap_menu, cap_story, need_keypress, settings_get,
                    settings_set, scan_a_qr, need_some_notes):
    # make some
    notes = need_some_notes()

    # wipe them
    settings_set('notes', [])

    goto_notes('Import')
    title, story = cap_story()
    assert 'Import' in title
    assert 'from SD Card' in story
    assert 'to scan QR' in story
    assert 'WARNING' not in story

    jj = json.dumps(dict(coldcard_notes=notes))

    need_keypress(KEY_QR)

    _, parts = split_qrs(jj, 'J', max_version=20)
    random.shuffle(parts)

    for p in parts:
        scan_a_qr(p)

    time.sleep(.5)  # decompression time in some cases
    m = cap_menu()
    for _ in range(3):
        if "1:" in m[0]:
            break
        time.sleep(.2)
        m = cap_menu()
        continue

    mm = [n.split(":")[-1].strip() for n in m if ":" in n]
    for note in notes:
        assert note['title'] in mm
    assert settings_get('notes', 'MISSING') == notes
    goto_notes()


@pytest.mark.parametrize('qr,title', [
    ('otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30',
     'ACME Co:john.doe@email.com'),
    ('otpauth://totp/pi%40raspberrypi?secret=7KSQL2JTUDIS5EF65KLMRQIIGY&issuer=raspberrypi',
     'pi@raspberrypi'),
    ('otpauth-migration://offline?data=CiAKCghCEIa1rWta1rUSDEV4YW1wbGUgRGF0YSABKAEwAhAB',
     'Google Auth'),
])  
def test_top_qr(qr, title, goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress,
                settings_get, settings_set, scan_a_qr):
    # import some fun QR codes (will be notes) from top-level, undocumented
    goto_notes()
    need_keypress(KEY_QR)

    scan_a_qr(qr)
    time.sleep(1)

    # lazy readback
    notes = settings_get('notes', [])

    assert notes[-1]['title'] == title
    assert notes[-1]['misc'] == qr

    #pick_menu_item('Delete')
    #need_keypress(KEY_ENTER)


def test_top_disable(goto_notes, pick_menu_item, cap_menu, settings_get, settings_set):
    # Keep last - disables, deletes notes
    settings_set('notes', [])
    goto_notes()
    m = cap_menu()
    assert 'Disable Feature' in m
    pick_menu_item('Disable Feature')
    m = cap_menu()

    assert 'Ready To Sign' in m
    assert settings_get('notes', 'MISSING') == 'MISSING'


def test_tmp_notes_separation(goto_notes, pick_menu_item, generate_ephemeral_words,
                              build_note, build_password, seed_vault_enable, cap_menu,
                              restore_main_seed, press_select, goto_home):
    seed_vault_enable()
    goto_notes()
    # create some notes in master settings
    build_note(n_title="note-master", n_body="Master seed note meta")
    build_password(n_title="pwd-master", n_user="ccu", n_pw="fdshjd76342gdhj",
                   n_body="WIF: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")

    # switch to random ephemeral seed
    generate_ephemeral_words(12, from_main=True, seed_vault=True)

    time.sleep(.1)
    goto_notes()
    m = cap_menu()
    assert len(m) == 4  # EMPTY - no saved notes

    build_note(n_title="note-tmp", n_body="Temporary seed note meta")
    build_password(n_title="pwd-tmp", n_user="ttu", n_pw="n7c4tvb6erdgg8",
                   n_body="HEX: 800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D")

    # switch to yet another random ephemeral seed
    generate_ephemeral_words(24, from_main=False, seed_vault=True)

    time.sleep(.1)
    goto_notes()
    m = cap_menu()
    assert len(m) == 4  # EMPTY - no saved notes

    build_note(n_title="note-tmp2", n_body="Second Temporary seed note meta")

    # back to master
    restore_main_seed(seed_vault=True)
    time.sleep(.1)

    goto_notes()
    m = cap_menu()
    mm = [n.split(":")[-1].strip() for n in m if ":" in n]
    assert 'note-master' in mm
    assert 'pwd-master' in mm
    assert 'note-tmp' not in mm
    assert 'pwd-tmp' not in mm
    assert 'note-tmp2' not in mm

    goto_home()
    pick_menu_item("Seed Vault")
    time.sleep(.1)
    m = cap_menu()

    # first tmp
    pick_menu_item(m[0])
    pick_menu_item("Use This Seed")
    press_select()
    goto_notes()
    m = cap_menu()
    mm = [n.split(":")[-1].strip() for n in m if ":" in n]
    assert 'note-master' not in mm
    assert 'pwd-master' not in mm
    assert 'note-tmp' in mm
    assert 'pwd-tmp' in mm
    assert 'note-tmp2' not in mm

    goto_home()
    pick_menu_item("Seed Vault")
    time.sleep(.1)
    m = cap_menu()

    # second tmp (directly from first tmp)
    pick_menu_item(m[1])
    pick_menu_item("Use This Seed")
    press_select()
    goto_notes()

    m = cap_menu()
    mm = [n.split(":")[-1].strip() for n in m if ":" in n]
    assert 'note-master' not in mm
    assert 'pwd-master' not in mm
    assert 'note-tmp' not in mm
    assert 'pwd-tmp' not in mm
    assert 'note-tmp2' in mm

    # back to master (again)
    restore_main_seed(seed_vault=True)
    time.sleep(.1)

    goto_notes()
    m = cap_menu()
    mm = [n.split(":")[-1].strip() for n in m if ":" in n]
    assert 'note-master' in mm
    assert 'pwd-master' in mm
    assert 'note-tmp' not in mm
    assert 'pwd-tmp' not in mm
    assert 'note-tmp2' not in mm


@pytest.mark.parametrize("msg", ["COLDCARD rocks!", "cc\nCC"])
@pytest.mark.parametrize("addr_fmt", [AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH])
@pytest.mark.parametrize("acct", [None, 0, 9999])
@pytest.mark.parametrize("way", ["sd", "qr", "nfc", "vdisk"])
def test_sign_note_body(msg, addr_fmt, acct, need_some_notes,
                        pick_menu_item, sign_msg_from_text, way,
                        goto_notes, settings_set):
    settings_set("notes", [])
    title = "aaa"
    need_some_notes(title, msg)
    goto_notes()
    pick_menu_item(f"1: {title}")
    pick_menu_item("Sign Note Text")
    sign_msg_from_text(msg, addr_fmt, acct, False, 0, way)


@pytest.mark.parametrize("chain", ["BTC", "XTN"])
@pytest.mark.parametrize("change", [True, False])
@pytest.mark.parametrize("idx", [None, 0, 9999])
def test_sign_password_free_form(chain, change, idx, need_some_passwords, settings_set,
                                 goto_notes, pick_menu_item, sign_msg_from_text):
    settings_set('notes', [])  # clear
    title = "A"
    msg = 'More Notes AAAA'
    settings_set('notes', [
        {'misc': msg,
         'password': 'fds65fd5f1sd51s',
         'site': 'https://a.com',
         'title': title,
         'user': 'AAA'}
    ])
    goto_notes()
    pick_menu_item(f"1: {title}")
    pick_menu_item("Sign Note Text")
    sign_msg_from_text(msg, AF_P2WPKH, None, change, idx, "qr", chain)

# EOF
