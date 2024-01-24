# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# tests for ../shared/notes.py
#
import pytest, time, os, shutil, json, random, pdb
from test_ux import word_menu_entry, enter_complex
from binascii import a2b_hex
from helpers import prandom
from constants import simulator_fixed_tprv
from charcodes import *

from test_bbqr import readback_bbqr, render_bbqr, readback_bbqr_ll
from bbqr import split_qrs

# All tests in this file are exclusively meant for Q
#
@pytest.fixture(autouse=True)
def THIS_FILE_requires_q1(is_q1):
    if not is_q1:
        raise pytest.skip('Q1 only')

@pytest.fixture
def goto_notes(cap_story, cap_menu, need_keypress, goto_home, pick_menu_item):
    # drill to the notes menu
    def doit(item=None):
        mt = 'Secure Notes & Passwords'
        goto_home()
        m = cap_menu()
        if mt in m:
            pick_menu_item(mt)
        else:
            pick_menu_item('Advanced/Tools')
            pick_menu_item(mt)

            title, story = cap_story()
            if title == 'Secure Notes':
                # enable feature
                need_keypress('y')

        if item:
            pick_menu_item(item)

    return doit

@pytest.fixture
def need_some_notes(settings_get, settings_set):
    # create a note or use what's there, provide as obj
    def doit():
        notes = settings_get('notes', [])
        if not notes:
            settings_set('notes', [dict(misc='Body', title='Title Here')])
        return notes
    return doit


@pytest.mark.parametrize('n_title', [ 'a', 'aaa', 'b'*32])
@pytest.mark.parametrize('n_body', [ 'short', 'very long '*30])
def test_build_note(n_title, n_body, goto_notes, pick_menu_item, enter_text, cap_menu, cap_story, need_keypress, cap_screen_qr, readback_bbqr, nfc_read_text):

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
    assert m[-1] == 'Export'

    # test readback
    for mi in ['View Note', f'"{n_title}"']:
        time.sleep(0.1)
        pick_menu_item(mi)
        title, story = cap_story()
        assert title == n_title
        assert story == n_body
        need_keypress(KEY_QR)
        qr_rb = cap_screen_qr().decode('utf-8')
        assert qr_rb == n_body
        need_keypress(KEY_CANCEL)

    # hidden QR button on menu feature
    m = cap_menu()
    assert m[1] == 'View Note'
    need_keypress(KEY_QR)
    qr_rb = cap_screen_qr().decode('utf-8')
    assert qr_rb == n_body
    need_keypress(KEY_CANCEL)

    # hidden NFC button on menu feature
    m = cap_menu()
    assert m[1] == 'View Note'
    need_keypress(KEY_NFC)
    nfc_rb = nfc_read_text()
    assert nfc_rb == n_body
    need_keypress(KEY_CANCEL)

    # export
    m = cap_menu()
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

    # drill back to it
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
    need_keypress(KEY_ENTER)
    m = cap_menu()
    assert ('Export All' in m) or ('Disable Feature' in m)
    
@pytest.mark.parametrize('size', [ 4000, 30000])
@pytest.mark.parametrize('encoding', '2Z' )
def test_huge_notes(size, encoding, goto_notes, pick_menu_item, enter_text, cap_menu, cap_story, need_keypress, cap_screen_qr, readback_bbqr, scan_a_qr, settings_set, settings_get):

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
    assert m[-1] == 'Export'

    notes = settings_get('notes')
    assert len(notes) == 1
    assert notes[0]['title'] == n_title
    assert notes[0]['misc'] == n_body

    settings_set('notes', [])
    goto_notes()        # redraw

@pytest.mark.parametrize('key', 'AB' + KEY_F1 + KEY_F2 + KEY_F3 + KEY_F4 + KEY_F5 + KEY_QR)
def test_build_password(key, goto_notes, pick_menu_item, enter_text, cap_menu, cap_story, need_keypress, cap_screen_qr, readback_bbqr, nfc_read_text, cap_text_box, settings_get, settings_set, scan_a_qr):
    # Test password entry, including all the auto-generation capabilities
    case = '0x%02x' % ord(key)

    n_title = f'Title {case}'
    n_user = f'Username {case}'
    n_pw = None
    n_site = f'Site {case}'
    n_body = f'More Notes {case}'

    # create
    goto_notes('New Password')
    enter_text(n_title)
    enter_text(n_user)
    if key == 'A':
        n_pw = 'A' * 99
        enter_text(n_pw)
    elif key == 'B':
        n_pw = 'B' * 3
        enter_text(n_pw)
    elif key == KEY_QR:
        n_pw = 'QR rocks'
        need_keypress(KEY_QR)
        time.sleep(1.1)
        scan_a_qr(n_pw)
        time.sleep(1.1)
        need_keypress(KEY_ENTER)
    else:
        # function keys: let it auto gen
        need_keypress(key)
        time.sleep(0.1)
        if key == KEY_F5:       # bip-85
            enter_text('34')
            time.sleep(0.1)
        n_pw = ''.join(cap_text_box()).strip()
        assert n_pw and len(n_pw) > 10
        need_keypress(KEY_ENTER)

    enter_text(n_site)
    enter_text(n_body, multiline=True)

    # view
    time.sleep(0.1)
    m = cap_menu()
    assert m[0] == f'"{n_title}"'
    assert n_user in m[1]
    assert n_site in m[2]
    assert 'Export' in m

    # top 3 menu items do same thing: view details
    for idx in range(3):
        pick_menu_item(m[idx])
        title, story = cap_story()
        assert title == n_title
        assert f'User: {n_user}' in story
        assert f'Site: {n_site}' in story
        assert 'Password: (' in story
        assert 'Notes:' in story
        assert story.endswith(n_body)

        need_keypress(KEY_CANCEL)

    # view pw as text and QR
    pick_menu_item('View Password')
    title, story = cap_story()
    assert title == n_title
    assert story == n_pw

    need_keypress(KEY_QR)
    qr_rb = cap_screen_qr().decode('utf-8')
    assert qr_rb == n_pw
    need_keypress(KEY_CANCEL)

    # change stuff
    pick_menu_item('Edit Metadata')
    mod = ' CHG%04d' % random.randint(1000, 9999)
    enter_text(mod)
    enter_text(mod)
    enter_text(mod)
    enter_text(KEY_CLEAR + n_body + mod, multiline=True)

    # approve change
    time.sleep(0.1)
    title, story = cap_story()
    assert 'SURE' in title
    assert 'Site Name' in story
    assert 'Title' in story
    need_keypress(KEY_ENTER)

    pick_menu_item('Change Password')
    enter_text(KEY_CLEAR + 'default')

    # confirm
    time.sleep(0.1)
    title, story = cap_story()
    assert 'Confirm' in title
    assert 'New Password' in story
    assert 'default' in story
    assert 'Old Password' in story
    assert n_pw in story
    need_keypress(KEY_ENTER)

    # test changes at low-level
    time.sleep(0.1)
    notes = settings_get('notes')
    note = [n for n in notes if n['title'] == n_title+mod][0]
    assert note['site'] == n_site + mod
    assert note['user'] == n_user + mod
    assert note['misc'] == n_body + mod
    assert note['password'] == 'default'

    # wipe & redraw
    settings_set('notes', notes[0:-3])
    goto_notes()


def test_top_export(goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress, settings_get, settings_set, readback_bbqr, need_some_notes):

    notes = need_some_notes()

    notes = settings_get('notes', [])
    assert len(notes) >= 1

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

def test_top_import(goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress, settings_get, settings_set, scan_a_qr, need_some_notes):

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
    
    time.sleep(.5)      # decompression time in some cases
    m = cap_menu()
    assert notes[0]['title'] in m[0]
    assert settings_get('notes', 'MISSING') == notes
    goto_notes()

@pytest.mark.parametrize('key', 'AB' + KEY_F1 + KEY_F2 + KEY_F3 + KEY_F4 + KEY_F5 + KEY_QR)
def test_build_password(key, goto_notes, pick_menu_item, enter_text, cap_menu, cap_story, need_keypress, cap_screen_qr, readback_bbqr, nfc_read_text, cap_text_box, settings_get, settings_set, scan_a_qr):
    # Test password entry, including all the auto-generation capabilities
    case = '0x%02x' % ord(key)

    n_title = f'Title {case}'
    n_user = f'Username {case}'
    n_pw = None
    n_site = f'Site {case}'
    n_body = f'More Notes {case}'

    # create
    goto_notes('New Password')
    enter_text(n_title)
    enter_text(n_user)
    if key == 'A':
        n_pw = 'A' * 99
        enter_text(n_pw)
    elif key == 'B':
        n_pw = 'B' * 3
        enter_text(n_pw)
    elif key == KEY_QR:
        n_pw = 'QR rocks'
        need_keypress(KEY_QR)
        time.sleep(1.1)
        scan_a_qr(n_pw)
        time.sleep(1.1)
        need_keypress(KEY_ENTER)
    else:
        # function keys: let it auto gen
        need_keypress(key)
        time.sleep(0.1)
        if key == KEY_F5:       # bip-85
            enter_text('34')
            time.sleep(0.1)
        n_pw = ''.join(cap_text_box()).strip()
        assert n_pw and len(n_pw) > 10
        need_keypress(KEY_ENTER)

    enter_text(n_site)
    enter_text(n_body, multiline=True)

    # view
    time.sleep(0.1)
    m = cap_menu()
    assert m[0] == f'"{n_title}"'
    assert n_user in m[1]
    assert n_site in m[2]
    assert 'Export' in m

    # top 3 menu items do same thing: view details
    for idx in range(3):
        pick_menu_item(m[idx])
        title, story = cap_story()
        assert title == n_title
        assert f'User: {n_user}' in story
        assert f'Site: {n_site}' in story
        assert 'Password: (' in story
        assert 'Notes:' in story
        assert story.endswith(n_body)

        need_keypress(KEY_CANCEL)

    # view pw as text and QR
    pick_menu_item('View Password')
    title, story = cap_story()
    assert title == n_title
    assert story == n_pw

    need_keypress(KEY_QR)
    qr_rb = cap_screen_qr().decode('utf-8')
    assert qr_rb == n_pw
    need_keypress(KEY_CANCEL)

    # change stuff
    pick_menu_item('Edit Metadata')
    mod = ' CHG%04d' % random.randint(1000, 9999)
    enter_text(mod)
    enter_text(mod)
    enter_text(mod)
    enter_text(KEY_CLEAR + n_body + mod, multiline=True)

    # approve change
    time.sleep(0.1)
    title, story = cap_story()
    assert 'SURE' in title
    assert 'Site Name' in story
    assert 'Title' in story
    need_keypress(KEY_ENTER)

    pick_menu_item('Change Password')
    enter_text(KEY_CLEAR + 'default')

    # confirm
    time.sleep(0.1)
    title, story = cap_story()
    assert 'Confirm' in title
    assert 'New Password' in story
    assert 'default' in story
    assert 'Old Password' in story
    assert n_pw in story
    need_keypress(KEY_ENTER)

    # test changes at low-level
    time.sleep(0.1)
    notes = settings_get('notes')
    note = [n for n in notes if n['title'] == n_title+mod][0]
    assert note['site'] == n_site + mod
    assert note['user'] == n_user + mod
    assert note['misc'] == n_body + mod
    assert note['password'] == 'default'

    # wipe & redraw
    settings_set('notes', notes[0:-3])
    goto_notes()


def test_top_export(goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress, settings_get, settings_set, readback_bbqr, need_some_notes):

    notes = need_some_notes()

    notes = settings_get('notes', [])
    assert len(notes) >= 1

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

def test_top_import(goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress, settings_get, settings_set, scan_a_qr, need_some_notes):

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
    
    time.sleep(.5)      # decompression time in some cases
    m = cap_menu()
    assert notes[0]['title'] in m[0]
    assert settings_get('notes', 'MISSING') == notes
    goto_notes()


@pytest.mark.parametrize('qr,title', [
    ('otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30', 'ACME Co:john.doe@email.com'),
    ('otpauth://totp/pi%40raspberrypi?secret=7KSQL2JTUDIS5EF65KLMRQIIGY&issuer=raspberrypi',
        'pi@raspberrypi'),
    ('otpauth-migration://offline?data=CiAKCghCEIa1rWta1rUSDEV4YW1wbGUgRGF0YSABKAEwAhAB',
        'Google Auth'),
])  
def test_top_qr(qr, title, goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress, settings_get, settings_set, scan_a_qr):
    # import some fun QR codes (will be notes) from top-level, undocumented

    goto_notes()
    need_keypress(KEY_QR)

    scan_a_qr(qr)
    time.sleep(.5)

    # lazy readback
    notes = settings_get('notes', [])

    assert notes[-1]['title'] == title
    assert notes[-1]['misc'] == qr

    #pick_menu_item('Delete')
    #need_keypress(KEY_ENTER)


def test_top_disable(goto_notes, pick_menu_item, cap_menu, cap_story, need_keypress, settings_get, settings_set):
    # Keep last - disables, deletes notes
    settings_set('notes', [])
    goto_notes()
    m = cap_menu()
    assert 'Disable Feature' in m
    pick_menu_item('Disable Feature')
    m = cap_menu()

    assert 'Ready To Sign' in m
    assert settings_get('notes', 'MISSING') == 'MISSING'

# EOF
