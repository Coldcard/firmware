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
    assert 'Export All' in m
    
@pytest.mark.parametrize('size', [ 4000, 30000])
@pytest.mark.parametrize('encoding', '2Z' )
def test_huge_notes(size, encoding, goto_notes, pick_menu_item, enter_text, cap_menu, cap_story, need_keypress, cap_screen_qr, readback_bbqr, scan_a_qr, settings_set, settings_get):

    # Since we don't limit note sizes, by request of NVK ... test them
    
    n_body = ''.join(chr((i%95) + 32) for i in prandom(size))
    n_title = f'Size {size}'

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

    notes = settings_get('notes')
    assert len(notes) == 1
    assert notes[0]['title'] == n_title
    assert notes[0]['misc'] == n_body

    settings_set('notes', [])
    goto_notes()        # redraw

# EOF
