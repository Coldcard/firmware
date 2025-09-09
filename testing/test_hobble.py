# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Verify hobble works: a restricted access mode, without export/view of seed and more.
#
# - spending policy menu and txn checks should not be in this file, instead expand
#    test_ccc.py or create test_sssp.py
#
import pytest, time, re, pdb
from helpers import prandom, xfp2str, str2xfp, str_to_path
from bbqr import join_qrs
from charcodes import KEY_QR, KEY_NFC
from base64 import b32encode
from constants import *
from test_ephemeral import SEEDVAULT_TEST_DATA
from test_notes import need_some_notes

'''TODO

When hobbled...

- temp seeds are read-only: no create, no rename, etc.
- seed vault can be accessed tho

- login sequence
    1) system has lgto value: should get bypass pin, main pin, delay, then main pin again
    2) using a trick PIN with delay, after bypass pin should delay
    3) bypass pin + duress wallet PIN => should work => but not a useful trick combo
   
- word entry during login
    - q1 vs mk4 style
    - wrong values given, etc

- verify whitelist of QR types is correct when in hobbled mode
    - no private key material, no teleport starting, unless "okeys" is set

- TODO: update menu tree w/ hobble mode view

- verify that PSBT can be "signed" when SP enabled and delta-mode pin is active. seed not wiped.

'''

# NOTE: these are unit tests of the effects of hobble mode, not how it is enabled/disabled:
#
# - test_teleport.py::test_teleport_ms_sign
#    - verifies: MS psbt KT should still work in hobbled mode
# - test_teleport.py::test_hobble_limited
#    - verifies: scan a KT and have it rejected if not PSBT type: so R and E types

@pytest.fixture
def set_hobble(sim_exec, settings_set, settings_remove, goto_home):
    def doit(mode, enabled={}):     # okeys, words, notes
        assert mode in { True, False, 2 }

        if mode:
            v = dict(en=True, pol={})
            for w in enabled:
                v[w] = True 
            settings_set('sssp', v)
            print(f'sssp = {v!r}')
        else:
            settings_remove('sssp')
        
        sim_exec(f'''
from pincodes import pa; from actions import goto_top_menu
pa.hobbled_mode = {mode!r}
goto_top_menu()
''')
        goto_home()     # required, not sure why

    yield doit

    doit(False)

@pytest.mark.parametrize('en_okeys', [ True, False] )
@pytest.mark.parametrize('en_notes', [ True, False] )
@pytest.mark.parametrize('en_nfc', [ True, False] )
@pytest.mark.parametrize('en_multisig', [ True, False] )
def test_menu_contents(set_hobble, pick_menu_item, cap_menu, en_okeys, en_notes, settings_set, need_some_notes, is_q1, is_mark4, en_nfc, sim_exec, en_multisig, vdisk_disabled):

    # just enough to pass/fail the menu predicates!
    settings_set('seedvault', True)

    #settings_set('nfc', en_nfc)
    sim_exec(f'import glob; glob.NFC = {(True if en_nfc else None)!r};') 

    settings_set('multisig', en_multisig)

    if is_q1:
        need_some_notes()

    # main menu basics
    expect = {'Ready To Sign',  'Address Explorer', 'Advanced/Tools' }

    if is_q1:
        expect.add('Scan Any QR Code')
    else:
        expect.add('Secure Logout')

    en = set()
    if en_okeys:
        en.add('okeys')
        expect.add('Seed Vault')
        expect.add('Passphrase')

    if en_notes:
        en.add('notes')
        if is_q1:
            expect.add('Secure Notes & Passwords')

    # enables hobble and goes to top menu
    set_hobble(True, en)

    m = cap_menu()
    assert set(m) == expect, 'Main menu wrong'

    # advanced menu
    pick_menu_item("Advanced/Tools")

    adv_expect = {  'File Management',
                    'Export Wallet',
                    'View Identity',
                    'Paper Wallets',
                    'Destroy Seed' }

    if is_q1 and en_multisig:
        adv_expect.add('Teleport Multisig PSBT')

    if en_nfc:
        adv_expect.add('NFC Tools')

    m = cap_menu()
    assert set(m) == adv_expect, "Adv menu wrong"

    # file management
    pick_menu_item("File Management")

    fm_expect = {   'Sign Text File',
                    'Batch Sign PSBT',
                    'List Files',
                    'Export Wallet',
                    'Verify Sig File',
                    'Format SD Card' }

    if not vdisk_disabled:
        fm_expect.add('Format RAM Disk')
    
    if en_nfc:
        fm_expect.add('NFC File Share')
    if is_q1:
        fm_expect.add('BBQr File Share')
        fm_expect.add('QR File Share')

    m = cap_menu()
    assert set(m) == fm_expect, "File Mgmt menu wrong"


def test_h_notes(only_q1, set_hobble, pick_menu_item, cap_menu, settings_set, need_some_notes, is_q1, sim_exec, settings_remove):
    '''
        * load a secure note/pw; check readonly once hobbled
            * cannot export
            * cannot edit
            * can view / use for kbd emulation
        * check notes not offered if none defined
        * check readonly features on notes when note pre-defined before entering hobbled mode
    '''
    need_some_notes()
    set_hobble(True, {'notes'})

    pick_menu_item('Secure Notes & Passwords')

    m = cap_menu()
    assert m == [ '1: Title Here' ]
    pick_menu_item(m[0])

    m = cap_menu()
    assert m == [ '"Title Here"', 'View Note', 'Sign Note Text' ]

    # clear notes, should not be offered
    settings_remove('notes')
    settings_remove('secnap')
    set_hobble(True, {'notes'})

    m = cap_menu()
    assert 'Secure Notes & Passwords' not in m

def test_kt_limits(only_q1, set_hobble, pick_menu_item, cap_menu, settings_set, need_some_notes, is_q1, sim_exec, settings_remove):
    ''' 
        - key teleport
            * check KT only offered if MS wallet setup
    '''
    settings_remove('multisig')
    set_hobble(True)
    pick_menu_item("Advanced/Tools")

    assert 'Teleport Multisig PSBT' not in cap_menu()
    # converse already tested in test_menu_contents

@pytest.mark.parametrize('sv_empty', [ True, False] )
def test_h_seedvault(sv_empty, set_hobble, pick_menu_item, cap_menu, settings_set, is_q1, sim_exec, settings_remove, restore_main_seed, settings_get, press_cancel, press_select, cap_story):
    '''
        - seed vault can be accessed, when enabled
        - temp seeds are read-only: no create, no rename, etc.
        - SV menu item is offered iff SV enabled; can be empty or not.
    '''

    settings_set('seedvault', True)
    if sv_empty:
        settings_set('seeds', [])
    else:
        settings_set('seeds', [])
        xfp, enc = SEEDVAULT_TEST_DATA[0][0:2]
        settings_set("seeds", [(xfp, '80'+enc, f"Menu Label", "meta")])

    set_hobble(True, {'okeys'})

    assert cap_menu()[0] == 'Ready To Sign', 'restart simulator now'
    pick_menu_item('Seed Vault')

    m = cap_menu()
    if sv_empty:
        assert m == ['(none saved yet)']
    else:
        assert m == [' 1: Menu Label']

        pick_menu_item(m[0])
        m = cap_menu()
        assert m == ['Menu Label', 'Use This Seed']

        pick_menu_item(m[0])
        title, story = cap_story()
        assert 'Origin:\nmeta' in story
        press_cancel()
            
        pick_menu_item('Use This Seed')
        title, story = cap_story()
        assert 'temporary master key is in effect' in story
        press_select()

        # arrive back in main menu, w/ tmp seed in effect
        # - but we are still hobbled.
        # - XFP shown
        # - Restore master should be offered.
        m = cap_menu()
        assert m[0] == f'[{xfp}]'
        assert 'Seed Vault' not in m        # because we are in a tmp key, they need to go master
        assert m[-1] == 'Restore Master'

        pick_menu_item("Advanced/Tools")
        m = cap_menu()
        assert 'Destroy Seed' in m          # indicates hobble mode active
        press_cancel()

        pick_menu_item("Restore Master")
        title, story = cap_story()
        assert 'main wallet' in story
        press_select()
        

    # clear keys from sv, should not be offered in menu, even if okeys set.
    settings_remove('seedvault')
    set_hobble(True, {'okey'})

    m = cap_menu()
    assert 'Seed Vault' not in m

# BIP-39 passphrases


# EOF
