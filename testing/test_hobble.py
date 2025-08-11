# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Verify hobble works: a restricted access mode, without export/view of seed and more.
#
# - spending policy menu and txn checks should not be in this file, instead expand
#    test_ccc.py or create test_sssp.py
#
# Additional tests, elsewhere:
#
# - test_teleport.py::test_teleport_ms_sign
#    - verifies: MS psbt KT should still work in hobbled mode
#
# - test_teleport.py::test_hobble_limited
#    - verifies: scan a KT and have it rejected if not PSBT type: so R and E types
#
# - login_settings_tests.py for login/bypass UX
#
#
import pytest, time, os, pdb
from bip32 import BIP32Node
from constants import simulator_fixed_words, simulator_fixed_xprv
from test_ephemeral import SEEDVAULT_TEST_DATA, WORDLISTS
from test_ephemeral import confirm_tmp_seed, verify_ephemeral_secret_ui 
from test_ux import word_menu_entry
from charcodes import KEY_QR

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

    if en_okeys:
        adv_expect.add('Temporary Seed')

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
        settings_set("seeds", [(xfp, '80'+enc, f"Menu Label", "meta-source")])

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
        assert 'Origin:\nmeta-source' in story
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

@pytest.mark.parametrize('mode', [ 'words', 'qr', 'xprv', 'tapsigner', 'coldcard', 'b39pass'])
def test_h_tempseeds(mode, set_hobble, pick_menu_item, cap_menu, settings_set, is_q1,
                     press_select, cap_story, word_menu_entry, confirm_tmp_seed, enter_complex,
                     verify_ephemeral_secret_ui, scan_a_qr, tapsigner_encrypted_backup,
                     need_keypress, enter_hex, open_microsd, microsd_path, go_to_passphrase):
    '''
    - can import and use a key for signing
    - NOT offered chance to save into seedvault
    '''
    if not is_q1 and mode == 'qr': return

    settings_set('seedvault', True)
    settings_set('seeds', [])

    set_hobble(True, {'okeys'})

    if mode != "b39pass":
        pick_menu_item("Advanced/Tools")
        pick_menu_item('Temporary Seed')

        m = cap_menu()
        assert 'Generate Words' not in m
        assert all(i.startswith("Import ") or i.endswith(' Backup') for i in m), m

    words, expect_xfp = WORDLISTS[12]

    if mode == 'words':
        # just quick tests here, not in-depth
        # - from test_ephemeral_seed_import_words()
        pick_menu_item("Import Words")
        pick_menu_item(f"12 Words")
        time.sleep(0.1)
        word_menu_entry(words.split())

    elif mode == 'qr':
        pick_menu_item("Import from QR Scan")
        val = ' '.join(words.split()).upper()
        scan_a_qr(val)
        time.sleep(0.2)

    elif mode == 'tapsigner':
        # like test_ephemeral_seed_import_tapsigner()
        fname, backup_key_hex, node = tapsigner_encrypted_backup('sd', testnet=True)
        expect_xfp = node.fingerprint().hex().upper()
        pick_menu_item("Tapsigner Backup")
        time.sleep(0.1)
        need_keypress('1')
        time.sleep(0.1)
        pick_menu_item(fname)

        time.sleep(0.1)
        _, story = cap_story()
        assert "your TAPSIGNER" in story

        press_select()  # yes I have backup key
        enter_hex(backup_key_hex)

    elif mode == 'coldcard':
        # like test_temporary_from_backup()
        # - but skip making new bk file
        fn = 'data/tip-index-famous-embark-tobacco-rice-attitude-interest-mask-random-amazing-initial.7z'
        pw = fn[5:-3].split('-')

        contents = open(fn, 'rb').read()
        with open_microsd('example.7z', 'wb') as fd:
            fd.write(contents)

        pick_menu_item("Coldcard Backup")
        time.sleep(0.1)
        need_keypress('1')
        time.sleep(0.1)
        pick_menu_item('example.7z')
        
        word_menu_entry(pw, has_checksum=False)

        title, story = cap_story()
        assert title == 'FAILED'
        assert 'successfully tested recovery' in story

        press_select()

        return

    elif mode == 'xprv':
        fname = "ek.txt"
        node = BIP32Node.from_master_secret(os.urandom(32), netcode="XTN")
        expect_xfp = node.fingerprint().hex().upper()
        ek = node.hwif(as_private=True)
        with open(microsd_path(fname), "w") as f:
            f.write(ek)

        pick_menu_item("Import XPRV")
        time.sleep(0.1)
        _, story = cap_story()
        if "Press (1) to import extended private key" in story:
            need_keypress("1")

        time.sleep(0.1)
        pick_menu_item(fname)

    elif mode == "b39pass":
        from mnemonic import Mnemonic
        go_to_passphrase()
        passphrase = "sssp"
        seed = Mnemonic.to_seed(simulator_fixed_words, passphrase=passphrase)
        node = BIP32Node.from_master_secret(seed, netcode="XTN")
        expect_xfp = node.fingerprint().hex().upper()

        enter_complex(passphrase, apply=True)
        time.sleep(.2)
        title, story = cap_story()
        assert title[1:-1] == expect_xfp
        assert "Above is the master key fingerprint of the new wallet" in story
        press_select()
        time.sleep(.1)
        title, story = cap_story()
        assert "store temporary seed into Seed Vault" not in story
        time.sleep(.1)

    else:
        raise pytest.fail(mode)

    if mode != "b39pass":
        # different UX for passphrase - verified above
        confirm_tmp_seed(seedvault=False, check_sv_not_offered=True)

    # do not verify presence of Seed Vault menu item - irrelevant
    verify_ephemeral_secret_ui(expected_xfp=expect_xfp, mnemonic=None, seed_vault=None)

    pick_menu_item("Restore Master")
    press_select()


@pytest.mark.parametrize('en_okeys', [ True, False])
def test_h_usbcmds(en_okeys, set_hobble, dev):
    # test various usb commands are blocked during hobble

    from ckcc_protocol.protocol import CCProtoError

    set_hobble(True, {'okeys'} if en_okeys else {})

    block_list = [ 'back', 'enrl', 'bagi', 'hsms', 'user', 'nwur', 'rmur' ]

    if not en_okeys:
        block_list.insert(0, 'pass')

    for cmd in block_list:
        with pytest.raises(CCProtoError) as ee:
            got = dev.send_recv(cmd)
        assert 'Spending policy in effect' in str(ee)


@pytest.mark.parametrize('en_okeys', [ True, False])
def test_h_qrscan(en_okeys, set_hobble, scan_a_qr, need_keypress, press_cancel, cap_screen, only_q1, cap_story, press_select, pick_menu_item):
    # verify whitelist of QR types is correct when in hobbled mode
    # - no private key material, unless "okeys" is set
    # - no teleport starting, except multisig co-signing
    #
    set_hobble(True, {'okeys'} if en_okeys else {})

    words, _ = WORDLISTS[12]
    keys = [ 
        ' '.join(w[0:4] for w in words.split()),
        simulator_fixed_xprv]

    for ss in keys:
        need_keypress(KEY_QR)
        scan_a_qr(ss)
        time.sleep(0.5)

        title, story = cap_story()
        if en_okeys:
            assert 'New temporary master key is in effect' in story
            press_select()

            pick_menu_item("Restore Master")
            press_select()
        else:
            assert 'Blocked when Spending Policy is in force.' in story
            press_select()

    for dt in 'RSE':
        need_keypress(KEY_QR)
        tt = f'B$H{dt}0100'+('A'*80)
        scan_a_qr(tt)
        time.sleep(0.5)

        if dt == 'E':
            title, story = cap_story()
            assert 'Incoming PSBT requires multisig wallet' in story
            press_cancel()
        else:
            scr = cap_screen()      # stays in scanning mode
            assert 'KT Blocked' in scr
        
# EOF
