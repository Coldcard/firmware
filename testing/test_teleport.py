# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Key Teleport (a Q-only feature)
#
# - you'll need v1.0.1 of bbqr library for this to work
#
import pytest, time, re, pdb, os, json, base64
from helpers import prandom, xfp2str, str2xfp, str_to_path
from bbqr import join_qrs
from charcodes import KEY_QR, KEY_NFC
from base64 import b32encode
from constants import *
from test_ephemeral import SEEDVAULT_TEST_DATA
from test_backup import make_big_notes

# All tests in this file are exclusively meant for Q
#
@pytest.fixture(autouse=True)
def THIS_FILE_requires_q1(is_q1, is_headless):
    if not is_q1 or is_headless:
        raise pytest.skip('Q1 only (not headless)')

@pytest.fixture()
def rx_start(grab_payload, goto_home, pick_menu_item):
    def doit(**kws):
        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Key Teleport (start)')

        return grab_payload('R', **kws)[0:2]

    return doit
    
@pytest.fixture()
def main_do_over(unit_test, settings_get, settings_set):
    # reset all contents, including master secret ... except ktrx
    # - so you can test backup-restore onto blank unit
    def doit():
        kp = settings_get('ktrx')
        unit_test('devtest/clear_seed.py')
        settings_set('ktrx', kp)

    return doit

@pytest.fixture()
def grab_payload(press_select, need_keypress, press_cancel, nfc_read_url,  cap_story, nfc_block4rf, cap_screen_qr, readback_bbqr):

    # started the process; capture pw/code and QR contents, verify NFC works
    def doit(tt_code, allow_reuse=True, reset_pubkey=False):
        expect_in_title = 'Receive' if tt_code == 'R' else 'Teleport Password'

        title, story = cap_story()
    
        if 'Reuse' in title and tt_code == 'R':
            assert allow_reuse
            assert 'press (R)' in story

            if reset_pubkey:
                # make a new key anyway
                need_keypress('r')
            else:
                press_select()

            time.sleep(.1)
            title, story = cap_story()

        assert 'Teleport' in title
        assert expect_in_title in title

        assert 'QR' in story

        code, = re.findall(' (\w{8})  =  ', story)
        assert len(code) == 8

        nfc_raw = None
        if KEY_NFC in story:
            # test NFC case -- when enabled
            need_keypress(KEY_NFC)
            
            # expect NFC animation
            nfc_block4rf()

            url = nfc_read_url().replace('%24', '$')

            assert url.startswith('https://keyteleport.com/#')

            nfc_data = url.rsplit('#')[1]
            assert nfc_data.startswith(f'B$2{tt_code}0100') 

            filetype, nfc_raw = join_qrs([nfc_data])     # update your bbqr install if fails
            assert filetype == tt_code

        need_keypress(KEY_QR)

        # will be multi-frame BBQr in case of PSBT, other cases usually one frame
        filetype, qr_raw = readback_bbqr()
        # this is un-split BBQR which didn't really happen, but useful
        qr_data = f'B$2{filetype}0100' + b32encode(qr_raw).decode('ascii').rstrip('=')

        assert filetype == tt_code

        if nfc_raw: assert nfc_raw == qr_raw

        press_cancel()
        press_cancel()

        return code, qr_data, qr_raw
        
    return doit

@pytest.fixture()
def rx_complete(press_select, need_keypress, press_cancel, cap_story, scan_a_qr, enter_complex, cap_screen, goto_home, split_scan_bbqr):
    # finish the teleport by doing QR and getting data
    def doit(data, pw, expect_fail=False, expect_xfp=None):
        goto_home()
        need_keypress(KEY_QR)
        time.sleep(.250)        # required

        if isinstance(data, tuple):
            bbrq_type, raw = data
            split_scan_bbqr(raw, bbrq_type, max_version=26)
        else:
            assert len(data) <  2000    # USB protocol limit
            scan_a_qr(data)

        if expect_fail:
            time.sleep(.200)
            return
        for retries in range(20):
            scr = cap_screen()
            if 'Teleport Password' in scr: break
            time.sleep(.200)

        if expect_xfp:
            assert xfp2str(expect_xfp) in scr

        enter_complex(pw)
        time.sleep(.150)        # required


    return doit

@pytest.fixture()
def tx_start(press_select, need_keypress, press_cancel, goto_home, pick_menu_item, cap_story, scan_a_qr, enter_complex, cap_screen):

    # start the Tx process, capturing password and leaving you are picker menu
    def doit(rx_qr, rx_code, expect_fail=None, expect_wrong_code=False):
        goto_home()
        need_keypress(KEY_QR)
        time.sleep(.250)        # required
        scan_a_qr(rx_qr)

        time.sleep(.250)        # required
        scr = cap_screen()
        if expect_fail:
            assert expect_fail in scr
            return

        assert 'Teleport Password (number)' in scr

        enter_complex(rx_code)
        time.sleep(.150)        # required


        title, story = cap_story()
        if expect_wrong_code:
            # not a sure thing
            if 'Incorrect Teleport Pass' in story:
                return True

        assert title == 'Key Teleport: Send'

        assert 'Choose what to share' in story
        assert 'WARNING' in story
        press_select()

    return doit

def test_rx_reuse(rx_start):
    # check rx pubkey re-use logic
    code, enc_pubkey = rx_start(allow_reuse=True, reset_pubkey=True)
    assert code.isdigit()
    code2, enc_pubkey2 = rx_start(allow_reuse=True, reset_pubkey=False)
    assert code2 == code
    assert enc_pubkey2 == enc_pubkey

    code3, pk3 = rx_start(allow_reuse=True, reset_pubkey=True)
    assert code3 != code

def test_tx_quick_note(rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select):
    # Send a quick-note
    code, rx_pubkey = rx_start()
    pw = tx_start(rx_pubkey, code)

    m = cap_menu()
    assert 'Master Seed Words' in m
    assert 'Quick Text Message' in m
    # other contents require other features to be enabled

    msg = b32encode(prandom(10)).decode('ascii')

    pick_menu_item('Quick Text Message')

    enter_complex(msg)

    time.sleep(.150)        # required
    pw, data, _ = grab_payload('S')
    assert len(pw) == 8
    
    # now, send that back
    rx_complete(data, pw)

    # should arrive in notes menu
    m = cap_menu()
    assert m[-1] == 'Import'
    mi = [i for i in m if i.endswith(': Quick Note')]
    assert mi
    pick_menu_item(mi[-1])      # most recent test

    # view note
    m = cap_menu()
    assert m[0] == '"Quick Note"'
    pick_menu_item(m[0])

    _, body = cap_story()
    assert body == msg

    # cleanup
    press_cancel()
    pick_menu_item('Delete')
    press_select()
    

@pytest.mark.parametrize('testcase', [ 'weak', 'strong'])
def test_tx_master_send(testcase, rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select, main_do_over):
    # Send master secret, but doesn't really work since same as what we have
    code, rx_pubkey = rx_start()
    pw = tx_start(rx_pubkey, code)

    # other contents require other features to be enabled
    pick_menu_item('Master Seed Words')

    title, body = cap_story()

    assert 'Are you SURE' in title
    assert 'MASTER secret' in body
    assert '24 words' in body

    press_select()

    time.sleep(.150)        # required?
    pw, data, _ = grab_payload('S')

    if testcase == 'strong':
        # virginized
        main_do_over()
    
    # now, send that back
    rx_complete(data, pw)

    title, body = cap_story()

    if testcase == 'weak':

        assert title == 'FAILED'
        assert 'Cannot use master seed as temp' in body
        assert 'successfully tested' in body

    elif testcase == 'strong':
        # real product would reboot; simulator just quietly goes back to top menu?
        assert title == ''
        m = cap_menu()
        assert m[0] == 'Ready To Sign'

    press_cancel()

@pytest.mark.parametrize('qty', [1, 3])
def test_tx_notes(qty, rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select, need_some_passwords, need_some_notes, settings_set, settings_get):
    # Send notes.
    settings_set('notes', [])
    need_some_notes()
    notes = need_some_passwords()

    assert len(notes) >= qty

    code, rx_pubkey = rx_start()
    pw = tx_start(rx_pubkey, code)

    # other contents require other features to be enabled
    if qty == 1:
        pick_menu_item('Single Note / Password')
        pick_menu_item('1: ' + notes[0]["title"])
    else:
        pick_menu_item('Export All Notes & Passwords')

    time.sleep(.150)        # required?
    pw, data, _ = grab_payload('S')
    
    # now, send that back
    rx_complete(data, pw)

    # arrive in settings menu, on last item (last imported)
    m = cap_menu()
    assert m[-1] == 'Import'

    after = settings_get('notes', None)

    assert notes[0:qty] == after[-qty:]

    settings_set('notes', [])
    press_cancel()

        
@pytest.mark.parametrize('data', SEEDVAULT_TEST_DATA[0:2])
def test_tx_seedvault(data, rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select, settings_set, settings_get, goto_home, need_keypress):
    # Send seeds from vault

    xfp, entropy, mnemonic = data

    # build stashed encoded secrets
    entropy_bytes = bytes.fromhex(entropy)
    if mnemonic:
        vlen = len(entropy_bytes)
        assert vlen in [16, 24, 32]
        marker = 0x80 | ((vlen // 8) - 2)
        stored_secret = bytes([marker]) + entropy_bytes
    else:
        stored_secret = entropy_bytes

    pkg = [xfp, stored_secret.hex(), f"[{xfp}]", "from testing"]

    settings_set("seedvault", True)
    settings_set("seeds", [pkg])

    # get ready to send
    code, rx_pubkey = rx_start(reset_pubkey=True)
    pw = tx_start(rx_pubkey, code)

    pick_menu_item('From Seed Vault')
    mi, = (i for i in cap_menu() if i.endswith(f"[{xfp}]"))
    pick_menu_item(mi)

    time.sleep(.150)        # required?
    pw, data, _ = grab_payload('S')

    settings_set("seeds", [])

    rx_complete(data, pw)

    if settings_get("seedvault", False):
        time.sleep(.1)
        title, body = cap_story()
        assert 'Press (1) to store temp' in body
        assert 'to continue without saving' in body
        need_keypress('1')

    time.sleep(.1)
    title, body = cap_story()
    assert xfp in body
    assert 'Saved to Seed Vault' in body

    assert settings_get('seeds') == [pkg]

    goto_home()
    pick_menu_item('Restore Master')
    press_select()

    time.sleep(.1)
    assert settings_get('xfp', -1) == simulator_fixed_xfp

def test_rx_truncated(rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, rx_complete, cap_story, press_cancel, press_select):
    # Truncate the RX Code
    code, rx_pubkey = rx_start()
    pw = tx_start(rx_pubkey[:-3], code, expect_fail='Truncated KT RX')


def test_tx_wrong_pub(rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select):
    # simulate wrong numeric code only -- sender doesn't know
    right_code, rx_pubkey = rx_start()

    for attempt in range(20):
        code = '%08d' % attempt
        failed = tx_start(rx_pubkey, code, expect_wrong_code=True)

        if failed:
            # 50% odds (apx, maybe?) of wrong code being detected.
            print(f'{code} => wasnt accepted')
            continue
        break
    else:
        raise pytest.fail('huh')

    # other contents require other features to be enabled
    pick_menu_item('Master Seed Words')
    time.sleep(.150)        # required?
    press_select()

    time.sleep(.150)        # required?
    pw, data, _ = grab_payload('S')
    
    # now, send that back
    rx_complete(data, pw, expect_fail=True)

    time.sleep(.1)
    title, body = cap_story()

    assert title == 'Teleport Fail'
    assert 'password was wrong' in body
    assert 'start again' in body

    press_cancel()

@pytest.mark.unfinalized
@pytest.mark.parametrize('num_ins', [ 15 ])
@pytest.mark.parametrize('M', [2, 4])
@pytest.mark.parametrize('segwit', [True])
@pytest.mark.parametrize('incl_xpubs', [ False ])
def test_teleport_ms_sign(M, use_regtest, make_myself_wallet, segwit, num_ins, dev, clear_ms,
                          fake_ms_txn, try_sign, incl_xpubs, bitcoind, cap_story, need_keypress,
                          cap_menu, pick_menu_item, grab_payload, rx_complete, press_select,
                          ndef_parse_txn_psbt, press_nfc, nfc_read, settings_get, settings_set,
                          txid_from_export_prompt):

    # IMPORTANT: won't work if you start simulator with --ms flag. Use no args
    all_out_styles = [af for af in unmap_addr_fmt.keys() if af != "p2tr"]
    num_outs = len(all_out_styles)

    clear_ms()
    use_regtest()

    # create a wallet, with 3 bip39 pw's
    keys, select_wallet = make_myself_wallet(M, do_import=(not incl_xpubs))
    N = len(keys)
    assert M<=N

    psbt = fake_ms_txn(num_ins, num_outs, M, keys, segwit_in=segwit, incl_xpubs=incl_xpubs, 
                        outstyles=all_out_styles, change_outputs=list(range(1,num_outs)))

    open(f'debug/myself-before.psbt', 'wb').write(psbt)

    cur_wallet = 0
    my_xfp = select_wallet(cur_wallet)

    _, updated = try_sign(psbt, accept_ms_import=incl_xpubs, exit_export_loop=False)
    open(f'debug/myself-after-1.psbt', 'wb').write(updated)
    assert updated != psbt

    title, body = cap_story()
    assert title == "PSBT Signed"
    assert '(T) to use Key Teleport to send PSBT to other co-signers' in body

    num_sigs_needed = M - 1  # we have already signed with first at this point

    while 1:
        # expect: a menu of other signers to pick from
        need_keypress('t')
        time.sleep(.1)

        m = cap_menu()
        assert len(m) == N
        assert 'YOU' in [ln for ln in m if xfp2str(my_xfp) in ln][0]

        unsigned = [ln[1:9] for ln in m if (xfp2str(my_xfp) not in ln) and ('DONE' not in ln)]
        assert unsigned

        # find another signer
        for idx, (xfp, *_) in enumerate(keys):
            if xfp2str(xfp) in unsigned:
                break
        else:
            assert 0, 'missing unsigned'

        # check XFP changes
        next_xfp = keys[idx][0]
        assert next_xfp != my_xfp
        last_xfp = my_xfp

        # pick other xfp to send to
        nm, = [mi for mi in m if xfp2str(next_xfp) in mi]
        pick_menu_item(nm)

        # grab the payload and pw
        pw, data, qr_raw = grab_payload('E')
        assert len(pw) == 8

        nn = xfp2str(next_xfp)
        open(f'debug/next_qr_{nn}.txt', 'wt').write(f'{nn}\n\n{pw}\n\n{data}')

        time.sleep(.1)
        title, story = cap_story()
        assert title == 'Sent by Teleport'
        s, aux = ("", "is") if num_sigs_needed == 1 else ("s", "are")
        msg = "%d more signature%s %s still required." % (num_sigs_needed, s, aux)
        assert msg in story

        # switch personalities, and try to read that QR
        new_xfp = select_wallet(idx)
        assert new_xfp == next_xfp
        my_xfp = next_xfp
        assert settings_get('xfp') == my_xfp

        # import and sign
        rx_complete(('E', qr_raw), pw, expect_xfp=last_xfp)

        title, body = cap_story()
        assert title == 'OK TO SEND?'

        press_select()
        time.sleep(.25)

        title, body = cap_story()
        if 'Finalized TX' in body:
            break

        assert '(T) to use Key Teleport to send PSBT to other co-signers' in body
        num_sigs_needed -= 1

    txid = txid_from_export_prompt()
    press_select()  # exit QR
    
    # share signed txn via low-level NFC
    press_nfc()
    time.sleep(.1)
    contents = nfc_read()

    got_psbt, got_txn, _ = ndef_parse_txn_psbt(contents, txid, expect_finalized=True)

    assert not got_psbt
    assert got_txn


def test_teleport_big_ms(make_myself_wallet, clear_ms, fake_ms_txn, try_sign, cap_story,
                         need_keypress, cap_menu, pick_menu_item, grab_payload, rx_complete,
                         press_select, ndef_parse_txn_psbt, set_master_key, goto_home, press_nfc,
                         nfc_read, settings_get, settings_set, open_microsd, import_ms_wallet,
                         press_cancel):

    # define lots of wallets and do teleport from SD disk

    clear_ms()
    M, N = 2, 15
    for i in range(5):
        keys = import_ms_wallet(M, N, name=f'ms{i}-test', unique=(i*73), accept=True,
                                    descriptor=False, bip67=True)
    
    # just use last wallet
    psbt = fake_ms_txn(1, 1, M, keys)

    fname = 'ms-example.psbt'
    open_microsd(fname, 'wb').write(psbt)

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('File Management')
    pick_menu_item('Teleport Multisig PSBT')

    need_keypress('1')      # top slot

    try:
        pick_menu_item(fname)
    except KeyError:
        # maybe just one file that is suitable --> str8 to xfp picking
        pass

    # on Co-signer list menu
    m = cap_menu()
    assert len(m) == N

    myself, = [i for i in m if 'YOU' in i]
    pick_menu_item(myself)

    title, body = cap_story()
    assert title == 'OK TO SEND?'
    press_select()

    time.sleep(.25)

    # have 1 sigs now, need one more via teleport
    title, body = cap_story()
    assert '(T) to use Key Teleport to send PSBT to other co-signers' in body
    need_keypress('t')

    # pick another one randomly
    m = cap_menu()
    assert len(m) == N

    target = m[-1] if 'YOU' not in m[0] else m[-2]
    pick_menu_item(target)
    target_xfp = str2xfp(target[1:9])

    # capture QR+pw to go there
    pw, data, qr_raw = grab_payload('E')

    tmp_ms = settings_get('multisig')

    # switch to that key, receive it
    node, = [n for x,n,_ in keys if x == target_xfp]
    set_master_key(node.hwif(as_private=True))

    # copy over the one MS wallet this xfp was involved in
    settings_set('multisig', [tmp_ms[-1]])

    # import and sign
    rx_complete(('E', qr_raw), pw, expect_xfp=simulator_fixed_xfp)

    title, body = cap_story()
    assert title == 'OK TO SEND?'

    press_select()
    time.sleep(.25)

    title, body = cap_story()
    assert 'Finalized TX' in body
    press_cancel()


@pytest.mark.manual
def test_teleport_real_ms(dev, fake_ms_txn):
    #
    # Do a 2-of-2 w/ USB-attached REAL Q and simulator
    # - build ms wallet beforehand, both devices (QR); default air-gap settings
    # - this makes fake txn, sents to (real) device via USB
    # - do your signature, press (T) to teleport to next
    # - observe BBQr, but press NFC and capture URL text via keyteleport.com
    # - get that BBQr string into clipboard, and paste into simulator
    # - observe working signature on sim side
    #
    # py.test test_teleport.py --dev --manual -k test_teleport_real_ms
    #
    from bip32 import BIP32Node
    from struct import unpack
    from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError

    M = N = 2

    #p2wsh
    deriv = "m/48h/1h/0h/2h"

    # simulator key
    n = BIP32Node.from_hwif(simulator_fixed_xprv).subkey_for_path(deriv)
    keys = [ (simulator_fixed_xfp, None, n) ]

    # add device
    xfp = dev.master_fingerprint
    xpk = dev.send_recv(CCProtocolPacker.get_xpub(deriv))
    node = BIP32Node.from_wallet_key(xpk)
    keys.append((xfp, None, node))

    def p2wsh_mapper(cosigner_idx):
        # match the default paths created by CC in airgapped MS wallet creation.
        return str_to_path(deriv)

    psbt = fake_ms_txn(3, 2, M, keys, fee=10000, outvals=None, segwit_in=False,
             outstyles=['p2pkh'], change_outputs=[], incl_xpubs=False,
             hack_change_out=False, input_amount=1E8, path_mapper=p2wsh_mapper)

    open('debug/teleport_real_ms.psbt', 'wb').write(psbt)

    ll, sha = dev.upload_file(psbt)
    dev.send_recv(CCProtocolPacker.sign_transaction(ll, sha))

    print("Follow signing prompts on device, and then do teleport back "
            "to Simulator via NFC => website => clipboard")
    

@pytest.mark.parametrize('testcase', [ 'weak', 'partial', 'strong'])
def test_send_backup(testcase, rx_start, tx_start, cap_menu, enter_complex, pick_menu_item, grab_payload, rx_complete, cap_story, press_cancel, press_select, settings_get, settings_set, restore_backup_unpacked, main_do_over, set_encoded_secret, reset_seed_words, make_big_notes):
    # Send complete backup file.
    code, rx_pubkey = rx_start()
    pw = tx_start(rx_pubkey, code)

    if testcase == 'strong':
        notes = make_big_notes()

    # other contents require other features to be enabled
    pick_menu_item('Full COLDCARD Backup')

    title, body = cap_story()

    assert 'Sending complete backup' in body

    press_select()

    time.sleep(.150)        # required?
    pw, data, qr_raw = grab_payload('S')

    if testcase == 'partial':
        # be on a different master, so backup is restored into seed vault/tmp seed
        kp = settings_get('ktrx')
        set_encoded_secret(b'\x20' + prandom(32))
        settings_set('ktrx', kp)

    if testcase == 'strong':
        # wipe everything; except we need the keypair
        main_do_over()
    
    # now, send that back
    rx_complete(('S', qr_raw), pw)

    title, body = cap_story()

    if testcase == 'weak':
        assert title == 'FAILED'
        assert 'Cannot use master seed as temp' in body
        assert 'successfully tested' in body
        press_cancel()

    elif testcase == 'partial':
        # should be in a tmp seed now
        assert title == '[0F056943]'
        assert 'temporary master key is in effect' in body

        reset_seed_words()

    elif testcase == 'strong':
        restore_backup_unpacked()
        assert settings_get('notes') == notes
        settings_set('notes', [])


@pytest.mark.bitcoind
@pytest.mark.parametrize("same_acct", [True, False])
@pytest.mark.parametrize("recovery", [True, False])
@pytest.mark.parametrize("leaf2_mine", [True, False])
@pytest.mark.parametrize("internal_type", ["unspend(", "xpub"])
@pytest.mark.parametrize("minisc", [
    "or_d(pk(@A),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:pk(@B),locktime(N)))",

    "or_d(multi_a(2,@A,@C),and_v(v:pkh(@B),locktime(N)))",

    "or_d(pk(@A),and_v(v:multi_a(2,@B,@C),locktime(N)))",
])
def test_minitapscript(leaf2_mine, recovery, minisc, clear_miniscript, goto_home,
                       pick_menu_item, cap_menu, cap_story, microsd_path, internal_type,
                       use_regtest, bitcoind, microsd_wipe, load_export, dev,
                       get_cc_key, import_miniscript, start_sign,
                       bitcoin_core_signer, same_acct, press_select, garbage_collector):
    # needs bitcoind 26.0

    sequence = 5
    locktime = 0
    # 101 blocks are mined by default
    to_replace = "older(5)"

    minisc = minisc.replace("locktime(N)", to_replace)

    core_keys = []
    signers = []
    for i in range(3):
        # core signers
        signer, core_key = bitcoin_core_signer(f"co-signer{i}")
        core_keys.append(core_key)
        signers.append(signer)

    # cc device key
    if same_acct:
        cc_key = get_cc_key("86h/1h/0h", subderiv="/<4;5>/*")
        cc_key1 = get_cc_key("86h/1h/0h", subderiv="/<6;7>/*")
    else:
        cc_key = get_cc_key("86h/1h/0h")
        cc_key1 = get_cc_key("86h/1h/1h")

    if recovery:
        # recevoery path is always B
        minisc = minisc.replace("@B", cc_key)
        minisc = minisc.replace("@A", core_keys[0])
    else:
        minisc = minisc.replace("@A", cc_key)
        minisc = minisc.replace("@B", core_keys[0])

    if "@C" in minisc:
        minisc = minisc.replace("@C", core_keys[1])

    if internal_type == "unspend(":
        ik = f"unspend({os.urandom(32).hex()})/<2;3>/*"
    else:
        assert internal_type == "xpub"
        from test_miniscript import ranged_unspendable_internal_key
        ik = ranged_unspendable_internal_key(os.urandom(32))

    if leaf2_mine:
        desc = f"tr({ik},{{{minisc},pk({cc_key1})}})"
    else:
        desc = f"tr({ik},{{pk({core_keys[2]}),{minisc}}})"

    use_regtest()
    clear_miniscript()
    name = "minisc_teleport"
    fname = f"{name}.txt"
    fpath = microsd_path(fname)
    with open(fpath, "w") as f:
        f.write(desc)

    garbage_collector.append(fpath)

    wo = bitcoind.create_wallet(wallet_name=name, disable_private_keys=True, blank=True,
                                  passphrase=None, avoid_reuse=False, descriptors=True)

    _, story = import_miniscript(fname)
    assert "Create new miniscript wallet?" in story
    # do some checks on policy --> helper function to replace keys with letters
    press_select()
    menu = cap_menu()
    assert menu[0] == name
    pick_menu_item(menu[0]) # pick imported descriptor multisig wallet
    pick_menu_item("Descriptors")
    pick_menu_item("Bitcoin Core")
    text = load_export("sd", label="Bitcoin Core miniscript", is_json=False, sig_check=False)
    text = text.replace("importdescriptors ", "").strip()
    # remove junk
    r1 = text.find("[")
    r2 = text.find("]", -1, 0)
    text = text[r1: r2]
    core_desc_object = json.loads(text)
    res = wo.importdescriptors(core_desc_object)
    for obj in res:
        assert obj["success"]
    addr = wo.getnewaddress("", "bech32m")
    addr_dest = wo.getnewaddress("", "bech32m")  # self-spend
    assert bitcoind.supply_wallet.sendtoaddress(addr, 49)
    bitcoind.supply_wallet.generatetoaddress(1, bitcoind.supply_wallet.getnewaddress())
    all_of_it = wo.getbalance()
    unspent = wo.listunspent()
    assert len(unspent) == 1
    inp = {"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}
    if recovery and sequence and not leaf2_mine:
        inp["sequence"] = sequence
    psbt_resp = wo.walletcreatefundedpsbt(
        [inp],
        [{addr_dest: all_of_it - 1}],
        locktime if (recovery and not leaf2_mine) else 0,
        {"fee_rate": 20, "change_type": "bech32m", "subtractFeeFromOutputs": [0]},
    )
    psbt = psbt_resp.get("psbt")

    # if (normal_cosign_core or recovery_cosign_core) and not leaf2_mine:
    #     psbt = signers[1].walletprocesspsbt(psbt, True, "ALL")["psbt"]

    name = f"{name}.psbt"
    start_sign(base64.b64decode(psbt))
    title, story = cap_story()
    if "OK TO SEND?" not in title:
        time.sleep(0.1)
        pick_menu_item(name)
        time.sleep(0.1)
        title, story = cap_story()
    assert title == "OK TO SEND?"
    assert "Consolidating" in story
    press_select()  # confirm signing
    time.sleep(0.5)
    title, story = cap_story()
    assert "PSBT Signed" == title
    import pdb;pdb.set_trace()
    press_select()
    fname_psbt = story.split("\n\n")[1]
    # fname_txn = story.split("\n\n")[3]
    fpath_psbt = microsd_path(fname_psbt)
    with open(microsd_path(fname_psbt), "r") as f:
        final_psbt = f.read().strip()
    garbage_collector.append(fpath)
    # with open(microsd_path(fname_txn), "r") as f:
    #     final_txn = f.read().strip()
    res = wo.finalizepsbt(final_psbt)
    assert res["complete"]
    tx_hex = res["hex"]
    # assert tx_hex == final_txn
    res = wo.testmempoolaccept([tx_hex])
    if recovery and not leaf2_mine:
        assert not res[0]["allowed"]
        assert res[0]["reject-reason"] == 'non-BIP68-final' if sequence else "non-final"
        bitcoind.supply_wallet.generatetoaddress(6, bitcoind.supply_wallet.getnewaddress())
        res = wo.testmempoolaccept([tx_hex])
        assert res[0]["allowed"]
    else:
        assert res[0]["allowed"]

    res = wo.sendrawtransaction(tx_hex)
    assert len(res) == 64  # tx id


# EOF
