# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Mk4 Virtual Disk related tests.
#

import pytest, glob, re, time, io, os
from binascii import b2a_hex, a2b_hex
import ndef
from hashlib import sha256
from txn import *
from base64 import b64encode, b64decode


def test_vd_basics(dev, virtdisk_path, is_simulator):
    # Check right files are in place.
    if is_simulator():
        assert os.path.isfile(virtdisk_path('README.md'))
        return

    assert os.path.isfile(virtdisk_path('README.txt'))
    assert os.path.isdir(virtdisk_path('ident'))

    for fn in ['serial.txt', 'version.txt']:
       assert os.path.isfile(virtdisk_path(f'ident/{fn}'))

    sn = open(virtdisk_path('ident/serial.txt'), 'rt').read().strip()
    assert sn == dev.serial

    assert os.path.isfile(virtdisk_path(f'ident/ckcc-{sn}.txt'))

@pytest.fixture
def try_sign_virtdisk(press_select, virtdisk_path, cap_story, virtdisk_wipe, press_cancel):

    # like "try_sign" but use Virtual Disk to send/receive PSBT/results
    # - on real dev, need user to manually say yes ... alot
    # - on simulator, start with "--eject" arg so no SDCard emulated


    def doit(f_or_data, accept=True, expect_finalize=False, accept_ms_import=False, complete=False, encoding='binary'):

        assert not accept_ms_import, 'no support'
        assert accept, 'no support'

        virtdisk_wipe()

        if f_or_data[0:5] == b'psbt\xff':
            ip = f_or_data
            filename = 'memory'
        else:
            filename = f_or_data
            ip = open(f_or_data, 'rb').read()
            if ip[0:10] == b'70736274ff':
                ip = a2b_hex(ip.strip())
            assert ip[0:5] == b'psbt\xff'

        if encoding == 'hex':
            ip = b2a_hex(ip)
        elif encoding == 'base64':
            ip = b64encode(ip)
        else:
            assert encoding == 'binary'
            assert ip[0:5] == b'psbt\xff'

        # clear old junk
        virtdisk_wipe()

        xfn = virtdisk_path('testcase.psbt')
        open(xfn, 'wb').write(ip)

        press_select()      # ready to sign (hopefully)

        # CC scans drive, reads PSBT, verifies...
        time.sleep(1)

        # approve siging txn
        if accept:
            press_select()
        else:
            press_cancel()

        if accept == False:
            time.sleep(0.050)

            # look for "Aborting..." ??
            return ip, None, None

        # wait for it to finish signing
        title, story = cap_story()
        if "OK TO SEND" in title or "PSBT Signed" in title:
            press_select()

        result_fn = xfn.replace('.psbt', '-*.psbt')
        result_txn = xfn.replace('.psbt', '.txn')

        got_psbt = None
        got_txn = None
        txid, got_txid = None, None
        for i in range(15):
            try:
                got_txn = open(result_txn, 'rb').read()
            except FileNotFoundError as e:
                print(e)
                pass

            lst = glob.glob(result_fn)
            if lst:
                assert len(lst) == 1, "multi files: " + ', '.join(lst)
                result_fn = lst[0]
                got_psbt = open(result_fn, 'rb').read()

            # for delete-psbt mode
            for ff in glob.glob(virtdisk_path('*.txn')):
                if ff == result_txn: continue
                try:
                    got_txid = re.findall(r'[0-9a-f]{64}', ff)[0]
                except IndexError:
                    got_txid = None
                got_txn = a2b_hex(open(ff, 'rt').read().strip())

            if got_txn or got_psbt:
                break

            time.sleep(1)
        else:
            raise pytest.fail('never got result: ' + result_fn)


        if got_txid and not txid:
            # Txid not shown unless "delete psbt" mode
            txid = got_txid

        if got_txid:
            assert got_txn
            assert got_txid == txid
            assert expect_finalize
            open("debug/vd-result.txn", 'wb').write(got_txid)


        # check output encoding matches input (for PSBT only)
        if got_psbt:
            if encoding == 'hex':
                got_psbt = a2b_hex(got_psbt.strip())
            elif encoding == 'base64':
                got_psbt = b64decode(got_psbt)
            else:
                assert encoding == 'binary'

        # validate what we got
        if got_txn:
            from ctransaction import CTransaction
            # parse it a little
            assert got_txn[0:4] != b'psbt'
            t = CTransaction()
            t.deserialize(io.BytesIO(got_txn))
            assert t.nVersion in [1, 2]
            if txid:
                assert t.txid().hex() == txid
            else:
                txid = t.txid().hex()

        if got_psbt:
            assert got_psbt[0:5] == b'psbt\xff'
            open("debug/vd-result.psbt", 'wb').write(got_psbt)

            from psbt import BasicPSBT
            was = BasicPSBT().parse(ip) 
            now = BasicPSBT().parse(got_psbt)
            assert was.txn == now.txn
            assert was != now

        return ip, (got_psbt or got_txn), txid

    return doit


@pytest.mark.unfinalized            # iff partial=1
@pytest.mark.parametrize('encoding', ['binary', 'hex', 'base64'])
@pytest.mark.parametrize('num_outs', [1,2])
@pytest.mark.parametrize('partial', [1, 0])
def test_virtdisk_signing(encoding, num_outs, partial, try_sign_virtdisk, fake_txn, dev, sd_cards_eject):
    xp = dev.master_xpub
    sd_cards_eject()

    def hack(psbt):
        if partial:
            # change first input to not be ours
            pk = list(psbt.inputs[0].bip32_paths.keys())[0]
            pp = psbt.inputs[0].bip32_paths[pk]
            psbt.inputs[0].bip32_paths[pk] = b'what' + pp[4:]

    psbt = fake_txn(2, num_outs, xp, segwit_in=True, psbt_hacker=hack)

    _, txn, txid = try_sign_virtdisk(psbt, expect_finalize=not partial, encoding=encoding)

if 0:
    @pytest.mark.parametrize('num_outs', [ 1, 20, 250])
    def test_virtdisk_after(num_outs, fake_txn, try_sign, nfc_read, need_keypress, cap_story, only_mk4):
        # Read signing result (transaction) over NFC, decode it.
        psbt = fake_txn(1, num_outs)
        orig, result = try_sign(psbt, accept=True, finalize=True)

        too_big = len(result) > 8000

        if too_big: assert num_outs > 100
        if num_outs > 100: assert too_big

        time.sleep(.1)
        title, story = cap_story()
        assert 'TXID' in title, story
        txid = a2b_hex(story.split()[0])
        assert 'Press (3)' in story
        need_keypress('3')

        if too_big:
            title, story = cap_story()
            assert 'is too large' in story
            return

        contents = virtdisk_read()
        #need_keypress('x')

        #print("contents = " + B2A(contents))
        for got in ndef.message_decoder(contents):
            if got.type == 'urn:nfc:wkt:T':
                assert 'Transaction' in got.text
                assert b2a_hex(txid).decode() in got.text
            elif got.type == 'urn:nfc:ext:bitcoin.org:txid':
                assert got.data == txid
            elif got.type == 'urn:nfc:ext:bitcoin.org:txn':
                assert got.data == result
            elif got.type == 'urn:nfc:ext:bitcoin.org:sha256':
                assert got.data == sha256(result).digest()
            else:
                raise ValueError(got.type)

def test_macos_detection():
    # not a portable test...  at all.
    import platform, subprocess, plistlib

    if not platform.platform().startswith('macOS-11'):
        raise pytest.xfail("requires MacOS")

    if not os.path.isdir('/Volumes/COLDCARD'):
        raise pytest.xfail("needs COLDCARD mounted in usual spot")

    cmd = ['diskutil', 'info', '-plist', '/Volumes/COLDCARD']
    pl = subprocess.check_output(cmd)

    pl = plistlib.loads(pl)

    assert pl['VolumeName'] == 'COLDCARD'
    assert pl['BusProtocol'] == 'USB'
    assert pl['FilesystemName'] == 'MS-DOS FAT16'
    assert pl['VolumeAllocationBlockSize'] == 512
    assert pl['IOKitSize'] == 4194304           # requires 5.0.6


@pytest.mark.parametrize('multiple_runs', range(3))
@pytest.mark.parametrize('testnet', [True, False])
def test_import_prv_virtdisk(testnet, pick_menu_item, cap_story, need_keypress,
                             unit_test, cap_menu, get_secrets, multiple_runs,
                             reset_seed_words, virtdisk_path, virtdisk_wipe,
                             settings_set, press_select):
    # copied from test_ux as we need vdisk enabled and card ejected
    if testnet:
        netcode = "XTN"
        settings_set('chain', 'XTN')
    else:
        netcode = "BTC"
        settings_set('chain', 'XTN')

    unit_test('devtest/clear_seed.py')

    fname = 'test-%d.txt' % os.getpid()
    path = virtdisk_path(fname)

    from bip32 import BIP32Node
    node = BIP32Node.from_master_secret(os.urandom(32), netcode=netcode)
    prv = node.hwif(as_private=True) + '\n'
    if testnet:
        assert "tprv" in prv
    else:
        assert "xprv" in prv
    with open(path, 'wt') as f:
        f.write(prv)
    print("Created: %s" % path)

    m = cap_menu()
    assert m[0] == 'New Seed Words'
    pick_menu_item('Import Existing')
    pick_menu_item('Import XPRV')
    title, body = cap_story()
    assert "press (2) to import from Virtual Disk" in body
    need_keypress("2")
    time.sleep(.01)
    pick_menu_item(fname)
    unit_test('devtest/abort_ux.py')

    v = get_secrets()

    assert v['xpub'] == node.hwif()
    assert v['xprv'] == node.hwif(as_private=True)

    reset_seed_words()

# EOF
