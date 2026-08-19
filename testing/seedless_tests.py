# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, pdb, time, random, os, shutil
from charcodes import KEY_QR
from core_fixtures import _pick_menu_item, _press_select, _press_cancel, _word_menu_entry
from core_fixtures import _need_keypress, _sim_exec, _cap_story
from run_sim_tests import ColdcardSimulator, clean_sim_data
from ckcc_protocol.client import ColdcardDevice
from ckcc_protocol.protocol import CCProtocolPacker


def test_status_bar_rewrite_after_restore_master(request):
    from PIL import Image
    is_Q = request.config.getoption('--Q')
    clean_sim_data()  # remove all from previous
    sim_args = ["-l"]
    if is_Q:
        sim_args.append("--q1")
    sim = ColdcardSimulator(args=sim_args)
    sim.start(start_wait=3)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, is_Q, "Advanced/Tools")
    _pick_menu_item(device, is_Q, "Temporary Seed")
    _need_keypress(device, "4")
    _pick_menu_item(device, is_Q, "Generate Words")
    _pick_menu_item(device, is_Q, "12 Words")

    _pick_menu_item(device, is_Q, "Mash Keys")
    time.sleep(.1)
    _press_select(device, is_Q)

    for i in range(65):
        _need_keypress(device, str(i % 10))

    time.sleep(.2)
    _press_select(device, is_Q)

    _need_keypress(device, "6")
    _press_select(device, is_Q)
    _press_select(device, is_Q)
    _press_cancel(device, is_Q)
    _press_cancel(device, is_Q)
    fn0 = os.path.realpath(f'./debug/seedless-status-snap-{random.randint(int(1E6), int(9E6))}.png')
    _sim_exec(device, f"from glob import dis; dis.dis.save_snapshot({fn0!r})")
    time.sleep(1)
    rv0 = Image.open(fn0)
    _pick_menu_item(device, is_Q, "Restore Master")
    _press_select(device, is_Q)
    fn1 = os.path.realpath(f'./debug/seedless-status-snap-{random.randint(int(1E6), int(9E6))}.png')
    _sim_exec(device, f"from glob import dis; dis.dis.save_snapshot({fn1!r})")
    time.sleep(1)
    rv1 = Image.open(fn1)
    rv0.show()
    rv1.show()
    sim.stop()


def test_seedless_qr_import_bad_checksum():
    clean_sim_data()
    sim = ColdcardSimulator(args=["--q1", "-l"])
    sim.start(start_wait=3)
    device = ColdcardDevice(is_simulator=True)
    try:
        _need_keypress(device, KEY_QR)
        time.sleep(.3)

        # Inject a bad-checksum SeedQR via the simulator's scan queue
        bad_seed = '0000' * 12
        _sim_exec(device, 'glob.SCAN._q.put_nowait(%r)' % bad_seed.encode())
        time.sleep(.5)

        title, story = _cap_story(device)
        assert 'checksum fail' in story
    finally:
        sim.stop()


def test_tmp_backup_restore_on_seedless():
    clean_sim_data()
    backup = os.path.realpath('./data/ckcc-backup.txt')
    shutil.copy(backup, os.path.realpath('../unix/work/MicroSD/ckcc-backup.txt'))

    sim = ColdcardSimulator(args=["--q1", "-l"], headless=True)
    sim.start(start_wait=3)
    device = ColdcardDevice(is_simulator=True)
    try:
        _pick_menu_item(device, True, "Advanced/Tools")
        _pick_menu_item(device, True, "Temporary Seed")
        _need_keypress(device, "4")
        _pick_menu_item(device, True, "Import Words")
        _pick_menu_item(device, True, "12 Words")
        _word_menu_entry(device, True, ["abandon"] * 11 + ["about"])
        time.sleep(.5)
        assert "New temporary master key is in effect now." in _cap_story(device)[1]
        _press_select(device, True)

        _pick_menu_item(device, True, "Advanced/Tools")
        _pick_menu_item(device, True, "Danger Zone")
        _pick_menu_item(device, True, "I Am Developer.")
        _pick_menu_item(device, True, "Restore Bkup")
        _pick_menu_item(device, True, "ckcc-backup.txt")
        time.sleep(.2)
        assert "load backup as temporary seed" in _cap_story(device)[1]
        _press_cancel(device, True)
        time.sleep(2.2)

        with open(backup, "rb") as fd:
            file_len, sha = device.upload_file(fd.read())
        device.send_recv(CCProtocolPacker.restore_backup(file_len, sha, plaintext=True),
                         timeout=None)
        time.sleep(.2)
        assert "Restore uploaded backup as a temporary seed?" in _cap_story(device)[1]
        _press_cancel(device, True)
    finally:
        sim.stop()
