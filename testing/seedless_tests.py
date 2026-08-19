# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, pdb, time, random, os
from charcodes import KEY_QR
from core_fixtures import _pick_menu_item, _press_cancel, _press_select
from core_fixtures import _need_keypress, _sim_exec, _cap_story
from run_sim_tests import ColdcardSimulator, clean_sim_data
from ckcc_protocol.client import ColdcardDevice


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
