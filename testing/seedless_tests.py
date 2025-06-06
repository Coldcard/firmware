# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, pdb, time, random, os
from charcodes import KEY_CANCEL
from core_fixtures import _pick_menu_item, _press_select
from core_fixtures import _need_keypress, _sim_exec
from run_sim_tests import ColdcardSimulator, clean_sim_data
from ckcc_protocol.client import ColdcardDevice


def test_status_bar_rewrite_after_restore_master(request):
    from PIL import Image
    clean_sim_data()  # remove all from previous
    sim = ColdcardSimulator(args=["--q1", "-l"])
    sim.start(start_wait=3)
    device = ColdcardDevice(is_simulator=True)

    _pick_menu_item(device, True, "Advanced/Tools")
    _pick_menu_item(device, True, "Temporary Seed")
    _need_keypress(device, "4")
    _pick_menu_item(device, True, "Generate Words")
    _pick_menu_item(device, True, "12 Words")
    _need_keypress(device, "6")
    _press_select(device, True)
    _press_select(device, True)
    _need_keypress(device, KEY_CANCEL)
    _need_keypress(device, KEY_CANCEL)
    fn0 = os.path.realpath(f'./debug/seedless-status-snap-{random.randint(int(1E6), int(9E6))}.png')
    _sim_exec(device, f"from glob import dis; dis.dis.save_snapshot({fn0!r})")
    time.sleep(1)
    rv0 = Image.open(fn0)
    _pick_menu_item(device, True, "Restore Master")
    _press_select(device, True)
    fn1 = os.path.realpath(f'./debug/seedless-status-snap-{random.randint(int(1E6), int(9E6))}.png')
    _sim_exec(device, f"from glob import dis; dis.dis.save_snapshot({fn1!r})")
    time.sleep(1)
    rv1 = Image.open(fn1)
    rv0.show()
    rv1.show()
    sim.stop()