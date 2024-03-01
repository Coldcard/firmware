# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, pdb, itertools
from charcodes import KEY_ENTER
from core_fixtures import _pick_menu_item, _cap_story, _press_select, _need_keypress, _cap_menu
from run_sim_tests import ColdcardSimulator, clean_sim_data
from ckcc_protocol.client import ColdcardDevice, CKCC_SIMULATOR_PATH


def _clone(source, target):
    assert source in ["Q", "Mk4"]
    assert target in ["Q", "Mk4"]
    source_sim_arg, source_is_Q = ("--q1", True) if source == "Q" else ("", False)
    target_sim_arg, target_is_Q = ("--q1", True) if target == "Q" else ("", False)

    # first the TARGET
    clean_sim_data()  # remove all from previous
    sim_q = ColdcardSimulator(args=[target_sim_arg, "-l"])
    sim_q.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    _pick_menu_item(device, target_is_Q, "Import Existing")
    _pick_menu_item(device, target_is_Q, "Clone Coldcard")
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "Insert a MicroSD card and press OK to start" in story
    assert "A small file with an ephemeral public key will be written" in story
    _press_select(device, target_is_Q)
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "Keep power on this Coldcard, and take MicroSD card to source Coldcard" in story
    assert "Bring that card back and press OK to complete clone process" in story

    # SOURCE
    # clone with multisig wallet
    sim_mk4 = ColdcardSimulator(args=[source_sim_arg, "--ms", "--p2wsh"])
    sim_mk4.start(start_wait=6)
    device_source = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    _pick_menu_item(device_source, source_is_Q, "Advanced/Tools")
    time.sleep(.1)
    _pick_menu_item(device_source, source_is_Q, "Backup")
    time.sleep(.1)
    _pick_menu_item(device_source, source_is_Q, "Clone Coldcard")
    time.sleep(2)
    title, story = _cap_story(device_source)
    assert "Done" in story
    assert "Take this MicroSD card back to other Coldcard and continue from there" in story
    _press_select(device_source, source_is_Q)
    sim_mk4.stop()

    for _ in range(2):
        try:
            # somehow it works even if it timeouts
            # remember that we have only one .socket (fpath is compiled in pyb.py)
            _need_keypress(device, KEY_ENTER if target_is_Q else "y", timeout=1000)
        except: pass

    sim_q.stop()

    # TARGET again. Killed now - restart and verify settings
    sim_q = ColdcardSimulator(args=[target_sim_arg])
    sim_q.start(start_wait=6)
    device = ColdcardDevice(sn=CKCC_SIMULATOR_PATH)
    _pick_menu_item(device, target_is_Q, "Settings")
    _pick_menu_item(device, target_is_Q, "Multisig Wallets")
    time.sleep(.1)
    m = _cap_menu(device)
    assert "2/4: P2WSH--2-of-4" in m
    sim_q.stop()


@pytest.mark.parametrize("source,target", list(itertools.product(["Q", "Mk4"], repeat=2)))
def test_clone(source, target):
    _clone(source, target)
    time.sleep(1)

# EOF