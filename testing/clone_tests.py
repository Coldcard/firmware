# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import pytest, time, pdb, itertools
from charcodes import KEY_ENTER
from core_fixtures import _pick_menu_item, _cap_story, _press_select, _word_menu_entry
from core_fixtures import _need_keypress, _cap_menu, _sim_exec, _pass_word_quiz
from run_sim_tests import ColdcardSimulator, clean_sim_data
from ckcc_protocol.cli import wait_and_download
from ckcc_protocol.client import ColdcardDevice
from ckcc_protocol.protocol import CCProtocolPacker


def _clone(source, target):
    allowed_devices = ["Q", "Mk4", "Mk5"]
    assert source in allowed_devices
    assert target in allowed_devices

    source_is_Q = False
    source_sim_arg = ""
    if source == "Q":
        source_sim_arg, source_is_Q = "--q1", True
    elif source == "Mk4":
        source_sim_arg, source_is_Q = "--mk4", False

    target_is_Q = False
    target_sim_arg = ""
    if target == "Q":
        target_sim_arg, target_is_Q = "--q1", True
    elif target == "Mk4":
        target_sim_arg, target_is_Q = "--mk4", False

    # first the TARGET
    clean_sim_data()  # remove all from previous
    sim_target = ColdcardSimulator(args=[target_sim_arg, "-l"])
    sim_target.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    _pick_menu_item(device, target_is_Q, "Import Existing")
    _pick_menu_item(device, target_is_Q, "Clone Coldcard")
    time.sleep(.1)
    title, story = _cap_story(device)
    assert f"Insert a MicroSD card and press {'ENTER' if target_is_Q else 'OK'} to start" in story
    assert "A small file with an ephemeral public key will be written" in story
    _press_select(device, target_is_Q)
    time.sleep(.1)
    title, story = _cap_story(device)
    assert "Keep power on this Coldcard, and take MicroSD card to source Coldcard" in story
    assert f"Bring that card back and press {'ENTER' if target_is_Q else 'OK'} to complete clone process" in story

    # SOURCE
    # clone with multisig wallet
    sim_source = ColdcardSimulator(args=[source_sim_arg, "--ms", "--p2wsh",
                                         "--set", "nfc=1", "--set", "vidsk=1"])
    sim_source.start(start_wait=6)
    device_source = ColdcardDevice(is_simulator=True)
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
    sim_source.stop()

    # does not work because of the socket
    # # first enter starts the clone process
    # try:
    #     _need_keypress(device, KEY_ENTER if target_is_Q else "y", timeout=1000)
    # except: pass
    # # now we should see FTUX
    # time.sleep(.1)
    # title, story = _cap_story(device)
    # assert title == 'NO-TITLE'  # no Welcome!
    # assert "best security practices" in story
    # assert "USB disabled" in story
    # assert "NFC disabled" in story
    # assert "VirtDisk disabled" in story
    # assert "You can change these under Settings > Hardware On/Off" in story
    # # confirm FTUX
    # try:
    #     _need_keypress(device, KEY_ENTER if target_is_Q else "y", timeout=1000)
    # except: pass
    # # classic success story + reboot required follows
    # time.sleep(.1)
    # title, story = _cap_story(device)
    # assert title == "Success!"
    # assert "must now reboot to install the updated settings and seed" in story
    # try:
    #     _need_keypress(device, KEY_ENTER if target_is_Q else "y", timeout=1000)
    # except: pass

    for _ in range(3):
        # need 3 ENTERS - 1. start the process; 2.FTUX; 3. Success story
        try:
            # somehow it works even if it timeouts
            # remember that we have only one .socket (fpath is compiled in pyb.py)
            _need_keypress(device, KEY_ENTER if target_is_Q else "y", timeout=1000)
        except: pass

    sim_target.stop()

    # TARGET again. Killed now - restart and verify settings
    sim_target = ColdcardSimulator(args=[target_sim_arg])
    sim_target.start(start_wait=6)
    device = ColdcardDevice(is_simulator=True)
    _pick_menu_item(device, target_is_Q, "Settings")
    _pick_menu_item(device, target_is_Q, "Multisig Wallets")
    time.sleep(.1)
    m = _cap_menu(device)
    assert "2/4: P2WSH--2-of-4" in m

    # check NFC/VDisk after clone - must be disabled
    # USB enabled as we are on the simulator
    cmd = lambda a: f"RV.write(repr(settings.get('{a}', {None!r})))"
    nfc_val = _sim_exec(device, cmd('nfc'))
    vdisk_val = _sim_exec(device, cmd('vidsk'))
    assert not eval(nfc_val) and not eval(vdisk_val)
    sim_target.stop()


@pytest.mark.parametrize("source,target", list(itertools.product(["Q", "Mk4", "Mk5"], repeat=2)))
def test_clone(source, target):
    _clone(source, target)
    time.sleep(1)


def test_backup_restore_delta_pin():
    # SOURCE
    # clone with multisig wallet
    clean_sim_data()  # remove all from previous
    sim_source = ColdcardSimulator(args=["--ms", "--p2wsh", "--set", "nfc=1", "--set", "vidsk=1"],
                                   segregate=True)  # in /tmp/cc-simulators
    sim_source.start(start_wait=6)
    device_source = ColdcardDevice(is_simulator=True, sn=sim_source.socket)
    _pick_menu_item(device_source, False, "Settings")
    time.sleep(.1)
    _pick_menu_item(device_source, False, "Login Settings")
    time.sleep(.1)
    _pick_menu_item(device_source, False, "Trick PINs")
    time.sleep(.1)
    _pick_menu_item(device_source, False, "Add New Trick")
    time.sleep(.1)

    # twice, first select, then verify
    for _ in range(2):
        pin = "11-11"
        pre, suff = pin.split("-")
        for ch in pre:
            _need_keypress(device_source, ch)
            time.sleep(.1)
        _press_select(device_source, False)

        time.sleep(.2)

        for ch in suff:
            _need_keypress(device_source, ch)
            time.sleep(.1)
        _press_select(device_source, False)

    time.sleep(.2)
    _pick_menu_item(device_source, False, "Delta Mode")
    time.sleep(.1)
    title, story = _cap_story(device_source)
    assert "trick PIN must be same length as true PIN and differ only in final 4 positions" in story
    _press_select(device_source, False)
    time.sleep(.1)
    _press_select(device_source, False)
    time.sleep(.1)
    m = _cap_menu(device_source)
    assert "11-11" in m[1]

    ok = device_source.send_recv(CCProtocolPacker.start_backup())
    assert ok is None
    time.sleep(1)
    title, story = _cap_story(device_source)
    assert "backup file password" in story
    word_list = [item.split()[-1] for item in story.split("\n")[1:-4]]
    assert len(word_list) == 12
    _pass_word_quiz(device_source, False, word_list)
    _press_select(device_source, False)  # bkpw
    result, chk = wait_and_download(device_source, CCProtocolPacker.get_backup_file(), 0)
    sim_source.stop()


    # TARGET Q (empty)
    sim_target = ColdcardSimulator(args=["--q1", "-l"])
    sim_target.start(start_wait=6)
    device_target = ColdcardDevice(is_simulator=True)

    name = "backup-delta.7z"
    path = f"../unix/work/MicroSD/{name}"
    with open(path, "wb") as f:
        f.write(result)

    _pick_menu_item(device_target, True, "Import Existing")
    _pick_menu_item(device_target, True, "Restore Backup")
    _pick_menu_item(device_target, True, name)
    time.sleep(.1)

    _word_menu_entry(device_target, True, word_list, has_checksum=False)
    _press_select(device_target, True)  # allow backup restore
    time.sleep(.1)
    _press_select(device_target, True)  # best security practices config
    time.sleep(.1)
    _press_select(device_target, True)  # success

    sim_target.stop()
    time.sleep(1)
    sim_target = ColdcardSimulator(args=["--q1"])
    sim_target.start(start_wait=6)
    device_target = ColdcardDevice(is_simulator=True, sn=sim_target.socket)
    _pick_menu_item(device_target, True, "Settings")
    time.sleep(.1)
    _pick_menu_item(device_target, True, "Login Settings")
    time.sleep(.1)
    _pick_menu_item(device_target, True, "Trick PINs")
    time.sleep(.1)
    m = _cap_menu(device_target)
    assert "11-11" in m[1]

# EOF