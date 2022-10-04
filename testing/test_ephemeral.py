# (c) Copyright 2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Ephemeral Seeds tests
#
import pytest, time, re

from constants import simulator_fixed_words, simulator_fixed_xfp, simulator_fixed_xpub
from helpers import xfp2str
from txn import fake_txn
from ckcc.protocol import CCProtocolPacker


def seed_story_to_words(story: str):
    # filter those that starts with space, number and colon --> actual words
    words = [
        line.strip().split(":")[1].strip()
        for line in story.split("\n")
        if re.search(r"\s\d:", line) or re.search(r"\d{2}:", line)
    ]
    return words

@pytest.fixture
def get_seed_value_ux(goto_home, pick_menu_item, need_keypress, cap_story):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Danger Zone")
        pick_menu_item("Seed Functions")
        pick_menu_item('View Seed Words')
        time.sleep(.01)
        title, body = cap_story()
        assert 'Are you SURE' in body
        assert 'can control all funds' in body
        need_keypress('y')  # skip warning
        time.sleep(0.01)
        title, story = cap_story()
        words = seed_story_to_words(story)
        return words
    return doit


@pytest.fixture
def get_identity_story(goto_home, pick_menu_item, cap_story):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("View Identity")
        time.sleep(0.1)
        title, story = cap_story()
        return story
    return doit

@pytest.fixture
def goto_eph_seed_menu(goto_home, pick_menu_item, cap_story, need_keypress):
    def doit():
        goto_home()
        pick_menu_item("Advanced/Tools")
        pick_menu_item("Ephemeral Seed")

        title, story = cap_story()
        if title == "WARNING":
            assert "temporary secret stored solely in device RAM" in story
            assert "Press 4 to prove you read to the end of this message and accept all consequences." in story
            need_keypress("4")  # understand consequences
    return doit

@pytest.mark.parametrize("num_words", ["12", "24"])
@pytest.mark.parametrize("dice", [False, True])
def test_ephemeral_seed_generate(num_words, cap_menu, pick_menu_item, goto_home, cap_story, need_keypress,
                                 reset_seed_words, get_seed_value_ux, get_identity_story, fake_txn, dev, try_sign, goto_eph_seed_menu, dice):

    reset_seed_words()
    goto_eph_seed_menu()

    menu = cap_menu()

    # no ephemeral seed chosen (yet)
    assert len(menu) == 2
    pick_menu_item("Generate Seed")
    if not dice:
        pick_menu_item(f"{num_words} Words")
        time.sleep(0.1)
    else:
        pick_menu_item(f"{num_words} Word Dice Roll")
        for ch in '123456yy':
            need_keypress(ch)

    title, story = cap_story()
    assert f"Record these {num_words} secret words!" in story
    assert "Press 6 to skip word quiz" in story

    # filter those that starts with space, number and colon --> actual words
    e_seed_words = seed_story_to_words(story)
    assert len(e_seed_words) == int(num_words)

    need_keypress("6")  # skip quiz
    need_keypress("y")  # yes - I'm sure
    time.sleep(0.1)
    need_keypress("4")  # understand consequences
    time.sleep(0.1)
    title, story = cap_story()
    in_effect_xfp = story[1:9]
    assert "key in effect until next power down." in story
    need_keypress("y")  # just confirm new master key message

    menu = cap_menu()
    assert menu[0] == "Ready To Sign"  # returned to main menu
    seed_words = get_seed_value_ux()
    assert e_seed_words == seed_words

    ident_story = get_identity_story()
    assert "Ephemeral seed is in effect" in ident_story

    ident_xfp = ident_story.split("\n\n")[1].strip()
    assert ident_xfp == in_effect_xfp

    e_master_xpub = dev.send_recv(CCProtocolPacker.get_xpub(), timeout=5000)
    assert e_master_xpub != simulator_fixed_xpub
    psbt = fake_txn(3, 3, master_xpub=e_master_xpub, segwit_in=True)
    try_sign(psbt, accept=True, finalize=True)  # MUST NOT raise
    goto_home()
    pick_menu_item("Advanced/Tools")
    pick_menu_item("Ephemeral Seed")
    menu = cap_menu()

    # ephemeral seed chosen -> [xfp] will be visible
    assert len(menu) == 3
    assert menu[0] == f"[{ident_xfp}]"

    reset_seed_words()

    goto_eph_seed_menu()
    menu = cap_menu()
    assert len(menu) == 2

# EOF
