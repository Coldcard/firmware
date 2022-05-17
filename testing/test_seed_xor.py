# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test Seed XOR features
#
import time
import pytest
from mnemonic import Mnemonic
from test_ux import word_menu_entry, pass_word_quiz

wordlist = Mnemonic('english').wordlist

zero32 = ' '.join('abandon' for _ in range(23)) + ' art'
ones32 = ' '.join('zoo' for _ in range(23)) + ' vote'

@pytest.mark.parametrize('incl_self', [False, True])
@pytest.mark.parametrize('parts, expect', [
    ( [ 'romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room',
        'lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge',
        'vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate',],
    'silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor'),
    ( [zero32]*2, zero32),
    ( [ones32]*7, ones32),
    ( [ones32]*4, zero32),
])
def test_import_xor(incl_self, parts, expect, goto_home, pick_menu_item, cap_story, need_keypress, cap_menu, word_menu_entry, get_secrets, reset_seed_words, set_seed_words):

    # values from docs/seed-xor.md, and some easy cases

    if incl_self:
        set_seed_words(parts[0])

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Seed XOR')
    pick_menu_item('Restore Seed XOR')
    time.sleep(.01)
    title, body = cap_story()

    assert 'all the parts' in body
    need_keypress('y')
    time.sleep(0.01)

    title, body = cap_story()
    assert 'you have a seed already' in body
    assert '(1) to include this Coldcard' in body
    if incl_self:
        need_keypress('1')
    else:
        need_keypress('y')

    #time.sleep(0.01)

    for n, part in enumerate(parts):
        if n == 0 and incl_self:
            continue

        word_menu_entry(part.split())

        time.sleep(0.01)
        title, body = cap_story()
        assert f"You've entered {n} parts so far"
        assert "or (2) if done"

        if n != len(parts)-1:
            need_keypress('1')
        else:
            # correct anticipated checksum word
            chk_word = expect.split()[-1]
            assert f"24: {chk_word}" in body
            if expect == zero32:
                assert 'ZERO WARNING' in body

    need_keypress('2')

    time.sleep(0.01)
    title, body = cap_story()
    assert 'New master key in effect' in body

    assert get_secrets()['mnemonic'] == expect
    reset_seed_words()

@pytest.mark.parametrize('qty', [2, 3, 4])
@pytest.mark.parametrize('trng', [False, True])
def test_xor_split(qty, trng, goto_home, pick_menu_item, cap_story, need_keypress, cap_menu, word_menu_entry, get_secrets, pass_word_quiz):

    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Seed XOR')
    pick_menu_item('Split Existing')
    time.sleep(.01)
    title, body = cap_story()

    assert 'Seed XOR Split' in body
    assert 'ANY ONE' in body
    assert 'ALL FUNDS' in body
    assert str(qty) in body
    need_keypress(str(qty))

    time.sleep(.01)
    title, body = cap_story()
    assert f"Split Into {qty} Parts" in body
    assert f"{qty*24} words" in body

    need_keypress('2' if trng else 'y')
    time.sleep(.01)
    title, body = cap_story()

    assert f'Record these {qty} lists of 24-words' in body
    assert all((f'Part {chr(n+65)}:' in body) for n in range(qty))
    
    words = [ln[4:] for ln in body.split('\n') if ln[2:4] == ': ']
    assert len(words) == (24 * qty)+1

    chk_word = words[-1]
    parts = [words[pos:pos+24] for pos in range(0, 24*qty, 24)]

    expect = get_secrets()['mnemonic'].split()
    assert expect[-1] == chk_word

    for part in parts[1:]:
        assert part != parts[0]
        assert all(parts[0][n] != part[n] for n in range(24))

    x = [0]*24
    for part in parts:
        for n, word in enumerate(part):
            x[n] ^= wordlist.index(word)

    assert len(set(x)) > 4

    #x[-1] &= 0x700
    got = [wordlist[i] for i in x[:-1]]
    assert len(got) == 23
    assert got == expect[0:-1]
    
    count, title, body = pass_word_quiz(parts[0], prefix='A')
    assert count == 24
    for n, part in enumerate(parts[1:]):
        count, title, body = pass_word_quiz(part, prefix=chr(65+n+1), preload=(title, body))
        assert count == 24

    assert 'Quiz Passed' in body

def test_import_zero_set(goto_home, pick_menu_item, cap_story, need_keypress, cap_menu, word_menu_entry, get_secrets, reset_seed_words, set_seed_words):

    # look for a warning
    goto_home()
    pick_menu_item('Advanced/Tools')
    pick_menu_item('Danger Zone')
    pick_menu_item('Seed Functions')
    pick_menu_item('Seed XOR')
    pick_menu_item('Restore Seed XOR')
    time.sleep(.01)
    title, body = cap_story()

    assert 'all the parts' in body
    need_keypress('y')
    time.sleep(0.01)

    title, body = cap_story()
    assert 'you have a seed already' in body
    assert '(1) to include this Coldcard' in body
    need_keypress('y')

    #time.sleep(0.01)

    for n in range(2):
        word_menu_entry(ones32.split())

        time.sleep(0.01)
        title, body = cap_story()
        assert f"You've entered {n} parts so far"
        assert "or (2) if done"

        if n == 1:
            assert 'ZERO WARNING' in body
            return

        need_keypress('1')

    raise pytest.fail("reached")

@pytest.mark.parametrize('parts, expect', [
    ( [ 'romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room',
        'lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge',
        'vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate',],
    'silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor'),
])
def test_xor_import_empty(parts, expect, goto_home, pick_menu_item, cap_story, need_keypress, cap_menu, word_menu_entry, get_secrets, reset_seed_words, unit_test, expect_ftux):

    # test import when wallet empty
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')
    pick_menu_item('Seed XOR')

    time.sleep(0.01)
    title, body = cap_story()
    assert 'all the parts' in body
    need_keypress('y')
    time.sleep(0.01)

    for n, part in enumerate(parts):
        word_menu_entry(part.split())

        time.sleep(0.01)
        title, body = cap_story()
        assert f"You've entered {n} parts so far"
        assert "or (2) if done"

        if n != len(parts)-1:
            assert 'ZERO WARNING' not in body
            need_keypress('1')
        else:
            # correct anticipated checksum word
            chk_word = expect.split()[-1]
            assert f"24: {chk_word}" in body
            if expect == zero32:
                assert 'ZERO WARNING' in body

    # install seed ... causes reset on real device
    need_keypress('2')

    time.sleep(0.01)

    # main menu should be "ready to sign" now
    expect_ftux()

    assert get_secrets()['mnemonic'] == expect
    reset_seed_words()


# EOF
