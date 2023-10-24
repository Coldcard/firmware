# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# test Seed XOR features
#

import pytest, time, itertools
from mnemonic import Mnemonic
from constants import simulator_fixed_words
from xor import prepare_test_pairs
from test_ux import word_menu_entry, pass_word_quiz

wordlist = Mnemonic('english').wordlist

# 24 words
zero32 = ' '.join('abandon' for _ in range(23)) + ' art'
ones32 = ' '.join('zoo' for _ in range(23)) + ' vote'

# 18 words
zero24 = ' '.join('abandon' for _ in range(17)) + ' agent'
ones24 = ' '.join('zoo' for _ in range(17)) + ' when'

# 12 words
zero16 = ' '.join('abandon' for _ in range(11)) + ' about'
ones16 = ' '.join('zoo' for _ in range(11)) + ' wrong'

zeros = {
    24: zero32,
    18: zero24,
    12: zero16
}

ones = {
    24: ones32,
    18: ones24,
    12: ones16
}

proper = {
    12: "captain appear kiss tent proof consider garlic innocent expire pitch before trap",
    18: ("pumpkin fade era cushion sign bundle relax pink canal improve filter essay "
         "over across fatigue leaf police hello"),
    24: simulator_fixed_words
}

def random_test_cases():
    comb = sorted(itertools.product([2, 3, 4],      # number of parts
                                    [12, 18, 24]))  # mnemonic length
    return [(c, None) for c in comb]

@pytest.fixture
def restore_seed_xor(set_seed_words, goto_home, pick_menu_item, cap_story,
                     choose_by_word_length, need_keypress, get_secrets,
                     word_menu_entry):
    def doit(parts, expect, incl_self=False, save_to_vault=False):
        if expect is None:
            parts, expect = prepare_test_pairs(*parts)

        num_words = len(expect.split())

        if incl_self is True:
            set_seed_words(parts[0])
        elif incl_self is False:
            set_seed_words(proper[num_words])

        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Danger Zone')
        pick_menu_item('Seed Functions')
        pick_menu_item('Seed XOR')
        pick_menu_item('Restore Seed XOR')
        time.sleep(.01)
        title, body = cap_story()

        assert 'all the parts' in body
        assert "Press OK for 24 words" in body
        assert "press (1)" in body
        assert "press (2)" in body

        choose_by_word_length(num_words)
        time.sleep(0.01)

        title, body = cap_story()
        assert 'you have a seed already' in body
        if incl_self:
            assert '(1) to include this Coldcard' in body
            need_keypress('1')
        else:
            need_keypress('y')

        for n, part in enumerate(parts):
            if n == 0 and incl_self:
                continue

            word_menu_entry(part.split())

            time.sleep(0.01)
            title, body = cap_story()
            assert f"You've entered {n + 1} parts so far" in body
            assert "or (2) if done" in body

            if n != len(parts) - 1:
                need_keypress('1')
            else:
                # correct anticipated checksum word
                chk_word = expect.split()[-1]
                assert f"{num_words}: {chk_word}" in body
                if expect == zeros[num_words]:
                    assert 'ZERO WARNING' in body

        need_keypress('2')

        time.sleep(0.01)
        title, body = cap_story()

        if 'into Seed Vault' in body:
            # seed vault saving is enabled, use it, maybe
            if save_to_vault:
                need_keypress('1')
                time.sleep(0.01)
                title, body = cap_story()
                assert 'Saved to Seed Vault' in body

                need_keypress('y')
            else:
                need_keypress('x')

            time.sleep(0.01)
            title, body = cap_story()

        assert 'New ephemeral master key in effect' in body
        need_keypress("y")
        assert get_secrets()['mnemonic'] == expect

    return doit

@pytest.mark.parametrize('incl_self', [False, True])
@pytest.mark.parametrize('seed_vault', [False, True])
@pytest.mark.parametrize('parts, expect', [
    # 24words - 3 parts
    (['romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room',
      'lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge',
      'vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate',],
     'silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor'),
    # 18words - 3 parts
    (['example twelve meadow embrace neither sign ribbon equal inspire guess episode piece fatal unlock prefer unhappy vanish curtain',
      'ostrich present hold dwarf area say act carpet eight jeans student warfare access cause offer suit dawn height',
      'sure lawsuit half gym fatal column remain dash cage orchard frame reform robust social inspire online evolve lobster'],
     'ancient dish minute goddess smooth foil auction floor bean mimic scale transfer trumpet alter echo push mass task'),
    # 12words - 3 parts
    (['become wool crumble brand camera cement gloom sell stand once connect stage',
      'save saddle indicate embrace detail weasel spread life staff mushroom bicycle light',
      'unlock damp injury tape enhance pause sheriff onion valley panic finger moon'],
     'drama jeans craft mixture filter lamp invest suggest vacant neutral history swim'),
    ([zero32]*2, zero32),
    ([zero24]*2, zero24),
    ([zero16]*2, zero16),
    ([ones32]*7, ones32),
    ([ones24]*7, ones24),
    ([ones16]*7, ones16),
    ([ones32]*4, zero32),
    ([ones24]*4, zero24),
    ([ones16]*4, zero16),
    # random generated
    *random_test_cases()
])
def test_import_xor(seed_vault, incl_self, parts, expect, word_menu_entry, restore_seed_xor):
    restore_seed_xor(parts, expect, incl_self, seed_vault)


@pytest.mark.parametrize('num_words', [12, 18, 24])
@pytest.mark.parametrize('qty', [2, 3, 4])
@pytest.mark.parametrize('trng', [False, True])
def test_xor_split(num_words, qty, trng, goto_home, pick_menu_item, cap_story, need_keypress,
                   cap_menu, get_secrets, pass_word_quiz, set_seed_words):

    set_seed_words(proper[num_words])

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
    # assert f"{qty*24} words" in body

    need_keypress('2' if trng else 'y')
    time.sleep(.01)
    title, body = cap_story()

    assert f'Record these {qty} lists of {num_words}-words' in body
    assert all((f'Part {chr(n+65)}:' in body) for n in range(qty))
    
    words = [ln[4:] for ln in body.split('\n') if ln[2:4] == ': ']
    assert len(words) == (num_words * qty) + 1  # check word

    chk_word = words[-1]
    parts = [words[pos:pos+num_words] for pos in range(0, num_words*qty, num_words)]

    expect = get_secrets()['mnemonic'].split()
    assert expect[-1] == chk_word

    for part in parts[1:]:
        assert part != parts[0]
        # words on same indexes do not necessarily need to differ
        # assert all(parts[0][n] != part[n] for n in range(num_words))

    x = [0]*num_words
    for part in parts:
        for n, word in enumerate(part):
            x[n] ^= wordlist.index(word)

    assert len(set(x)) > 4

    #x[-1] &= 0x700
    got = [wordlist[i] for i in x[:-1]]
    assert len(got) == (num_words -1)
    assert got == expect[0:-1]
    
    count, title, body = pass_word_quiz(parts[0], prefix='A')
    assert count == num_words
    for n, part in enumerate(parts[1:]):
        count, title, body = pass_word_quiz(part, prefix=chr(65+n+1), preload=(title, body))
        assert count == num_words

    assert 'Quiz Passed' in body

@pytest.mark.parametrize('num_words', [12, 18, 24])
def test_import_zero_set(num_words, goto_home, pick_menu_item, cap_story, need_keypress, cap_menu,
                         get_secrets, word_menu_entry, reset_seed_words, set_seed_words,
                         choose_by_word_length):

    set_seed_words(proper[num_words])

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
    assert "Press OK for 24 words" in body
    assert "press (1)" in body
    assert "press (2)" in body

    choose_by_word_length(num_words)
    time.sleep(0.01)

    title, body = cap_story()
    assert 'you have a seed already' in body
    assert '(1) to include this Coldcard' in body
    need_keypress('y')

    #time.sleep(0.01)
    for n in range(2):
        word_menu_entry(ones[num_words].split())

        time.sleep(0.01)
        title, body = cap_story()
        assert f"You've entered {n+1} parts so far" in body
        assert "or (2) if done" in body

        if n == 1:
            assert 'ZERO WARNING' in body
            return

        need_keypress('1')

    raise pytest.fail("reached")

@pytest.mark.parametrize('parts, expect', [
    # 24words - 3 parts
    (['romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room',
      'lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge',
      'vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate',],
     'silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor'),
    # 18words - 3 parts
    (['example twelve meadow embrace neither sign ribbon equal inspire guess episode piece fatal unlock prefer unhappy vanish curtain',
      'ostrich present hold dwarf area say act carpet eight jeans student warfare access cause offer suit dawn height',
      'sure lawsuit half gym fatal column remain dash cage orchard frame reform robust social inspire online evolve lobster'],
     'ancient dish minute goddess smooth foil auction floor bean mimic scale transfer trumpet alter echo push mass task'),
    # 12words - 3 parts
    (['become wool crumble brand camera cement gloom sell stand once connect stage',
      'save saddle indicate embrace detail weasel spread life staff mushroom bicycle light',
      'unlock damp injury tape enhance pause sheriff onion valley panic finger moon'],
     'drama jeans craft mixture filter lamp invest suggest vacant neutral history swim'),
    # random generated
    *random_test_cases()
])
def test_xor_import_empty(parts, expect, pick_menu_item, cap_story, need_keypress,
                          cap_menu, word_menu_entry, get_secrets, reset_seed_words,
                          unit_test, expect_ftux, choose_by_word_length):

    # test import when wallet empty
    if expect is None:
        parts, expect = prepare_test_pairs(*parts)

    num_words = len(expect.split())
    unit_test('devtest/clear_seed.py')

    m = cap_menu()
    assert m[0] == 'New Seed Words'    
    pick_menu_item('Import Existing')
    pick_menu_item('Seed XOR')

    time.sleep(0.01)
    title, body = cap_story()
    assert 'all the parts' in body
    assert "Press OK for 24 words" in body
    assert "press (1)" in body
    assert "press (2)" in body
    choose_by_word_length(num_words)
    time.sleep(0.01)

    for n, part in enumerate(parts):
        word_menu_entry(part.split())

        time.sleep(0.01)
        title, body = cap_story()
        assert f"You've entered {n + 1} parts so far" in body
        assert "or (2) if done" in body

        if n != len(parts)-1:
            assert 'ZERO WARNING' not in body
            need_keypress('1')
        else:
            # correct anticipated checksum word
            chk_word = expect.split()[-1]
            assert f"{num_words}: {chk_word}" in body
            if expect == zeros[num_words]:
                assert 'ZERO WARNING' in body

    # install seed ... causes reset on real device
    need_keypress('2')

    time.sleep(0.01)

    # main menu should be "ready to sign" now
    expect_ftux()

    assert get_secrets()['mnemonic'] == expect
    reset_seed_words()

# EOF
