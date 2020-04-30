# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# tests for ../shared/pwsave.py
#
import pytest, time, os
from test_ux import word_menu_entry, enter_complex
from binascii import b2a_hex, a2b_hex
from constants import simulator_fixed_xprv

SIM_FNAME = '../unix/work/MicroSD/.tmp.tmp'

@pytest.fixture
def set_pw_phrase(pick_menu_item, word_menu_entry):
    def doit(words):
        for w in words.split():
            pick_menu_item('Add Word')
            word_menu_entry([w.lower()])
            pick_menu_item(w)

    return doit


@pytest.fixture
def get_to_pwmenu(cap_story, need_keypress, goto_home, pick_menu_item):
    # drill to the enter passphrase menu
    def doit():
        goto_home()
        pick_menu_item('Passphrase')

        _, story = cap_story()
        if 'your BIP39 seed words' in story:
            time.sleep(.01); need_keypress('y'); time.sleep(.01)      # skip warning

    return doit


@pytest.mark.parametrize('pws', [
        'aBc1 aBc2 aBc3', 
        'abcd defg',
        '1aaa 2aaa',
        'ab'*25,
    ])
def test_first_time(pws, need_keypress, cap_story, pick_menu_item, goto_home, enter_complex, cap_menu, get_to_pwmenu):

    try:    os.unlink(SIM_FNAME)
    except: pass

    pws = pws.split()
    xfps = []

    for pw in pws:
        get_to_pwmenu()

        enter_complex(pw)

        pick_menu_item('APPLY')

        time.sleep(.01)
        title, story = cap_story()
        xfp = title[1:-1]
        assert '1 to save to MicroSD' in story

        need_keypress('1')
        xfps.append(xfp)


    for n, pw in enumerate(pws):
        get_to_pwmenu()

        pick_menu_item('Restore Saved')

        m = cap_menu()
        print(m)
        assert len(m) == len(pws)
        assert all(('*' in i) for i in m)

        assert m[n][0] == pw[0] or m[n][-1] == pw[-1]

        pick_menu_item(m[n])

        time.sleep(.01)
        title, story = cap_story()
        xfp = title[1:-1]

        assert xfp == xfps[n]
        need_keypress('y'); 


def test_crypto_unittest(sim_eval, sim_exec):
    # unit test for AES key generation from SDCard and master secret
    card = sim_exec('import files; from h import b2a_hex; cs = files.CardSlot().__enter__(); RV.write(b2a_hex(cs.get_id_hash())); cs.__exit__()')

    # known value for simulator, generally unknown on random SD cards
    assert card == '95a60b9ff0c944ec2c23a28e599f794e95bb376a451b6037b054f8230b405fb0'
    salt = a2b_hex(card)

    # read key simulator calculates
    key = sim_exec('''\
import files; from h import b2a_hex; \
from pwsave import PassphraseSaver; \
cs = files.CardSlot().__enter__(); \
p=PassphraseSaver(); p._calc_key(cs); RV.write(b2a_hex(p.key)); cs.__exit__()''')

    assert len(key) == 64
    #assert key == '234af2aa2ab43af83667dfc6e11d08223e0f486ef34539b41a045dd9eb3ea664'

    from pycoin.key.BIP32Node import BIP32Node
    from pycoin.encoding import from_bytes_32, to_bytes_32
    from hashlib import sha256

    mk = BIP32Node.from_wallet_key(simulator_fixed_xprv)

    sk = mk.subkey_for_path('2147431408p/0p')

    md = sha256()
    md.update(salt)
    md.update(to_bytes_32(sk.secret_exponent()))
    md.update(salt)

    expect = sha256(md.digest()).hexdigest()

    assert expect == key

    # check that key works for decrypt / that the file was actually encrypted

    with open(SIM_FNAME, 'rb') as fd:
        raw = fd.read()

    import pyaes
    d = pyaes.AESModeOfOperationCTR(a2b_hex(expect), pyaes.Counter(0)).decrypt
    txt = str(bytearray(d(raw)), 'utf8')

    print(txt)
    assert txt[0] == '[' and txt[-1] == ']'
    import json
    j = json.loads(txt)
    assert isinstance(j, list)
    assert j[0]['pw']
    assert j[0]['xfp']


# EOF
