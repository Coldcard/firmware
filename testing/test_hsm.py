# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Test HSM and its policy file.
#
import pytest, time, struct, os
#from pycoin.key.BIP32Node import BIP32Node
#from binascii import b2a_hex, a2b_hex
from ckcc_protocol.protocol import MAX_MSG_LEN, CCProtocolPacker, CCProtoError
from ckcc_protocol.protocol import CCUserRefused
import json
from pprint import pprint
from objstruct import ObjectStruct as DICT
from txn import *

TEST_USERS = { 
            # time based OTP
            # otpauth://totp/totp?secret=UR4LAZMTSJOF52FE&issuer=Coldcard%20simulator
            'totp': [1, 'UR4LAZMTSJOF52FE', 0],

            # OBSCURE: counter-based, not time
            # - no way to get your counter in sync w/ simulator
            # otpauth://hotp/hotp?secret=DBDCOKLQKM6BAKXD&issuer=Coldcard%20simulator
            'hotp': [2, 'DBDCOKLQKM6BAKXD', 0],

            # password
            # pw / 1234abcd
            'pw': [3, 'THNUHHFTG44NLI4EC7H7D6MU5AYMC3B3ER2ZFIBHQVUBOLGADA7Q', 0],
        }
USERS = list(TEST_USERS.keys())

# filename for the policy file, as stored on simulated CC
hsm_policy_path = '../unix/work/hsm-policy.json'

@pytest.fixture(scope='function')
def hsm_reset(simulator, need_keypress):
    def doit():
        # make sure we can setup an HSM now; often need to restart simulator tho
        try:
            os.unlink(hsm_policy_path)
        except FileNotFoundError:
            pass

        # reset simulator (HSM code) to clear previous HSM setup
        while 1:
            j = json.loads(simulator.send_recv(CCProtocolPacker.hsm_status()))
            if j.get('active') == False:
                break

            need_keypress('TEST_RESET')
            time.sleep(.1)

    yield doit

    try:
        os.unlink(hsm_policy_path)
    except FileNotFoundError:
        pass

@pytest.mark.parametrize('policy,contains', [
    (DICT(), 'No transaction will be signed'),
    (DICT(must_log=1), 'MicroSD card MUST '),
    (DICT(must_log=0), 'MicroSD card will '),
    (DICT(warnings_ok=1), 'PSBT warnings'),
    (DICT(msg_paths=["m/1'/2p/3H"]), "m/1'/2'/3'"),
    (DICT(msg_paths=["m/1", "m/2"]), "m/1 OR m/2"),
    (DICT(notes='sdfjkljsdfljklsdf'), 'sdfjkljsdfljklsdf'),

    (DICT(period=2), '2 minutes'),
    (DICT(period=60), '1 hrs'),
    (DICT(period=5*60), '5 hrs'),
    (DICT(period=3*24*60), '72 hrs'),

    (DICT(allow_sl=1), 'once'),
    (DICT(allow_sl=10), '10 times'),
    (DICT(set_sl='abcd'*4, allow_sl=1), 'Locker will be updated'),

    # period / max amount
    (DICT(period=60, rules=[dict(per_period=1000)]),
        '0.00001000 XTN per period'),
    (DICT(period=60, rules=[dict(per_period=1000, max_amount=2000)]),
        'and up to 0.00002000 XTN per txn'),
    (DICT(period=60, rules=[dict(max_amount=3000)]),
        'Up to 0.00003000 XTN per txn'),
    (DICT(rules=[dict(max_amount=3000)]),
        'Up to 0.00003000 XTN per txn'),
    (DICT(rules=[dict()]),
        'Any amount will be approved'),

    # wallets
    (DICT(rules=[dict(wallet='1')]),
        '(non multisig)'),

    # users
    (DICT(rules=[dict(users=USERS)]),
        'Any amount may be authorized by all users'),
    (DICT(rules=[dict(min_users=1, users=USERS)]),
        'Any amount may be authorized by any one user'),
    (DICT(rules=[dict(min_users=2, users=USERS)]),
        'Any amount may be authorized by at least 2 users'),

    # whitelist
    (DICT(rules=[dict(whitelist=['1dfshksdfkhjdfhs'])]),
        'provided it goes to: 1dfshksdfkhjdfhs'),
    (DICT(rules=[dict(whitelist=['1faker', 'tb1qspam'])]),
        'provided it goes to: 1faker OR tb1qspam'),

    # if local user confirms
    (DICT(rules=[dict(local_conf=True)]),
        'if local user confirms'),

    # multiple rules
    (DICT(rules=[dict(local_conf=True), dict(max_amount=1E8)]),
        'Rule #2'),
])
def test_policy_parsing(sim_exec, policy, contains, load_hsm_users):
    # Unit test on parsing!

    load_hsm_users()

    cmd = f"from hsm import HSMPolicy; a=HSMPolicy(); a.load({dict(policy)}); a.explain(RV)"

    got = sim_exec(cmd)
    print(got)

    assert 'Other policy' in got
    assert 'Transactions:\n' in got
    assert 'Message signing:\n' in got
    assert 'Other policy:\n' in got

    if 'rules' not in policy:
        assert 'No transaction will be signed' in got

    if getattr(policy, 'msg_paths', None):
        assert '- Allowed if path is: '

    if getattr(policy, 'period', None):
        assert '%d minutes\n'%policy.period in got

    assert contains in got


@pytest.fixture
def tweak_rule(sim_exec):
    # reach under the skirt, and change policy rule ... so much faster
    def doit(idx, new_rule):
        cmd = f"from hsm import ApprovalRule; from main import hsm_active; hsm_active.rules[{idx}] = ApprovalRule({dict(new_rule)}, {idx}); RV.write(hsm_active.rules[{idx}].to_text())"
        txt = sim_exec(cmd)
        print(f"Rule {idx} now: {txt}")
    return doit

@pytest.fixture
def load_hsm_users(settings_set):
    def doit():
        settings_set('usr', TEST_USERS)
    return doit

@pytest.fixture
def hsm_status(dev):

    def doit():
        txt = dev.send_recv(CCProtocolPacker.hsm_status())
        assert txt[0] == '{'
        assert txt[-1] == '}'
        j = json.loads(txt, object_hook=DICT)
        assert j.active in {True, False}
        return j

    return doit

@pytest.fixture
def start_hsm(dev, need_keypress, sim_exec, hsm_reset, hsm_status, cap_story):
    
    def doit(policy):
        # send policy, start it, approve it
        data = json.dumps(policy).encode('ascii')

        ll, sha = dev.upload_file(data)
        assert ll == len(data)

        dev.send_recv(CCProtocolPacker.hsm_start(ll, sha))

        # capture explanation given user
        time.sleep(.250)
        title, body = cap_story()
        assert title == "Start HSM?"
        need_keypress('y')

        # approve on 
        time.sleep(.250)
        for ch in '12346y':
            need_keypress(ch)

        time.sleep(.100)

        j = hsm_status()
        assert j.active == True
        assert j.summary in body

        return j

    # setup: remove any existing HSM setup
    hsm_reset()

    # fixture ready
    yield doit

def wait_til_signed(dev):
    result = None
    while result == None:
        time.sleep(0.050)
        result = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)

    return result

@pytest.fixture
def attempt_psbt(hsm_status, start_sign, dev):

    def doit(psbt, refuse=None):
        open('debug/attempt.psbt', 'wb').write(psbt)
        start_sign(psbt)

        try:
            resp_len, chk = wait_til_signed(dev)
            assert refuse == None, "should have been refused: " + refuse
        except CCUserRefused:
            msg = hsm_status().last_refusal
            assert refuse != None, "should not have been refused: " + msg
            assert 'HSM rejected' in msg
            assert refuse in msg

    return doit

@pytest.mark.parametrize('amount', [ 1E4, 1E6, 1E8 ])
@pytest.mark.parametrize('over', [ 1, 1000])
def test_simple_limit(dev, amount, over, start_hsm, sim_exec, start_sign, fake_txn, cap_story, attempt_psbt):
    # a policy which sets a hard limit
    policy = DICT(rules=[dict(max_amount=amount)])

    stat = start_hsm(policy)
    assert ('Up to %.8f XTN per txn will be approved' % (amount/1E8)) in stat.summary

    # create a transaction
    psbt = fake_txn(2, 2, dev.master_xpub, outvals=[amount, 2E8-amount],
                        change_outputs=[1], fee=0)
    attempt_psbt(psbt)

    psbt = fake_txn(2, 2, dev.master_xpub, outvals=[amount+over, 2E8-amount-over],
                                                    change_outputs=[1], fee=0)
    attempt_psbt(psbt, "too much out")

def test_named_ms(dev, start_hsm, tweak_rule, make_myself_wallet, hsm_status, attempt_psbt, fake_txn, fake_ms_txn, amount=5E6, incl_xpubs=False):
    wname = 'Myself-4'
    M = 4

    stat = hsm_status()
    assert not stat.active

    for retry in range(3):
        keys, _ = make_myself_wallet(4)       # slow AF

        stat = hsm_status()
        if wname in stat.wallets:
            break

    # policy: only allow multisig w/ that name
    policy = DICT(rules=[dict(wallet=wname)])

    stat = start_hsm(policy)
    assert 'Any amount from multisig wallet' in stat.summary
    assert wname in stat.summary
    assert 'wallets' not in stat

    # simple p2pkh should fail

    psbt = fake_txn(1, 2, dev.master_xpub, outvals=[amount, 1E8-amount], change_outputs=[1], fee=0)
    attempt_psbt(psbt, "not multisig")

    # but txn w/ multisig wallet should work
    psbt = fake_ms_txn(1, 2, M, keys, fee=0, outvals=[amount, 1E8-amount], outstyles=['p2wsh'],
                                    change_outputs=[1], incl_xpubs=incl_xpubs)
    attempt_psbt(psbt)

    # check ms txn not accepted when rule spec's a single signer
    tweak_rule(0, dict(wallet='1'))
    attempt_psbt(psbt, 'wrong wallet')



# EOF
