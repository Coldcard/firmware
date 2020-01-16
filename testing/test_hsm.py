# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Test HSM and its policy file.
#
import pytest, time, struct, os
#from pycoin.key.BIP32Node import BIP32Node
#from binascii import b2a_hex, a2b_hex
from ckcc_protocol.protocol import MAX_MSG_LEN, CCProtocolPacker, CCProtoError
from ckcc_protocol.protocol import CCUserRefused, CCProtoError
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

# example dest addrs
EXAMPLE_ADDRS = [ '1ByzQTr5TCkMW9RH1fkD7QtnMbErffDeUo', '2N4EDPkGYcZa5o6kFou2g9zEyiTjk27Jt5D',
            '3Cg1L1LX174jbK7i8mQoY3FiW7XaDs9oRX', 'mrVwhWw4GEBcHFttjEiawL77DaqZWNDm75',
            'tb1q0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rclglv65',
            'bc1q0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc4wylp8',
            'bc1q0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0puqxn6udr',
            'tb1q0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0puq3mvnhv',
]

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
    (DICT(rules=[dict(whitelist=['131CnJGaDyPaJsb5P4NHFxcRi29zo3ZXw'])]),
        'provided it goes to: 131CnJGaDyPaJsb5P4NHFxcRi29zo3ZXw'),
    (DICT(rules=[dict(whitelist=EXAMPLE_ADDRS)]),
        'provided it goes to: '+ ', '.join(EXAMPLE_ADDRS)),

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
        cmd = f"from hsm import ApprovalRule; from main import hsm_active; hsm_active.rules[{idx}] = ApprovalRule({dict(new_rule)}, {idx}); hsm_active.summary='**tweaked**'; RV.write(hsm_active.rules[{idx}].to_text())"
        txt = sim_exec(cmd)
        print(f"Rule {idx} now: {txt}")
    return doit

@pytest.fixture
def tweak_hsm_attr(sim_exec):
    # reach under the skirt, and change and attr on hsm obj
    def doit(name, value):
        cmd = f"from main import hsm_active; setattr(hsm_active, '{name}', {value})"
        sim_exec(cmd)
    return doit

@pytest.fixture
def tweak_hsm_method(sim_exec):
    # reach under the skirt, and change and attr on hsm obj
    def doit(fcn_name, *args):
        cmd = f"from main import hsm_active; getattr(hsm_active, '{name}')({', '.join(args)})"
        sim_exec(cmd)
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
        time.sleep(.2)
        title, body = cap_story()
        assert title == "Start HSM?"
        need_keypress('y')

        # approve it
        time.sleep(.1)
        title, body2 = cap_story()
        assert 'Last chance' in body2
        ll = body2.split('\n')[-1]
        assert ll.startswith("Press ")
        ch = ll[6]
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

    def doit(psbt, refuse=None, remote_error=None):
        open('debug/attempt.psbt', 'wb').write(psbt)
        start_sign(psbt)

        try:
            resp_len, chk = wait_til_signed(dev)
            assert refuse == None, "should have been refused: " + refuse
        except CCProtoError as exc:
            assert remote_error, "unexpected remote error: %s" % exc
            if remote_error not in str(exc):
                raise
        except CCUserRefused:
            msg = hsm_status().last_refusal
            assert refuse != None, "should not have been refused: " + msg
            assert 'HSM rejected' in msg
            assert refuse in msg

            return msg

    return doit

@pytest.mark.parametrize('amount', [ 1E4, 1E6, 1E8 ])
@pytest.mark.parametrize('over', [ 1, 1000])
def test_simple_limit(dev, amount, over, tweak_rule, start_hsm, sim_exec, start_sign, fake_txn, cap_story, attempt_psbt):
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

    tweak_rule(0, dict(max_amount=amount+over))
    attempt_psbt(psbt)

def test_named_wallets(dev, start_hsm, tweak_rule, make_myself_wallet, hsm_status, attempt_psbt, fake_txn, fake_ms_txn, amount=5E6, incl_xpubs=False):
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


def test_whitelist_single(dev, start_hsm, tweak_rule, attempt_psbt, fake_txn, amount=5E6):
    junk = EXAMPLE_ADDRS[0]
    policy = DICT(rules=[dict(whitelist=[junk])])

    stat = start_hsm(policy)

    # try all addr types
    for style in ['p2wpkh', 'p2wsh', 'p2sh', 'p2pkh', 'p2wsh-p2sh', 'p2wpkh-p2sh']:
        dests = []
        psbt = fake_txn(1, 2, dev.master_xpub,
                            outstyles=[style, 'p2wpkh'],
                            outvals=[amount, 1E8-amount], change_outputs=[1], fee=0,
                            capture_scripts=dests)

        dest = render_address(dests[0])

        tweak_rule(0, dict(whitelist=[dest]))
        attempt_psbt(psbt)

        tweak_rule(0, dict(whitelist=[junk]))
        attempt_psbt(psbt, "non-whitelisted")

        tweak_rule(0, dict(whitelist=[dest, junk]))
        attempt_psbt(psbt)

def test_whitelist_multi(dev, start_hsm, tweak_rule, attempt_psbt, fake_txn, amount=5E6):
    # sending to one whitelisted, and one non, etc.
    junk = EXAMPLE_ADDRS[0]
    policy = DICT(rules=[dict(whitelist=[junk])])

    stat = start_hsm(policy)

    # make a txn that sends to every type of output
    styles = ['p2wpkh', 'p2wsh', 'p2sh', 'p2pkh', 'p2wsh-p2sh', 'p2wpkh-p2sh']
    dests = []
    psbt = fake_txn(1, len(styles), dev.master_xpub,
                        outstyles=styles, capture_scripts=dests)

    dests = [render_address(s) for s in dests]

    # simple: sending to all
    tweak_rule(0, dict(whitelist=dests))
    attempt_psbt(psbt)

    # whitelist only one of those (expect fail)
    for dest in dests:
        tweak_rule(0, dict(whitelist=[dest]))
        msg = attempt_psbt(psbt, 'non-whitelisted')
        assert all((a in msg) for a in dests if a != dest)

    # whitelist all but one of them
    for dest in dests:
        others = [d for d in dests if d != dest]
        tweak_rule(0, dict(whitelist=others))
        msg = attempt_psbt(psbt, 'non-whitelisted')
        assert dest in msg
        assert not any((d in msg) for d in others)

@pytest.mark.parametrize('warnings_ok', [ False, True])
def test_huge_fee(warnings_ok, dev, start_hsm, hsm_status, tweak_hsm_attr, attempt_psbt, fake_txn, amount=5E6):
    # fee over 50% never good idea
    # - doesn't matter what current policy is
    policy = {'warnings_ok': warnings_ok, 'rules': [{}]}

    if not hsm_status().active:
        stat = start_hsm(policy)

    tweak_hsm_attr('warnings_ok', warnings_ok)

    psbt = fake_txn(1, 1, dev.master_xpub, fee=0.5E8)
    attempt_psbt(psbt, remote_error='Network fee bigger than 10% of total')

    psbt = fake_txn(1, 1, dev.master_xpub, fee=100)
    attempt_psbt(psbt)

def test_psbt_warnings(dev, start_hsm, tweak_hsm_attr, attempt_psbt, fake_txn, amount=5E6):
    # txn w/ warnings
    policy = DICT(warnings_ok=True, rules=[{}])
    stat = start_hsm(policy)
    assert 'warnings' in stat.summary

    psbt = fake_txn(1, 1, dev.master_xpub, fee=0.05E8)
    attempt_psbt(psbt)

    tweak_hsm_attr('warnings_ok', False)
    attempt_psbt(psbt, 'has 1 warning(s)')


# EOF
