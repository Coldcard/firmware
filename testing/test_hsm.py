# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Test HSM and its policy file.
#
import pytest, time, struct, os, itertools
#from pycoin.key.BIP32Node import BIP32Node
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from ckcc_protocol.protocol import MAX_MSG_LEN, CCProtocolPacker, CCProtoError
from ckcc_protocol.protocol import CCUserRefused, CCProtoError
from ckcc_protocol.protocol import USER_AUTH_TOTP, USER_AUTH_HOTP, USER_AUTH_HMAC

import json
from pprint import pprint
from objstruct import ObjectStruct as DICT
from txn import *
from ckcc_protocol.constants import *

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

            simulator.send_recv('HSMR')
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
    (DICT(msg_paths=["any"]), "(any path)"),

    (DICT(share_addrs=["m/1'/2p/3H"]), ['Address values values will be shared', "m/1'/2'/3'"]),
    (DICT(share_addrs=["m/1", "m/2"]), ['Address values values will be shared', "m/1 OR m/2"]),
    (DICT(share_addrs=["any"]), ['Address values values will be shared', "(any path)"]),
    (DICT(share_addrs=["p2sh", "any"]), ['Address values values will be shared', "(any P2SH)", "(any path"]),

    (DICT(share_xpubs=["m/1'/2p/3H"]), ['XPUB values will be shared', "m/1'/2'/3'"]),
    (DICT(share_xpubs=["m/1", "m/2"]), ['XPUB values will be shared', "m/1 OR m/2"]),
    (DICT(share_xpubs=["any"]), ['XPUB values will be shared', "(any path)"]),

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

    if isinstance(contains, str):
        assert contains in got
    else:
        assert all(c in got for c in contains)


@pytest.fixture
def tweak_rule(sim_exec):
    # reach under the skirt, and change policy rule ... so much faster
    def doit(idx, new_rule):
        cmd = f"from hsm import ApprovalRule; from main import hsm_active; hsm_active.rules[{idx}] = ApprovalRule({dict(new_rule)}, {idx}); hsm_active.summary='**tweaked**'; RV.write(hsm_active.rules[{idx}].to_text())"
        txt = sim_exec(cmd)
        if 'Traceback' in txt:
            raise RuntimeError(txt)
        print(f"Rule {idx} now: {txt}")
    return doit

@pytest.fixture
def readback_rule(sim_exec):
    # readback the stored config of a rule, after parsing
    def doit(idx):
        cmd = f"import ujson; from main import hsm_active; RV.write(ujson.dumps(hsm_active.rules[{idx}].to_json()));"
        txt = sim_exec(cmd)
        if 'Traceback' in txt:
            raise RuntimeError(txt)
        return json.loads(txt, object_hook=DICT)
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
def change_hsm(sim_eval, sim_exec, hsm_status):
    # change policy after HSM is running.
    def doit(policy):
        # if already an HSM in motion; just replace it quickly

        act = sim_eval('main.hsm_active')
        assert act != 'None', 'hsm not enabled yet'

        cmd = f"import main; from hsm import HSMPolicy; \
                    p=HSMPolicy(); p.load({dict(policy)}); main.hsm_active=p; p.explain(RV)"
        rv = sim_exec(cmd)
        assert 'Other policy' in rv

        return hsm_status()
    return doit

@pytest.fixture
def start_hsm(dev, need_keypress, hsm_reset, hsm_status, cap_story, change_hsm, sim_eval):
    
    def doit(policy, quick=False):
        # send policy, start it, approve it
        data = json.dumps(policy).encode('ascii')

        if quick:
            # if already an HSM in motion; just replace it quickly
            act = sim_eval('main.hsm_active')
            if act != 'None':
                return change_hsm(policy)

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
            #assert msg.startswith('Rejected: ')
            assert refuse in msg

            return msg

    return doit

@pytest.fixture
def attempt_msg_sign(dev, hsm_status):
    def doit(refuse, *args, **kws):
        dev.send_recv(CCProtocolPacker.sign_message(*args, **kws), timeout=None)

        try:
            done = None
            while done == None:
                time.sleep(0.050)
                done = dev.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)

            assert len(done) == 2
            assert refuse == None, "signing didn't fail, but expected to"
        except CCUserRefused:
            msg = hsm_status().last_refusal
            assert refuse != None, "should not have been refused: " + msg
            assert refuse in msg

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

    stat = start_hsm(policy, quick=True)

    tweak_hsm_attr('warnings_ok', warnings_ok)

    psbt = fake_txn(1, 1, dev.master_xpub, fee=0.5E8)
    attempt_psbt(psbt, remote_error='Network fee bigger than 10% of total')

    psbt = fake_txn(1, 1, dev.master_xpub, fee=100)
    attempt_psbt(psbt)

def test_psbt_warnings(dev, start_hsm, tweak_hsm_attr, attempt_psbt, fake_txn, amount=5E6):
    # txn w/ warnings
    policy = DICT(warnings_ok=True, rules=[{}])
    stat = start_hsm(policy, quick=True)
    assert 'warnings' in stat.summary

    psbt = fake_txn(1, 1, dev.master_xpub, fee=0.05E8)
    attempt_psbt(psbt)

    tweak_hsm_attr('warnings_ok', False)
    attempt_psbt(psbt, 'has 1 warning(s)')

@pytest.mark.parametrize('num_out', [11, 50])
@pytest.mark.parametrize('num_in', [10, 20])
def test_big_txn(num_in, num_out, dev, start_hsm, hsm_status,
                            tweak_hsm_attr, attempt_psbt, fake_txn, amount=5E6):
    # do something slow
    policy = DICT(warnings_ok=True, rules=[{}])
    start_hsm(policy, quick=True)

    for count in range(20):
        psbt = fake_txn(num_in, num_out, dev.master_xpub)
        attempt_psbt(psbt)


def test_sign_msg_good(start_hsm, change_hsm, attempt_msg_sign, addr_fmt=AF_CLASSIC):
    # message signing, but only at certain derivations
    permit = ['m/73', 'm/1p/3h/4/5/6/7' ]
    block = ['m', 'm/72', permit[-1][:-2]]
    msg = b'testing 123'

    policy = DICT(msg_paths=permit)
    start_hsm(policy, quick=True)

    if 1:
        for addr_fmt in  [ AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH]:

            for p in permit: 
                attempt_msg_sign(None, msg, p, addr_fmt=addr_fmt)

            for p in block:
                attempt_msg_sign('not enabled for that path', msg, p, addr_fmt=addr_fmt)

    policy = DICT(msg_paths=['any'])
    change_hsm(policy)

    for p in block+permit: 
        attempt_msg_sign(None, msg, p, addr_fmt=addr_fmt)

def test_sign_msg_any(start_hsm, attempt_msg_sign, addr_fmt=AF_CLASSIC):
    permit = ['m/73', 'm/1p/3h/4/5/6/7' ]
    block = ['m', 'm/72', permit[-1][:-2]]
    msg = b'whatever'

    policy = DICT(msg_paths=['any'])
    start_hsm(policy, quick=True)

    for p in permit+block: 
        attempt_msg_sign(None, msg, p, addr_fmt=addr_fmt)

def test_must_log(start_hsm, sim_card_ejected, attempt_msg_sign, fake_txn, attempt_psbt):
    # stop everything if can't log
    policy = DICT(must_log=True, msg_paths=['m'], rules=[{}])

    start_hsm(policy, quick=False)

    psbt = fake_txn(1, 1)

    sim_card_ejected(True)
    attempt_msg_sign('Could not log details', b'hello', 'm', addr_fmt=AF_CLASSIC)
    attempt_psbt(psbt, 'Could not log details')

    sim_card_ejected(False)
    attempt_msg_sign(None, b'hello', 'm', addr_fmt=AF_CLASSIC)
    attempt_psbt(psbt)

@pytest.fixture
def enter_local_code(need_keypress):
    def doit(code):
        assert len(code) == 6 and code.isdigit()
        need_keypress('x')
        for ch in code:
            need_keypress(ch)
        need_keypress('y')

        # need this because UX loop for HSM has long sleep in it
        time.sleep(.250)

    return doit
        

@pytest.fixture
def auth_user(dev):


    from onetimepass import get_hotp
    
    class State:
        def __init__(self):
            # start time only; don't want to wait 30 seconds between steps
            self.tt = int(time.time() // 30)
            # counter for HOTP
            self.ht = 3
            self.psbt_hash = None

        def __call__(self, username, garbage=False, do_replay=False):
            # calc right values!
            from base64 import b32decode

            mode, secret, _ = TEST_USERS[username]

            if garbage:
                pw = b'\x12'*32 if mode == USER_AUTH_HMAC else b'123x23'
                cnt = (self.tt if mode == USER_AUTH_TOTP else 0)
            elif mode == USER_AUTH_HMAC:
                assert len(self.psbt_hash) == 32
                secret = '1234abcd'     # 
                cnt = 0

                from hashlib import pbkdf2_hmac, sha256
                from hmac import HMAC
                from ckcc_protocol.constants import PBKDF2_ITER_COUNT

                salt = sha256(b'pepper'+dev.serial.encode('ascii')).digest()
                key = pbkdf2_hmac('sha256', secret.encode('ascii'), salt, PBKDF2_ITER_COUNT)
                pw = HMAC(key, self.psbt_hash, sha256).digest()
                assert not do_replay
            else:
                if do_replay:
                    if mode == USER_AUTH_TOTP:
                        cnt = self.tt-1
                    elif mode == USER_AUTH_HOTP:
                        cnt = self.ht-1
                else:
                    if mode == USER_AUTH_TOTP:
                        cnt = self.tt; self.tt += 1
                    elif mode == USER_AUTH_HOTP:
                        cnt = self.ht; self.ht += 1

                pw = b'%06d' % get_hotp(secret, cnt)

            assert len(pw) in {6, 32}

            # no feedback from device at this point.
            dev.send_recv(CCProtocolPacker. user_auth(username.encode('ascii'), pw, totp_time=cnt))

    return State()


def test_invalid_psbt(start_hsm, attempt_psbt):
    policy = DICT(warnings_ok=True, rules=[{}])
    start_hsm(policy, quick=True)
    garb = b'psbt\xff'*20
    attempt_psbt(garb, remote_error='PSBT parse failed')

    # even w/o any signing rights, invalid is invalid
    policy = DICT()
    start_hsm(policy, quick=True)
    attempt_psbt(garb, remote_error='PSBT parse failed')

@pytest.mark.parametrize('package', [
    "hello world; how's tricks?",
    'OGlICrIPZE6DEtsGfcWH2pO6Uz6ZI+w05BYOERMN0XahGicvBhSR4HcgcX3mzk/qM3dWFZ8QAOEIvPFujlhULg==',
    ])
@pytest.mark.parametrize('count', [1, 5])
def test_storage_locker(package, count, start_hsm, dev):
    # read and write, limited; of storage locker.
    policy = DICT(set_sl=package, allow_sl=count)
    start_hsm(policy, quick=False)

    for t in range(count+3):
        if t < count:
            got = dev.send_recv(CCProtocolPacker.get_storage_locker())
            assert got == package.encode('ascii')
        else:
            with pytest.raises(CCProtoError) as ee:
                got = dev.send_recv(CCProtocolPacker.get_storage_locker())
            assert 'consumed' in str(ee)

def test_usb_cmds_block(start_hsm, dev):
    # check these commands return errors (test whitelist)
    block_list = [
        'rebo', 'dfu_', 'enrl', 'enok',
        'back', 'pass', 'bagi', 'hsms', 'nwur', 'rmur', 'pwok', 'bkok',
    ]

    start_hsm(dict(), quick=True)

    for cmd in block_list:
        with pytest.raises(CCProtoError) as ee:
            got = dev.send_recv(cmd)
        assert 'HSM' in str(ee)

def test_unit_local_conf(sim_exec, enter_local_code, start_hsm):

    start_hsm({}, quick=True)

    enter_local_code('123456')
    rb = sim_exec('from main import hsm_active; RV.write(hsm_active.local_code_pending)')
    assert rb == '123456'


def test_show_addr(dev, start_hsm, change_hsm):
    # test we can do address "showing" with no UX
    # which can also be disabled, etc.
    path = 'm/4'
    addr_fmt = AF_P2WPKH
    policy = DICT(share_addrs=[path])

    start_hsm(policy, quick=True)
    addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt))

    change_hsm(DICT(share_addrs=['m']))
    with pytest.raises(CCProtoError) as ee:
        addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt))
    assert 'Not allowed in HSM mode' in str(ee)

    addr = dev.send_recv(CCProtocolPacker.show_address('m', addr_fmt))

    change_hsm(DICT(share_addrs=['any']))
    addr = dev.send_recv(CCProtocolPacker.show_address('m', addr_fmt))
    addr = dev.send_recv(CCProtocolPacker.show_address('m/1/2/3', addr_fmt))
    addr = dev.send_recv(CCProtocolPacker.show_address('m/3', addr_fmt))

    permit = ['m/73', 'm/1p/3h/4/5/6/7', 'm/1/2/3' ]
    change_hsm(DICT(share_addrs=permit))
    for path in permit:
        addr = dev.send_recv(CCProtocolPacker.show_address(path, addr_fmt))

def test_show_p2sh_addr(dev, hsm_reset, start_hsm, change_hsm, make_myself_wallet, addr_vs_path):
    # MULTISIG addrs
    from test_multisig import HARD, make_redeem
    M = 4
    pm = lambda i: [HARD(45), i, 0,0]

    # can't amke ms wallets inside HSM mode
    hsm_reset()
    keys, _ = make_myself_wallet(M)       # slow AF

    permit = ['p2sh', 'm/73']
    start_hsm(DICT(share_addrs=permit))


    scr, pubkeys, xfp_paths = make_redeem(M, keys, path_mapper=pm)
    assert len(scr) <= 520, "script too long for standard!"

    got_addr = dev.send_recv(CCProtocolPacker.show_p2sh_address(
                                    M, xfp_paths, scr, addr_fmt=AF_P2WSH))
    addr_vs_path(got_addr, addr_fmt=AF_P2WSH, script=scr)

    # turn it off; p2sh must be explicitly allowed
    for allow in ['m', 'any']:
        change_hsm(DICT(share_addrs=[allow]))
        dev.send_recv(CCProtocolPacker.show_address('m', AF_CLASSIC))

        with pytest.raises(CCProtoError) as ee:
            got_addr = dev.send_recv(CCProtocolPacker.show_p2sh_address(
                                    M, xfp_paths, scr, addr_fmt=AF_P2WSH))
        assert 'Not allowed in HSM mode' in str(ee)

def test_xpub_sharing(dev, start_hsm, change_hsm, addr_fmt=AF_CLASSIC):
    # message signing, but only at certain derivations
    permit = ['m/73', 'm/1p/3h/4/5/6/7' ]
    block = ['m', 'm/72', permit[-1][:-2]]

    policy = DICT(share_xpubs=permit)
    start_hsm(policy, quick=True)

    for p in permit: 
        xpub = dev.send_recv(CCProtocolPacker.get_xpub(p))

        for p in block:
            with pytest.raises(CCProtoError) as ee:
                xpub = dev.send_recv(CCProtocolPacker.get_xpub(p))
            assert 'Not allowed in HSM mode' in str(ee)

    policy = DICT(share_xpubs=['any'])
    change_hsm(policy)

    for p in block+permit: 
        xpub = dev.send_recv(CCProtocolPacker.get_xpub(p))

@pytest.fixture
def fast_forward(sim_exec):
    def doit(dt):
        cmd = f'from main import hsm_active; hsm_active.period_started -= {dt}; RV.write("ok")'
        assert sim_exec(cmd) == 'ok'
    return doit

def test_velocity(start_hsm, fake_txn, attempt_psbt, fast_forward, hsm_status):
    # stop everything if can't log
    level = int(1E8)
    policy = DICT(period=2, rules=[dict(per_period=level)])

    start_hsm(policy, quick=False)

    psbt = fake_txn(2, 1)
    attempt_psbt(psbt, 'would exceed period spending')

    psbt = fake_txn(2, 2)
    attempt_psbt(psbt, 'would exceed period spending')

    psbt = fake_txn(2, 10)
    attempt_psbt(psbt, 'would exceed period spending')

    psbt = fake_txn(2, 2, outvals=[level, 2E8-level], change_outputs=[1])
    attempt_psbt(psbt)      # exactly the limit

    s = hsm_status()
    assert 118 <= s.period_ends <= 120
    assert s.has_spent == [level]

    attempt_psbt(psbt, 'would exceed period spending')

    psbt = fake_txn(1, 1)
    attempt_psbt(psbt, 'would exceed period spending')

    # skip ahead
    fast_forward(120)
    s = hsm_status()
    assert 'period_ends' not in s
    assert 'has_spend' not in s

    amt = 0.30E8
    psbt = fake_txn(1, 2, outvals=[amt, 1E8-amt], change_outputs=[1])
    attempt_psbt(psbt)      # 1/3rd of limit
    attempt_psbt(psbt)      # 1/3rd of limit
    attempt_psbt(psbt)      # 1/3rd of limit
    attempt_psbt(psbt, 'would exceed period spending')

    s = hsm_status()
    assert 118 <= s.period_ends <= 120
    assert s.has_spent == [int(amt*3)]


def test_user_subset(dev, start_hsm, tweak_rule, load_hsm_users, fake_txn, attempt_psbt, auth_user):
    psbt = fake_txn(1,1)
    auth_user.psbt_hash = sha256(psbt).digest()

    policy = DICT(rules=[dict(users=['totp'])])
    load_hsm_users()
    start_hsm(policy, quick=False)

    for name in USERS:
        tweak_rule(0, dict(users=[name]))

        # should fail
        auth_user(name, garbage=True)
        msg = attempt_psbt(psbt, ': mismatch')
        assert name in msg
        assert 'wrong auth' in msg

        # should work
        auth_user(name)
        attempt_psbt(psbt)

        # auth should be cleared
        attempt_psbt(psbt, 'need user(s) confirmation')

        # fail as "replay"
        # - except PW thing is linked to PSBT, not the counter
        # - except HOTP doesn't see it as replay because it doesn't even check old counter value
        if name != 'pw':
            auth_user(name, do_replay=True)
            attempt_psbt(psbt, 'replay' if name == 'totp' else 'mismatch')

def test_min_users_parse(dev, start_hsm, tweak_rule, load_hsm_users, 
                            auth_user, sim_exec, readback_rule):

    policy = DICT(rules=[dict(users=USERS)])
    load_hsm_users()
    start_hsm(policy, quick=False)

    r = readback_rule(0)
    assert sorted(r.users) == sorted(USERS)
    assert r.min_users == len(USERS)

    for n in range(1, len(USERS)-1):
        policy = DICT(rules=[dict(users=USERS, min_users=n)])
        tweak_rule(0, policy.rules[0])
        r = readback_rule(0)
        assert sorted(r.users) == sorted(USERS)
        assert r.min_users == n if n else r.min_users == len(USERS)

    policy = DICT(rules=[dict(users=USERS, min_users=0)])
    with pytest.raises(RuntimeError) as ee:
        tweak_rule(0, policy.rules[0])
    assert 'must be in range' in str(ee)

    policy = DICT(rules=[dict(users=USERS, min_users=7)])
    with pytest.raises(RuntimeError) as ee:
        tweak_rule(0, policy.rules[0])
    assert 'must be in range' in str(ee)

    policy = DICT(rules=[dict(users=USERS+USERS+USERS, min_users=7)])
    with pytest.raises(RuntimeError) as ee:
        tweak_rule(0, policy.rules[0])
    assert 'dup users' in str(ee)


def test_min_users_perms(dev, start_hsm, load_hsm_users, fake_txn,
                            attempt_psbt, auth_user, sim_exec, readback_rule):
    psbt = fake_txn(1,1)
    auth_user.psbt_hash = sha256(psbt).digest()

    load_hsm_users()

    # all subsets of users
    for n in range(1, len(USERS)):
        policy = DICT(rules=[dict(users=USERS, min_users=n)])
        start_hsm(policy, quick=True)

        for au in itertools.permutations(USERS, n):
            print("Auth with: " + '+'.join(au))
            for u in au:
                auth_user(u)

        attempt_psbt(psbt)

        # auth should be cleared
        attempt_psbt(psbt, 'need user(s) confirmation')
        
def test_local_conf(dev, start_hsm, tweak_rule, load_hsm_users, fake_txn, enter_local_code,
                            hsm_status, attempt_psbt, auth_user, sim_exec, readback_rule):
    
    psbt = fake_txn(1,1)
    auth_user.psbt_hash = sha256(psbt).digest()

    load_hsm_users()
    policy = DICT(rules=[dict(users=USERS, local_conf=True)])
    start_hsm(policy, quick=True)

    for u in USERS:
        auth_user(u)
    enter_local_code(hsm_status().next_local_code)
    attempt_psbt(psbt)


    for u in USERS:
        auth_user(u)
    attempt_psbt(psbt, 'local operator didn\'t confirm')


    tweak_rule(0, dict(local_conf=True))
    attempt_psbt(psbt, 'local operator didn\'t confirm')
    enter_local_code(hsm_status().next_local_code)
    attempt_psbt(psbt)
    
# EOF
