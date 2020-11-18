# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Test PIN code management. Requires real device, emulator is useless for this.
#
# CAUTIONS: 
# - interrupting these test can leave unit in difficult-to-recover states
# - will erase seed
# - assumes no PIN set yet
# - dev mode must be enabled
# - these tests need to run individually, not working well all together
# - provide "--mk 3" on command line for newer hardware stuff
# - always run with "-s" so you have something to watch: very slow.
#
import time, pytest, os
from ckcc_protocol.protocol import CCProtocolPacker, CCProtoError, MAX_TXN_LEN, CCUserRefused
from binascii import b2a_hex, a2b_hex
from pprint import pprint

@pytest.fixture(scope='session')
def setup_repl(repl):
    repl.exec('from main import pa, dis; import callgate')

def xxx_test_repl(repl, setup_repl):
    # check repl works
    resp = repl.exec('print("hello")')
    assert resp == 'hello\r\n'

def test_eval(repl):
    assert repl.eval('1+2') == 3
    assert repl.eval("'a'+'b'") == "ab"

@pytest.mark.parametrize('pin', [ '12-12', '123456-123456'])
def test_pin_set(repl, setup_repl, is_mark3, pin):
    # always clear it after!
    # might need for recovery:
    #       pa.setup(b'12-12'); pa.login(); pa.change(new_pin=b'')
    #
    
    assert pin != ''

    assert repl.eval("pa.setup(b'')")&0xf == 3, 'pin wasnt blank'
    #assert repl.eval("pa.login() if not pa.is_blank() else True") == True

    print("Attempt pin set to: %s" % pin)
    assert repl.eval("pa.change(new_pin=b'%s')" % pin) == None

    assert repl.eval("pa.setup(b'%s')" % pin)&0xf == 0

    assert repl.eval('pa.private_state == 0') == True

    assert repl.eval("pa.login()") == True

    if is_mark3:
        assert repl.eval('pa.private_state != 0') == True

    assert repl.eval("pa.change(new_pin=b'')") == None

    # this line is a bugfix: mk1/2 bootroms need login after pin change
    assert repl.eval("pa.setup(b'')") == 3

    time.sleep(1)

@pytest.mark.parametrize('test_secret', [b'a'*72, b'X'*72, b'\0'*72])
def test_set_secret(repl, setup_repl, test_secret):
    assert repl.eval('pa.is_successful()'), 'not logged in?'

    assert repl.eval("pa.change(new_secret=%r)" % test_secret) == None
    assert repl.eval("pa.fetch()") == test_secret

    # recovery time, so USB port can service traffic?
    time.sleep(1)

def test_prefix_words(repl, setup_repl):
    # NOTE: doing more than 10 these, we get tarpitted, and more than 25 will cause lockup
    # - all units will have different results here
    a1 = repl.eval("pa.prefix_words(b'12-')")
    a2 = repl.eval("pa.prefix_words(b'435-')")
    assert a1 != a2
    a3 = repl.eval("pa.prefix_words(b'12-')")
    assert a3 != a2
    assert a1 == a3

def test_greenlight(repl, setup_repl):
    from random import randint

    # NOTE: the return values and names of these functions are all stupid.

    assert repl.eval("pa.greenlight_firmware()", max_time=5) == None

    assert repl.eval("callgate.get_genuine()") == 1
    assert repl.eval("callgate.clear_genuine()") == None
    assert repl.eval("callgate.get_genuine()") == 0

    assert repl.eval("callgate.set_genuine()", max_time=5) == 0
    assert repl.eval("callgate.get_genuine()") == 1

    # this changes flash.
    assert repl.eval("open('/flash/test', 'wb').write(b'hi %06d')" % randint(1,1e6)) >= 3
    time.sleep(1)

    # 'set_genuine' really means "test if genuine" here
    assert repl.eval("callgate.set_genuine()", max_time=5) == -1
    assert repl.eval("callgate.get_genuine()") == 1

    assert repl.eval("pa.greenlight_firmware()", max_time=5) == None

    assert repl.eval("callgate.set_genuine()", max_time=5) == 0
    assert repl.eval("callgate.get_genuine()") == 1

    assert repl.eval("dis.clear(); dis.text(0,0, 'done'); dis.show()") == 28

@pytest.mark.parametrize('secondary', [ False, True])
def test_duress(is_mark3, repl, setup_repl, secondary):
    if secondary and is_mark3:
        raise pytest.skip('mark3')

    ss = repl.eval("pa.setup(b'', secondary=%r)" % secondary)
    assert ss&0xf == 3

    if is_mark3:
        assert repl.eval('pa.private_state == 0') == False
    else:
        assert repl.eval('pa.private_state == 0') == True

    assert repl.eval('pa.has_duress_pin()') == False
    assert repl.eval('pa.is_successful()') == True
    assert repl.eval("pa.change(is_duress=True, new_pin=b'34-34', old_pin=b'')") == None
    assert repl.eval("pa.change(is_duress=True, new_secret=b'a'*72, old_pin=b'34-34')") == None
    assert repl.eval("pa.fetch(duress_pin=b'34-34')") == b'a'*72
    assert repl.eval("pa.change(is_duress=True, new_secret=bytes(72), old_pin=b'34-34', new_pin=b'')") == None
    assert repl.eval('pa.has_duress_pin()') == False

    # cleanup
    if secondary:
        repl.eval("pa.setup(b'')")

@pytest.mark.parametrize('secondary', [ False, True])
@pytest.mark.parametrize('nfails', [1, 3])
def test_bad_logins_mark2(is_mark3, repl, setup_repl, secondary, nfails):
    if is_mark3:
        raise pytest.skip('mark3')

    ss = repl.eval("pa.setup(b'', secondary=%r)" % secondary)

    if ss&0xf  != 3:
        # robustness
        repl.eval("pa.setup(b'12-12', secondary=%r)" % secondary)
        repl.eval("[pa.delay() for i in range(pa.delay_required)]")
        assert repl.eval("pa.login()") == True

    assert repl.eval("pa.change(new_pin=b'12-12')") == None
    assert repl.eval("pa.setup(b'12-12', secondary=%r)" % secondary)&0xf == 0
    assert repl.eval("pa.login()") == True

    def prepare_attempt(pin):
        assert repl.eval("pa.setup(%r, secondary=%r)" % (pin, secondary))&0xf == 0
        nf = repl.eval('pa.num_fails')
        nd = repl.eval('pa.delay_required')
        if nf: assert nd >= 1
        for x in range(nd):
            repl.eval('pa.delay()')
        assert repl.eval('pa.delay_required') == repl.eval('pa.delay_achieved')
        return nf

    # try wrong pin a few times
    for n in range(nfails):
        nf = prepare_attempt(b'xx')

        assert nf == n

        with pytest.raises(RuntimeError) as ee:
            repl.eval("pa.login()")
        assert 'AUTH_FAIL' in ee.value.args[0]
        
    # should be successful now
    prepare_attempt(b'12-12')
    assert repl.eval("pa.login()") == True

    # reset state
    assert repl.eval("pa.change(new_pin=b'')") == None
    assert repl.eval("pa.setup(b'', secondary=%r)" % secondary)&0xf == 3
    assert repl.eval("pa.delay_required") == 0
    assert repl.eval("pa.num_fails") == 0


MAX_ATT = 13

@pytest.mark.parametrize('nfails', [MAX_ATT-1, 1, 3, 5])
def test_bad_logins_mark3(is_mark3, repl, setup_repl, nfails):
    if not is_mark3:
        raise pytest.skip('mark3 only')

    ss = repl.eval("pa.setup(b'')")

    if ss&0xf != 3:
        # robustness: recover w/ probably pin
        repl.eval("pa.setup(b'12-12')")
        assert repl.eval("pa.login()") == True

    assert repl.eval("pa.change(new_pin=b'12-12')") == None
    assert repl.eval("pa.setup(b'12-12')")&0xf == 0
    assert repl.eval("pa.login()") == True

    def prepare_attempt(pin):
        assert repl.eval("pa.setup(%r)" % pin)&0xf == 0

        nd, nf, al = repl.eval('pa.delay_required, pa.num_fails, pa.attempts_left')
        assert nd == 0                  # must be zero, obsolete
        assert al <= MAX_ATT
        assert nf + al == MAX_ATT

        return nf

    # try wrong pin a few times
    for n in range(nfails):
        nf = prepare_attempt(b'xx')

        assert nf == n

        with pytest.raises(RuntimeError) as ee:
            repl.eval("pa.login()")
        assert 'AUTH_FAIL' in ee.value.args[0]
        
    # should be successful now
    prepare_attempt(b'12-12')
    assert repl.eval("pa.login()") == True

    nf, al = repl.eval('pa.num_fails, pa.attempts_left')
    assert nf == 0
    assert al == MAX_ATT

    # reset state
    assert repl.eval("pa.change(new_pin=b'')") == None
    assert repl.eval("pa.setup(b'')")&0xf == 3
    nf, al = repl.eval('pa.num_fails, pa.attempts_left')
    assert nf == 0
    assert al == MAX_ATT

@pytest.mark.parametrize('test_secret', [b'a'*416, b'\0'*32+b'm'*(416-32),
                                            bytearray(0x41+(i%57) for i in range(416))])
def test_long_secret(is_mark3, repl, setup_repl, test_secret):
    if not is_mark3:
        raise pytest.skip('mark3 only')

    assert repl.eval('pa.is_successful()'), 'not logged in?'

    assert repl.eval("pa.ls_change(%r)" % test_secret) == None
    assert repl.eval("pa.ls_fetch()") == test_secret

    # recovery time, so USB port can service traffic?
    time.sleep(1)


# EOF
