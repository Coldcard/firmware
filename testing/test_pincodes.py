# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Test PIN code management. Requires real device, emulator is useless for this.
#
# CAUTIONS: 
# - interrupting these test can leave unit in difficult-to-recover states
# - will erase seed
# - assumes no PIN set yet
# - dev mode must be enabled
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
def test_pin_set(repl, setup_repl, pin):
    # always clear it after!
    # might need for recovery:
    #       pa.setup(b'12-12'); pa.login(); pa.change(new_pin=b'')
    #
    
    assert pin != ''

    assert repl.eval("pa.setup(b'')") == 3, 'pin wasnt blank'
    #assert repl.eval("pa.login() if not pa.is_blank() else True") == True

    print("Attempt pin set to: %s" % pin)
    assert repl.eval("pa.change(new_pin=b'%s')" % pin) == None

    assert repl.eval("pa.setup(b'%s')" % pin) == 0
    assert repl.eval("pa.login()") == True
    assert repl.eval("pa.change(new_pin=b'')") == None

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
    assert repl.eval("pa.greenlight_firmware()", max_time=5) == None
    assert repl.eval("dis.clear(); dis.text(0,0, 'okay'); dis.show()") == 28

    assert repl.eval("callgate.get_genuine()") == 1
    assert repl.eval("callgate.clear_genuine()") == None
    assert repl.eval("callgate.get_genuine()") == 0

    assert repl.eval("callgate.set_genuine()", max_time=5) == 0
    assert repl.eval("callgate.get_genuine()") == 1

    assert repl.eval("dis.clear(); dis.text(0,0, 'done'); dis.show()") == 28


# EOF
