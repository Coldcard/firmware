# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Tests that need a person there... mostly when not run on simulator
#
import time, pytest
from ckcc_protocol.protocol import MAX_MSG_LEN, CCProtocolPacker, CCProtoError
from ckcc_protocol.protocol import CCUserRefused


def test_backup_refuse(dev, need_keypress):
    time.sleep(0.050)

    r = dev.send_recv(CCProtocolPacker.start_backup())
    assert r == None

    need_keypress('x')

    with pytest.raises(CCUserRefused):
        done = None
        while done == None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_backup_file())

def test_backup_accept(dev, need_keypress):
    time.sleep(0.050)

    r = dev.send_recv(CCProtocolPacker.start_backup())
    assert r == None

    need_keypress('y')

    while 1:
        if dev.is_simulator:
            # work our way thru the password quiz... eventually pressing '1' will work.
            need_keypress('1')

        time.sleep(0.10)
        done = dev.send_recv(CCProtocolPacker.get_backup_file(), timeout=5000)
        if done: break

    assert len(done) == 2, done

    ll, sha = done
    assert ll > 500
    assert len(sha) == 32

    result = dev.download_file(ll, sha, file_number=0)

    assert result[0:2] == b'7z'
    assert len(set(result)) > 200

