# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Tests that need a person there... mostly when not run on simulator
# - with mk4 these are unattended
#
import time, pytest
from ckcc_protocol.protocol import CCProtocolPacker, CCUserRefused


@pytest.fixture
def bkpw(settings_set):
    def doit(pwd=None, blank=False):
        if pwd is None and blank is False:
            # random
            pwd = 'charge bottom tired when romance blind treat afford bus salute degree anchor'

        if pwd:
            settings_set("bkpw", pwd)
        else:
            settings_set("bkpw", None)
    return doit


@pytest.mark.parametrize("last_saved", [True, False])
def test_backup_refuse(last_saved, dev, press_cancel, bkpw):
    time.sleep(0.050)

    if last_saved:
        bkpw()
    else:
        bkpw(blank=True)

    r = dev.send_recv(CCProtocolPacker.start_backup())
    assert r is None

    if last_saved:
        press_cancel()
    press_cancel()

    with pytest.raises(CCUserRefused):
        done = None
        while done is None:
            time.sleep(0.050)
            done = dev.send_recv(CCProtocolPacker.get_backup_file())


@pytest.mark.parametrize("last_saved", [True, False])
def test_backup_accept(last_saved, dev, need_keypress, press_select, bkpw):
    time.sleep(0.050)
    if last_saved:
        bkpw()
    else:
        bkpw(blank=True)
    r = dev.send_recv(CCProtocolPacker.start_backup())
    assert r is None

    press_select()
    if last_saved:
        time.sleep(1)  # needed
        done = dev.send_recv(CCProtocolPacker.get_backup_file(), timeout=5000)
        assert done
    else:
        while 1:
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

