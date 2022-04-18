# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Various firmware upgrade things.
#
import pytest, os, struct, time
from sigheader import *
from ckcc_protocol.protocol import MAX_MSG_LEN, CCProtocolPacker, CCProtoError
from collections import namedtuple

Header = namedtuple('Header', FWH_PY_VALUES)
packed_len = struct.calcsize(FWH_PY_FORMAT)
assert packed_len == FW_HEADER_SIZE

def parse_hdr(hdr):
    return Header(**dict(zip(FWH_PY_VALUES.split(), struct.unpack(FWH_PY_FORMAT, hdr))))

@pytest.fixture()
def upload_file(dev):
    def doit(data, pkt_len=2048):
        
        from hashlib import sha256
        import os

        for pos in range(0, len(data), pkt_len):
            v = dev.send_recv(CCProtocolPacker.upload(pos, len(data), data[pos:pos+pkt_len]))
            assert v == pos
            chk = dev.send_recv(CCProtocolPacker.sha256())
            assert chk == sha256(data[0:pos+pkt_len]).digest(), 'bad hash'
    return doit

@pytest.fixture()
def make_firmware():
    def doit(hw_compat, fname='../stm32/firmware-signed.bin', outname='tmp-firmware.bin'):
        os.system(f'signit sign 3.0.99 --keydir ../stm32/keys -r {fname} -o {outname} --force-hw-compat=0x{hw_compat:02x}')

        rv = open(outname, 'rb').read()

        os.unlink(outname)

        return rv
    return doit

@pytest.fixture
def upgrade_by_sd(open_microsd, cap_story, pick_menu_item, goto_home, need_keypress, microsd_path, sim_exec):

    # send a firmware file over the microSD card

    def doit(data, expect_fail=None):

        fname = 'tmp-firmware'

        # stop it from reseting at end of process
        sim_exec('import machine; machine.reset = lambda:None')

        # create DFU file (wrapper)
        open(f'{fname}.bin', 'wb').write(data)
        dfu = microsd_path('tmp-firmware.dfu')
        cmd = f'../external/micropython/tools/dfu.py -b 0x08008000:{fname}.bin {dfu}'
        print(cmd)
        os.system(cmd)

        goto_home()
        pick_menu_item('Advanced/Tools')
        pick_menu_item('Upgrade')
        pick_menu_item('From MicroSD')

        time.sleep(.1)
        _, story = cap_story()
        assert 'Pick firmware image to use' in story
        need_keypress('y')
        time.sleep(.1)
            
        pick_menu_item(os.path.basename(dfu))

        if expect_fail:
            time.sleep(2)
            title, story = cap_story()
            assert title == 'Sorry!'
            assert expect_fail in story

    return doit


@pytest.mark.parametrize('mode', ['nocheck', 'compat', 'incompat'])
@pytest.mark.parametrize('transport', ['sd', 'usb'])
def test_hacky_upgrade(mode, transport, dev, sim_exec, make_firmware, upload_file, sim_eval, upgrade_by_sd):

    # manually: run this test on all Mark1 thru 3 simulators
    hw_label = eval(sim_eval('version.hw_label'))
    assert hw_label[0:2] == 'mk'
    mkn = int(hw_label[2])

    print(f"Simulator is {hw_label}")

    if mode == 'nocheck':
        data = make_firmware(0x00)
    elif mode == 'compat':
        data = make_firmware(1 << (mkn-1))
    elif mode == 'incompat':
        data = make_firmware(0xf ^ (1 << (mkn-1)))

    hdr = data[FW_HEADER_OFFSET:FW_HEADER_OFFSET+FW_HEADER_SIZE]

    cooked = parse_hdr(hdr)
    #print(cooked)
    assert cooked.magic_value == FW_HEADER_MAGIC
    assert cooked.firmware_length == len(data)

    if mode == 'incompat':
        if transport == 'usb':
            with pytest.raises(CCProtoError) as ee:
                upload_file(data + hdr)
            assert "doesn't support this version of Coldcard" in str(ee)
        else:
            upgrade_by_sd(data, expect_fail="doesn't support this version of Coldcard")

        return

    # file should be accepted
    if transport == 'usb':
        upload_file(data + hdr)
    else:
        upgrade_by_sd(data)

    # check data was uploaded verbatim (VERY SLOW)
    for pos in range(0, cooked.firmware_length + 128, 128):
        a = eval(sim_eval(f'SF.array[{pos}:{pos+128}]'))
        if pos in [ FW_HEADER_OFFSET, cooked.firmware_length]:
            assert a == hdr, f"wrong @ {pos}"
        else:
            assert a == data[pos:pos+128], repr(pos)
    

# EOF
