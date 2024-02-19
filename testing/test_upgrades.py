# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Various firmware upgrade things.
#
import pytest, os, struct, time, hashlib, subprocess
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
        for pos in range(0, len(data), pkt_len):
            v = dev.send_recv(CCProtocolPacker.upload(pos, len(data), data[pos:pos+pkt_len]))
            assert v == pos
            chk = dev.send_recv(CCProtocolPacker.sha256())
            assert chk == hashlib.sha256(data[0:pos+pkt_len]).digest(), 'bad hash'
    return doit

@pytest.fixture
def make_firmware():
    def doit(hw_compat, fname='../stm32/firmware-signed.bin', outname='tmp-firmware.bin'):
        # os.system(f'signit sign 3.0.99 --keydir ../stm32/keys -r {fname} -o {outname} --hw-compat=0x{hw_compat:02x}')
        p = subprocess.run(
            [
                'signit', 'sign', '3.0.99',
                 '--keydir', '../stm32/keys',
                 '-r', f'{fname}',
                 '-o', f'{outname}',
                 f'--hw-compat={hw_compat}'
            ],
            capture_output=True,
            text=True,
        )
        if p.stderr:
            raise RuntimeError(p.stderr)

        rv = open(outname, 'rb').read()

        os.unlink(outname)

        return rv
    return doit

@pytest.fixture
def upgrade_by_sd(open_microsd, cap_story, pick_menu_item, goto_home, press_select, microsd_path, sim_exec):

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
        try:
            pick_menu_item('Upgrade')
        except KeyError:
            pick_menu_item('Upgrade Firmware')
        pick_menu_item('From MicroSD')

        time.sleep(.1)
            
        pick_menu_item(os.path.basename(dfu))

        if expect_fail:
            time.sleep(2)
            title, story = cap_story()
            assert title == 'Sorry!'
            assert expect_fail in story

    return doit


@pytest.mark.parametrize('mode', ['compat', 'incompat'])
@pytest.mark.parametrize('transport', ['sd', 'usb'])
def test_hacky_upgrade(mode, cap_story, transport, dev, sim_exec, make_firmware, upload_file, sim_eval, upgrade_by_sd):

    # manually: run this test on all Mark1 thru 3 simulators
    hw_label = eval(sim_eval('version.hw_label'))
    assert hw_label[0:2] in ['mk', 'q1']
    try:
        mkn = int(hw_label[2])
    except IndexError:
        mkn = "q1"  # q1

    print(f"Simulator is {hw_label}")

    if mode == 'compat':
        data = make_firmware(mkn)
    elif mode == 'incompat':
        with pytest.raises(RuntimeError) as err:
            if mkn == "q1":
                mkn = 4

            make_firmware(mkn-1)
        assert "too big for our USB upgrades" in str(err)
        return

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

    _, story = cap_story()
    assert "Install this new firmware?" in story
    # check data was uploaded verbatim (VERY SLOW)
    # for pos in range(0, cooked.firmware_length + 128, 128):
    #     to_eval = f'from sflash import SF;SF.array[{pos}:{pos+128}]'
    #     x = sim_exec(to_eval)
    #     a = eval(x)
    #     if pos in [ FW_HEADER_OFFSET, cooked.firmware_length]:
    #         assert a == hdr, f"wrong @ {pos}"
    #     else:
    #         assert a == data[pos:pos+128], repr(pos)
    

# EOF
