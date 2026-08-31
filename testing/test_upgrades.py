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

@pytest.fixture
def upload_file(dev):
    def doit(data, pkt_len=2048):
        for pos in range(0, len(data), pkt_len):
            v = dev.send_recv(CCProtocolPacker.upload(pos, len(data), data[pos:pos+pkt_len]))
            assert v == pos
            chk = dev.send_recv(CCProtocolPacker.sha256())
            assert chk == hashlib.sha256(data[0:pos+pkt_len]).digest(), 'bad hash'
    return doit

@pytest.fixture
def make_firmware(src_root_dir):
    def doit(hw_compat, fname=f'{src_root_dir}/stm32/firmware-signed.bin',
             outname='tmp-firmware.bin', version='3.0.99'):
        # os.system(f'signit sign 3.0.99 --keydir ../stm32/keys -r {fname} -o {outname} --hw-compat=0x{hw_compat:02x}')
        p = subprocess.run(
            [
                'signit', 'sign', version,
                 '--keydir', f'{src_root_dir}/stm32/keys',
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
def upgrade_by_sd(open_microsd, cap_story, pick_menu_item, goto_home, press_select, microsd_path, sim_exec, src_root_dir):

    # send a firmware file over the microSD card

    def doit(data, expect_fail=None):

        fname = 'tmp-firmware'

        # stop it from reseting at end of process
        sim_exec('import machine; machine.reset = lambda:None')

        # create DFU file (wrapper)
        open(f'{fname}.bin', 'wb').write(data)
        dfu = microsd_path('tmp-firmware.dfu')
        cmd = f'{src_root_dir}/external/micropython/tools/dfu.py -b 0x08008000:{fname}.bin {dfu}'
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
def test_hacky_upgrade(mode, cap_story, transport, dev, sim_exec, make_firmware, upload_file,
                       upgrade_by_sd, press_cancel, is_q1, is_mark5):

    if mode == 'compat':
        data = make_firmware("q1" if is_q1 else (5 if is_mark5 else 4))
    elif mode == 'incompat':
        data = make_firmware(4 if is_q1 else "q1")

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
    press_cancel()
    # check data was uploaded verbatim (VERY SLOW)
    # for pos in range(0, cooked.firmware_length + 128, 128):
    #     to_eval = f'from sflash import SF;SF.array[{pos}:{pos+128}]'
    #     x = sim_exec(to_eval)
    #     a = eval(x)
    #     if pos in [ FW_HEADER_OFFSET, cooked.firmware_length]:
    #         assert a == hdr, f"wrong @ {pos}"
    #     else:
    #         assert a == data[pos:pos+128], repr(pos)


def test_upgrade_staged_image_tamper(make_firmware, upload_file, cap_story,
                                     press_select, sim_exec, sim_eval, is_q1, is_mark5):
    # a second upload may land while the upgrade approval is on screen
    # (check_busy allow-lists FirmwareUpgradeRequest); the staged bytes
    # must be re-verified before flashing, not just the header snapshot
    hw = "q1" if is_q1 else (5 if is_mark5 else 4)
    data_a = make_firmware(hw, version='3.0.98')
    hdr_a = data_a[FW_HEADER_OFFSET:FW_HEADER_OFFSET+FW_HEADER_SIZE]

    sim_exec("import glob; from pincodes import pa; "
             "glob._fw_upgrade = pa.firmware_upgrade; "
             "glob._fw_upgrade_called = False; "
             "pa.firmware_upgrade = lambda *a: setattr(glob, '_fw_upgrade_called', True)")

    # upload image A with trailer -> fires authorize_upgrade
    upload_file(data_a + hdr_a)

    # upload image B as a raw image (no trailer) -> no re-auth, but
    # overwrites the staging area via PSRAM.write
    data_b = make_firmware(hw, outname='tmp-firmware-b.bin', version='3.0.99')
    assert len(data_b) == len(data_a)
    assert data_b != data_a
    upload_file(data_b)

    _, story = cap_story()
    assert "Install this new firmware?" in story
    assert "3.0.98" in story

    try:
        press_select()
        time.sleep(1)
        assert sim_eval("glob._fw_upgrade_called") == 'False'
    finally:
        sim_exec("from pincodes import pa; import glob; "
                 "pa.firmware_upgrade = glob._fw_upgrade")


# EOF
