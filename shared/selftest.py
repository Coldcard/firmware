# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# selftest.py - Interactive Selftest code
#
import ckcc
from uasyncio import sleep_ms
from glob import dis
from display import FontLarge
from ux import ux_wait_keyup, ux_clear_keys, ux_poll_key
from ux import ux_show_story
from callgate import get_is_bricked, get_genuine, clear_genuine
from utils import problem_file_line
import version
from glob import settings

async def test_numpad():
    # do an interactive self test

    keys = list('123456789x0y')

    for ch in keys:
        dis.clear()
        dis.text(0,0, "Numpad Test. Press:")
        dis.text(None,24, ch if ch != 'y' else 'OK', FontLarge)
        dis.show()

        k = await ux_wait_keyup(ch + 'x')
        if k == 'x' and ch != 'x':
            raise RuntimeError("numpad test aborted")
        assert k == ch

def set_genuine():
    # PIN must be blank for this to work
    # - or logged in already as main
    from pincodes import pa

    if pa.is_secondary:
        return

    if not pa.is_successful():
        # assume blank pin during factory selftest
        pa.setup(b'')
        assert not pa.is_delay_needed()     # "PIN failures?"

        if not pa.is_successful():
            pa.login()
            assert pa.is_successful()       # "PIN not blank?"

    # do verify step
    pa.greenlight_firmware()

    dis.show()

async def test_secure_element():

    assert not get_is_bricked()         # bricked already

    # test right chips installed
    assert version.has_608          # expect 608

    if ckcc.is_simulator(): return

    for ph in range(5):
        gg = get_genuine()

        dis.clear()
        if gg:
            dis.text(-1, 8, "Green ON? -->")
        else:
            dis.text(-1,50, "Red ON? -->")

        dis.show()
        k = await ux_wait_keyup('xy')
        assert k == 'y'     # "LED bust"

        if ph and gg:
            # stop once it's on and we've tested both states
            return

        # attempt to switch to other state
        if gg:
            clear_genuine()
        else:
            # very slow!
            dis.text(0,0, "Wait")
            dis.show()
            set_genuine()
            ux_clear_keys()

        ng = get_genuine()
        assert ng != gg     # "Could not invert LED"
            
async def test_sd_active():
    # Mark 2: SD Card active light.
    from machine import Pin
    led = Pin('SD_ACTIVE', Pin.OUT)

    for ph in range(2):
        gg = not ph
        led.value(gg)

        dis.clear()
        if gg:
            dis.text(0,16, "<-- Green ON?")
        else:
            dis.text(0,16, "<-- Green off?")

        dis.show()
        k = await ux_wait_keyup('xy')
        assert k == 'y'     # "SD Active LED bust"

async def test_usb_light():
    # Mk4's new USB activity light (right by connector)
    from machine import Pin
    p = Pin('USB_ACTIVE', Pin.OUT)

    try:
        p.value(1)
        dis.clear()
        dis.text(0,0, "USB light on? ^^")
        dis.show()

        k = await ux_wait_keyup('xy')
        assert k == 'y'     # "USB Active LED bust"
    finally:
        p.value(0)

async def test_nfc():
    # Mk4: NFC chip and field
    if not version.has_nfc: return
    from nfc import NFCHandler
    await NFCHandler.selftest()
    
async def test_psram():
    from glob import PSRAM
    from ustruct import pack
    import ngu

    dis.clear()
    dis.text(None, 18, 'PSRAM Test')
    dis.show()

    test_len = PSRAM.length * 2
    chk = bytearray(32)
    spots = set()
    for pos in range(0, PSRAM.length, 800 * 17):
        if pos >= PSRAM.length: break
        rnd = ngu.hash.sha256s(pack('I', pos))

        PSRAM.write(pos, rnd)
        PSRAM.read(pos, chk)
        assert chk == rnd, "bad @ 0x%x" % pos
        dis.progress_bar_show(pos / test_len)
        spots.add(pos)

    for pos in spots:
        rnd = ngu.hash.sha256s(pack('I', pos))
        PSRAM.read(pos, chk)
        assert chk == rnd, "RB bad @ 0x%x" % pos
        dis.progress_bar_show((PSRAM.length + pos) / test_len)


async def test_oled():
    # all on/off tests
    for ph in (1, 0):
        dis.clear()
        dis.dis.fill(ph)
        dis.text(None,2, "Selftest", invert=ph)
        dis.text(None,30, "All on?" if ph else 'All off?', invert=ph, font=FontLarge)
        dis.show()

        ch = await ux_wait_keyup('yx')
        if ch != 'y':
            raise RuntimeError("OLED test aborted")

async def test_microsd():
    if ckcc.is_simulator(): return

    async def wait_til_state(want):
        dis.clear()
        dis.text(None, 10, 'MicroSD Card:')
        dis.text(None, 34, 'Remove' if sd.present() else 'Insert', font=FontLarge)
        dis.show()

        while 1:
            if want == sd.present(): return
            await sleep_ms(100)
            if ux_poll_key():
                raise RuntimeError("MicroSD test aborted")

    try:
        import pyb
        sd = pyb.SDCard()
        sd.power(0)

        # test presence switch
        for ph in range(7):
            await wait_til_state(not sd.present())

            if ph >= 2 and sd.present():
                # debounce
                await sleep_ms(100)
                if sd.present(): break
                if ux_poll_key():
                    raise RuntimeError("MicroSD test aborted")

        dis.clear()
        dis.text(None, 10, 'MicroSD Card:')
        dis.text(None, 34, 'Testing', font=FontLarge)
        dis.show()

        # card inserted
        assert sd.present()     #, "SD not present?"

        # power up?
        await sleep_ms(100)     # required
        ok = sd.power(1)
        assert ok               #  "sd.power() fail"
        await sleep_ms(100)     # prob'ly not required

        try:
            blks, bsize, *unused = sd.info()
            assert bsize == 512
        except:
            # sd.info() returns None if problem
            assert 0        # , "card info"

        # just read it a bit, writing would prove little
        buf = bytearray(512)
        msize = 256*1024
        for addr in range(0, msize, 1024):
            sd.readblocks(addr, buf)
            dis.progress_bar_show(addr/msize)

            if addr == 0:
                assert buf[-2:] == b'\x55\xaa'      # "Bad read"

        # force removal, so cards don't get stuck in finished units
        await wait_til_state(False)

    finally:
        # CRTICAL: power it back down
        sd.power(0)


async def start_selftest():

    try:
        await test_oled()
        await test_psram()
        await test_nfc()
        await test_microsd()
        await test_numpad()
        await test_secure_element()
        await test_sd_active()
        await test_usb_light()

        # add more tests here

        settings.set('tested', True)
        await ux_show_story("Selftest complete", 'PASS')

    except (RuntimeError, AssertionError) as e:
        e = str(e) or problem_file_line(e)
        await ux_show_story("Test failed:\n" + str(e), 'FAIL')
        
    
# EOF
