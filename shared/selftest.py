# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# selftest.py - Interactive Selftest code
#
import ckcc
from uasyncio import sleep_ms
from glob import dis, settings
from ux import ux_wait_keydown, ux_clear_keys, ux_poll_key
from ux import ux_show_story
from callgate import get_is_bricked, get_genuine, clear_genuine
from utils import problem_file_line
import version
from charcodes import KEY_ENTER, KEY_CANCEL, KEY_QR

try:
    from display import FontLarge
except ImportError:
    FontLarge = None

async def wait_ok():
    k = await ux_wait_keydown('xy' + KEY_ENTER + KEY_CANCEL)
    if k not in 'y' + KEY_ENTER:
        raise RuntimeError('Canceled')

def label_test(line1, line2=''):
    dis.clear()
    if version.has_qwerty:
        dis.text(None, 1, line1)
        dis.text(None, 3, line2)
    else:
        dis.text(None, 10, line1)
        dis.text(None, 34, line2, font=FontLarge)
    dis.show()

async def test_numpad():
    # do an interactive self test

    keys = list('123456789x0y')

    for ch in keys:
        dis.clear()
        dis.text(0,0, "Numpad Test. Press:")
        dis.text(None,24, ch if ch != 'y' else 'OK', FontLarge)
        dis.show()

        k = await ux_wait_keydown(ch + 'x')
        if k == 'x' and ch != 'x':
            raise RuntimeError("numpad test aborted")
        assert k == ch

async def test_gpu():
    import gpu_binary

    try:
        dis.gpu.take_spi()
        dis.clear()
        dis.text(0,-1, "GPU Test okay?")
        dis.show()

        assert dis.gpu.get_version() == gpu_binary.VERSION
        dis.bootrom_takeover()
        dis.gpu.show_test_pattern()

        await wait_ok()
    finally:
        # not required?
        dis.real_clear()

async def test_keyboard():
    # for Q1 - just some of them: one in each row and column

    keys = list('1wdvgy7k.p '+KEY_QR)
    
    for ch in keys:
        dis.clear()
        dis.text(None,2, "Keyboard Test. Press:")
        dis.text(None,4, 'SPACE' if ch == ' ' else ch.upper())
        dis.show()

        k = await ux_wait_keydown(ch + KEY_CANCEL)
        if k == KEY_CANCEL:
            raise RuntimeError("kbd test aborted")
        assert k == ch

async def test_qr_scanner():
    # QR Scanner module: assume pretested, just testing connection really
    from glob import SCAN

    # Can take 2+ seconds to setup the QR scanner (from powerup), and
    # if batteries are right, we can hit that timeframe in factory test case.
    for i in range(25):
        if SCAN.setup_done:
            break
        await sleep_ms(100)

    assert SCAN and SCAN.version and SCAN.version.startswith('V2.3.'), 'QR Scanner Missing'

async def test_battery():
    from battery import get_batt_level

    try:
        from machine import ADC
        # expect 11500 or so, and certainly not 65535
        assert max(ADC(ADC.CORE_VREF).read_u16() for i in range(10)) < 60000, 'VREF fix not done'
    except ImportError:
        # simulator
        pass

    dis.clear()
    dis.text(None, 1, "Battery Test")
    dis.text(None, 3, "Connect 3.3v reference cells.")

    while 1:
        lvl = get_batt_level()

        if lvl and 3.2 <= lvl <= 3.4:
            # pass
            return 

        if lvl:
            dis.text(None, -1, "VIN Sense reads: %.1f volts" % lvl, dark=True)
        else:
            dis.text(None, -1, "Remove USB plug.", dark=True)
        dis.show()

        if settings.get('tested', False):
            # auto-pass this test if we've been thru here before; customer may
            # not have magic batteries and so on.
            break

        # show for 100ms or until they press key
        ch = await ux_wait_keydown(KEY_CANCEL+'s', 100)
        if not ch: continue

        if ch == 's':
            # undocumented: 'skip'
            return
        elif ch == KEY_CANCEL:
            raise RuntimeError("Battery test aborted")
        else:
            raise ValueError(ch)

def set_genuine():
    # PIN must be blank for this to work
    # - or logged in already as main
    from pincodes import pa

    if not pa.is_successful():
        # assume blank pin during factory selftest
        pa.setup(b'')

        if not pa.is_successful():
            pa.login()
            assert pa.is_successful()       # "PIN not blank?"

    # do verify step
    dis.bootrom_takeover()
    pa.greenlight_firmware()

    dis.show()

async def test_secure_element():

    assert not get_is_bricked()         # bricked already

    if ckcc.is_simulator(): return

    for ph in range(5):
        gg = get_genuine()

        dis.clear()

        if version.has_qwerty:
            dis.text(0, 0, "^^-- Green?      " if gg else "   ^^-- Red?")
        else:
            if gg:
                dis.text(-1, 8, "Green ON? -->")
            else:
                dis.text(-1,50, "Red ON? -->")

        dis.show()
        await wait_ok()

        if ph and gg:
            # stop once it's on and we've tested both states
            return

        # attempt to switch to other state
        if gg:
            clear_genuine()
        else:
            # very slow!
            dis.fullscreen("Wait...")
            set_genuine()
            ux_clear_keys()

        ng = get_genuine()
        assert ng != gg     # "Could not invert LED"
            
async def test_sd_active():
    # Mark 2+: SD Card active light.
    # Q1: dual slots
    from machine import Pin

    for num in range(version.num_sd_slots):

        led = Pin('SD_ACTIVE' if not num else 'SD_ACTIVE2', Pin.OUT)

        for ph in range(2):
            gg = not ph
            led.value(gg)

            dis.clear()
            if version.has_qwerty:
                if num == 0:
                    dis.text(0, 2, "<-- SD A is %s?  " % ('ON' if gg else 'off'))
                else:
                    dis.text(0, 7, "<-- SD B is %s?  " % ('ON' if gg else 'off'))
            else:
                if gg:
                    dis.text(0,16, "<-- Green ON?")
                else:
                    dis.text(0,16, "<-- Green off?")
            dis.show()

            await wait_ok()

async def test_usb_light():
    # Mk4's new USB activity light (right by connector)
    from machine import Pin
    p = Pin('USB_ACTIVE', Pin.OUT)

    try:
        p.value(1)
        label_test("USB light is on?")

        await wait_ok()
    finally:
        p.value(0)

async def test_nfc_light():
    if not version.has_qwerty:
        return

    from machine import Pin
    p = Pin('NFC_ACTIVE', Pin.OUT)

    try:
        p.value(1)
        dis.clear()
        dis.text(-1, -1, "NFC light green? --->")
        dis.show()

        await wait_ok()
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

    label_test('PSRAM Test')

    test_len = PSRAM.length * 2
    chk = bytearray(32)
    spots = []
    for pos in range(0, PSRAM.length, 4000 * 17):
        if pos >= PSRAM.length: break
        rnd = ngu.hash.sha256s(pack('I', pos))

        PSRAM.write(pos, rnd)
        PSRAM.read(pos, chk)
        assert chk == rnd, "bad @ 0x%x" % pos
        dis.progress_bar_show(pos / test_len)
        spots.append(pos)

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

        await wait_ok()

async def test_lcd():
    # Very basic
    try:
        for nm, col in [('RED', 0xf800), ('GREEN', 0x07e0), ('BLUE', 0x001f)]:
            dis.real_clear()
            dis.dis.fill_screen(col)
            dis.text(1,1, "Selftest")
            dis.text(None,3, "All pixels are %s?" % nm)
            dis.show()

            await wait_ok()
    finally:
        dis.real_clear()
        dis.draw_status(full=1)
        dis.clear()

async def test_microsd():
    if ckcc.is_simulator(): return
    from version import num_sd_slots
    from files import CardSlot
    import os

    async def wait_til_state(num, want):
        title = 'MicroSD Card'
        if num_sd_slots > 1:
            title += ' ' + chr(65+num)
        label_test(title +':', 'Remove' if CardSlot.is_inserted() else 'Insert')

        while 1:
            if want == CardSlot.is_inserted(): return
            await sleep_ms(100)
            if ux_poll_key():
                raise RuntimeError("MicroSD test aborted")

    for slot_num in range(num_sd_slots):
        # test presence switch
        for ph in range(7):
            await wait_til_state(slot_num, not CardSlot.is_inserted())

            if ph >= 2 and CardSlot.is_inserted():
                # debounce
                await sleep_ms(100)
                if CardSlot.is_inserted(): break
                if ux_poll_key():
                    raise RuntimeError("MicroSD test aborted")

        label_test('MicroSD Card:', 'Testing')

        # card inserted
        assert CardSlot.is_inserted()     #, "SD not present?"

        with CardSlot(slot_b=slot_num) as card:

            _, fn = card.pick_filename('test-delme.txt')

            with open(fn, 'wt') as fd:
                fd.write("Hello")
            with open(fn, 'rt') as fd:
                assert fd.read() == "Hello"

            os.unlink(fn)

        # force removal, so cards don't get stuck in finished units
        await wait_til_state(slot_num, False)



async def start_selftest():

    try:
        if version.has_battery:
            await test_battery()

        if version.has_qr:
            await test_qr_scanner()

        if not version.has_qwerty:
            await test_oled()
        else:
            await test_lcd()
            await test_gpu()

        await test_psram()
        await test_nfc_light()
        await test_nfc()

        if version.has_qwerty:
            await test_keyboard()
        else:
            await test_numpad()

        await test_secure_element()
        await test_sd_active()
        await test_usb_light()
        await test_microsd()

        # add more tests here

        settings.set('tested', True)
        await ux_show_story("Selftest complete", 'PASS')

    except (RuntimeError, AssertionError) as e:
        e = str(e) or problem_file_line(e)
        await ux_show_story("Test failed:\n" + str(e), 'FAIL')
        
    
# EOF
