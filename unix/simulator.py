#!/usr/bin/env python
#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Simulate the hardware of a Coldcard. Particularly the OLED display (128x32) and 
# the number pad. 
#
# This is a normal python3 program, not micropython. It communicates with a running
# instance of micropython that simulates the micropython that would be running in the main
# chip.
#
# Limitations:
# - USB light not fully implemented, because happens at irq level on real product
#
import os, sys, tty, pty, termios, time, pdb, tempfile
import subprocess
import sdl2.ext
from PIL import Image
from select import select
import fcntl
from binascii import b2a_hex, a2b_hex
from bare import BareMetal

MPY_UNIX = 'l-port/micropython'

UNIX_SOCKET_PATH = '/tmp/ckcc-simulator.sock'


class SimulatedScreen:
    # a base class

    def snapshot(self):
        fn = time.strftime('../snapshot-%j-%H%M%S.png')
        with tempfile.NamedTemporaryFile() as tmp:
            sdl2.SDL_SaveBMP(self.sprite.surface, tmp.name.encode('ascii'))
            tmp.file.seek(0)
            img = Image.open(tmp.file)
            img.save(fn)

        print("Snapshot saved: %s" % fn.split('/', 1)[1])

    def movie_start(self):
        self.movie = []
        self.last_frame = time.time() - 0.1
        print("Movie recording started.")
        self.new_frame()

    def movie_end(self):
        fn = time.strftime('../movie-%j-%H%M%S.gif')
        from PIL import Image, ImageSequence

        if not self.movie: return

        dt0, img = self.movie[0]

        img.save(fn, save_all=True, append_images=[fr for _,fr in self.movie[1:]],
                        duration=[max(dt, 20) for dt,_ in self.movie], loop=50)

        print("Movie saved: %s (%d frames)" % (fn.split('/', 1)[1], len(self.movie)))

        self.movie = None

    def new_frame(self):
        from PIL import Image

        dt = int((time.time() - self.last_frame) * 1000)
        self.last_frame = time.time()

        with tempfile.NamedTemporaryFile() as tmp:
            sdl2.SDL_SaveBMP(self.sprite.surface, tmp.name.encode('ascii'))
            tmp.file.seek(0)
            img = Image.open(tmp.file)
            img = img.convert('P')
            self.movie.append((dt, img))

class LCDSimulator(SimulatedScreen):
    pass

class OLEDSimulator(SimulatedScreen):
    # top-left coord of OLED area; size is 1:1 with real pixels... 128x64 pixels
    OLED_ACTIVE = (46, 85)

    # keypad touch buttons
    KEYPAD_LEFT = 52
    KEYPAD_TOP = 216
    KEYPAD_PITCH = 73

    background_img = 'mk4-images/background.png'

    def __init__(self, factory):
        self.movie = None

        s = factory.create_software_sprite( (128,64), bpp=32)
        self.sprite = s
        s.x, s.y = self.OLED_ACTIVE
        s.depth = 100

        self.fg = sdl2.ext.prepare_color('#ccf', s)
        self.bg = sdl2.ext.prepare_color('#111', s)
        sdl2.ext.fill(s, self.bg)

        self.mv = sdl2.ext.PixelView(self.sprite)
    
        # for genuine/caution lights and other LED's
        self.led_red = factory.from_image("mk4-images/led-red.png")
        self.led_green = factory.from_image("mk4-images/led-green.png")
        self.led_sdcard = factory.from_image("mk4-images/led-sd.png")
        self.led_usb = factory.from_image("mk4-images/led-usb.png")

    def new_contents(self, buf):
        # got bytes for new update.
        buf = buf[-1024:]       # ignore backlogs, get final state
        assert len(buf) == 1024, len(buf)

        for y in range(0, 64, 8):
            line = buf[y*128//8:]
            for x in range(128):
                val = buf[(y*128//8) + x]
                mask = 0x01
                for i in range(8):
                    self.mv[y+i][x] = self.fg if (val & mask) else self.bg
                    mask <<= 1

        if self.movie is not None:
            self.new_frame()

    def click_to_key(self, x, y):
        # take a click on image => keypad key if valid
        col = ((x - self.KEYPAD_LEFT) // self.KEYPAD_PITCH)
        row = ((y - self.KEYPAD_TOP) // self.KEYPAD_PITCH)

        #print('rc= %d,%d' % (row,col))
        if not (0 <= row < 4): return None
        if not (0 <= col < 3): return None

        return '123456789x0y'[(row*3) + col]

    def draw_leds(self, spriterenderer, active_set=0):
        # always draw SE led, since one is always on
        GEN_LED = 0x1
        SD_LED = 0x2
        USB_LED = 0x4

        spriterenderer.render(self.led_green if (active_set & GEN_LED) else self.led_red)

        if active_set & SD_LED:
            spriterenderer.render(self.led_sdcard)
        if active_set & USB_LED:
            spriterenderer.render(self.led_usb)


def start():
    print('''\nColdcard Simulator: Commands (over simulated window):
  - Control-Q to quit
  - ^Z to snapshot screen.
  - ^S/^E to start/end movie recording
  - ^N to capture NFC data (tap it)
''')
    sdl2.ext.init()
    sdl2.SDL_EnableScreenSaver()

    is_q1 = ('--q1' in sys.argv)

    factory = sdl2.ext.SpriteFactory(sdl2.ext.SOFTWARE)
    simdis = OLEDSimulator(factory)
    bg = factory.from_image(simdis.background_img)

    window = sdl2.ext.Window("Coldcard Simulator", size=bg.size, position=(100, 100))
    window.show()

    ico = factory.from_image('program-icon.png')
    sdl2.SDL_SetWindowIcon(window.window, ico.surface)

    spriterenderer = factory.create_sprite_render_system(window)

    # initial state
    spriterenderer.render(bg)
    spriterenderer.render(simdis.sprite)
    genuine_state = False
    simdis.draw_leds(spriterenderer)

    # capture exec path and move into intended working directory
    env = os.environ.copy()
    env['MICROPYPATH'] = ':' + os.path.realpath('../shared')

    display_r, display_w = os.pipe()      # fancy OLED display
    led_r, led_w = os.pipe()        # genuine LED
    numpad_r, numpad_w = os.pipe()  # keys

    # manage unix socket cleanup for client
    def sock_cleanup():
        import os
        fp = UNIX_SOCKET_PATH
        if os.path.exists(fp):
            os.remove(fp)
    sock_cleanup()
    import atexit
    atexit.register(sock_cleanup)

    # handle connection to real hardware, on command line
    # - open the serial device
    # - get buffering/non-blocking right
    # - pass in open fd numbers
    pass_fds = [display_w, numpad_r, led_w]

    if '--metal' in sys.argv:
        # bare-metal access: use a real Coldcard's bootrom+SE.
        metal_req_r, metal_req_w = os.pipe()
        metal_resp_r, metal_resp_w = os.pipe()

        bare_metal = BareMetal(metal_req_r, metal_resp_w)
        pass_fds.append(metal_req_w)
        pass_fds.append(metal_resp_r)
        metal_args = [ '--metal', str(metal_req_w), str(metal_resp_r) ]
        sys.argv.remove('--metal')
    else:
        metal_args = []
        bare_metal = None

    os.chdir('./work')
    cc_cmd = ['../coldcard-mpy', 
                        '-X', 'heapsize=9m',
                        '-i', '../sim_boot.py',
                        str(display_w), str(numpad_r), str(led_w)] \
                        + metal_args + sys.argv[1:]
    xterm = subprocess.Popen(['xterm', '-title', 'Coldcard Simulator REPL',
                                '-geom', '132x40+450+40', '-e'] + cc_cmd,
                                env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                pass_fds=pass_fds, shell=False)


    # reopen as binary streams
    display_rx = open(display_r, 'rb', closefd=0, buffering=0)
    led_rx = open(led_r, 'rb', closefd=0, buffering=0)
    numpad_tx = open(numpad_w, 'wb', closefd=0, buffering=0)

    # setup no blocking
    for r in [display_rx, led_rx]:
        fl = fcntl.fcntl(r, fcntl.F_GETFL)
        fcntl.fcntl(r, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    readables = [display_rx, led_rx]
    if bare_metal:
        readables.append(bare_metal.request)

    running = True
    pressed = set()

    def send_event(ch, is_down):
        before = len(pressed)

        if is_down:
            pressed.add(ch)
        else:
            pressed.discard(ch)

        if len(pressed) != before:
            numpad_tx.write(b''.join(pressed) + b'\n')


    while running:
        events = sdl2.ext.get_events()
        for event in events:
            if event.type == sdl2.SDL_QUIT:
                running = False
                break

            if event.type == sdl2.SDL_KEYUP or event.type == sdl2.SDL_KEYDOWN:
                try:
                    ch = chr(event.key.keysym.sym)
                    #print('0x%0x => %s  mod=0x%x'%(event.key.keysym.sym, ch, event.key.keysym.mod))
                except:
                    # things like 'shift' by itself
                    #print('0x%0x' % event.key.keysym.sym)
                    if 0x4000004f <= event.key.keysym.sym <= 0x40000052:
                        # arrow keys
                        ch = '9785'[event.key.keysym.sym - 0x4000004f]
                    else:
                        ch = '\0'

                # control+KEY
                if event.key.keysym.mod == 0x40 and event.type == sdl2.SDL_KEYDOWN:
                    if ch == 'q':
                        # control-Q
                        running = False
                        break

                    if ch == 'n':
                        # see sim_nfc.py
                        try:
                            nfc = open('nfc-dump.ndef', 'rb').read()
                            fn = time.strftime('../nfc-%j-%H%M%S.bin')
                            open(fn, 'wb').write(nfc)
                            print(f"Simulated NFC read: {len(nfc)} bytes into {fn}")
                        except FileNotFoundError:
                            print("NFC not ready")

                    if ch in 'zse':
                        if ch == 'z':
                            simdis.snapshot()
                        if ch == 's':
                            simdis.movie_start()
                        if ch == 'e':
                            simdis.movie_end()
                        continue

                    if ch == 'm':
                        # do many OK's in a row ... for word nest menu
                        for i in range(30):
                            numpad_tx.write(b'y\n')
                            numpad_tx.write(b'\n')
                        continue

                if event.key.keysym.mod == 0x40:
                    # control key releases: ignore
                    continue

                # remap ESC/Enter 
                if not is_q1:
                    if ch == '\x1b':
                        ch = 'x'
                    elif ch == '\x0d':
                        ch = 'y'

                    if ch not in '0123456789xy':
                        if ch.isprintable():
                            print("Invalid key: '%s'" % ch)
                        continue
                    
                # need this to kill key-repeat
                ch = ch.encode('ascii')
                send_event(ch, event.type == sdl2.SDL_KEYDOWN)

            if event.type == sdl2.SDL_MOUSEBUTTONDOWN:
                #print('xy = %d, %d' % (event.button.x, event.button.y))
                ch = simdis.click_to_key(event.button.x, event.button.y)
                if ch is not None:
                    send_event(ch.encode('ascii'), True)

            if event.type == sdl2.SDL_MOUSEBUTTONUP:
                for ch in list(pressed):
                    send_event(ch, False)

        rs, ws, es = select(readables, [], [], .001)
        for r in rs:

            if bare_metal and r == bare_metal.request:
                bare_metal.readable()
                continue

            # Must be bigger than a full screen update.
            buf = r.read(1024*1000)
            if not buf:
                break
        
            if r is display_rx:
                simdis.new_contents(buf)
                spriterenderer.render(simdis.sprite)
                window.refresh()
            elif r is led_rx:

                # XXX 8+8 bits
                for c in buf:
                    #print("LED change: 0x%02x" % c[0])

                    mask = (c >> 4) & 0xf
                    lset = c & 0xf

                    active_set = (mask & lset)

                    #print("Genuine LED: %r" % genuine_state)
                    spriterenderer.render(bg)
                    spriterenderer.render(simdis.sprite)
                    simdis.draw_leds(spriterenderer, active_set)

                window.refresh()
            else:
                pass

        if xterm.poll() != None:
            print("\r\n<xterm stopped: %s>\r\n" % xterm.poll())
            break

    xterm.kill()
    

if __name__ == '__main__':
    start()
