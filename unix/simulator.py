#!/usr/bin/env python
#
# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Simulate the hardware of a Coldcard. Particularly the OLED display (128x32) and 
# the numberpad. 
#
# This is a normal python3 program, not micropython. It communicates with a running
# instance of micropython that simulates the micropython that would be running in the main
# chip.
#
import os, sys, tty, pty, termios, time, pdb, tempfile
import subprocess
import sdl2.ext
from PIL import Image
from select import select
import fcntl
from binascii import b2a_hex, a2b_hex

MPY_UNIX = 'l-port/micropython'

UNIX_SOCKET_PATH = '/tmp/ckcc-simulator.sock'

# top-left coord of OLED area; size is 1:1 with real pixels... 128x64 pixels
OLED_ACTIVE = (50, 78)

# keypad touch buttons
KEYPAD_LEFT = 52
KEYPAD_TOP = 216
KEYPAD_PITCH = 73


class OLEDSimulator:

    def __init__(self, factory):
        self.movie = None

        s = factory.create_software_sprite( (128,64), bpp=32)
        self.sprite = s
        s.x, s.y = OLED_ACTIVE
        s.depth = 100

        self.fg = sdl2.ext.prepare_color('#ccf', s)
        self.bg = sdl2.ext.prepare_color('#111', s)
        sdl2.ext.fill(s, self.bg)

        self.mv = sdl2.ext.PixelView(self.sprite)

    def render(self, window, buf):
        # take a full-screen update of the OLED contents and display
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
    

def start():
    print('''\nColdcard Simulator: Commands (over simulated window):
  - Control-Q to quit
  - Z to snapshot screen.
  - S/E to start/end movie recording
''')
    sdl2.ext.init()

    factory = sdl2.ext.SpriteFactory(sdl2.ext.SOFTWARE)
    bg = factory.from_image("background.png")
    oled = OLEDSimulator(factory)
    
    # for genuine/caution lights
    led_red = factory.from_image("led-red.png")
    led_green = factory.from_image("led-green.png")
    led_sdcard = factory.from_image("led-sd.png")

    window = sdl2.ext.Window("Coldcard Simulator", size=bg.size, position=(100, 100))
    window.show()

    ico = factory.from_image('program-icon.png')
    sdl2.SDL_SetWindowIcon(window.window, ico.surface)

    spriterenderer = factory.create_sprite_render_system(window)

    spriterenderer.render(bg)
    spriterenderer.render(oled.sprite)
    spriterenderer.render(led_red)
    genuine_state = False
    sd_active = False

    # capture exec path and move into intended working directory
    mpy_exec = os.path.realpath('l-port/coldcard-mpy')
    env = os.environ.copy()
    env['MICROPYPATH'] = ':' + os.path.realpath('../shared')


    oled_r, oled_w = os.pipe()      # fancy OLED display
    led_r, led_w = os.pipe()        # genuine LED
    numpad_r, numpad_w = os.pipe()  # keys

    # manage unix socket cleanup for client
    try:
        os.unlink('/tmp/ckcc-simulator.sock')
    except: pass
    import atexit
    atexit.register(os.unlink, '/tmp/ckcc-simulator.sock')

    os.chdir('./work')
    cc_cmd = ['../coldcard-mpy', '-i', '../sim_boot.py',
                        str(oled_w), str(numpad_r), str(led_w)] \
                        + sys.argv[1:]
    xterm = subprocess.Popen(['xterm', '-title', 'Coldcard Simulator REPL',
                                '-geom', '132x40+450+40', '-e'] + cc_cmd,
                                env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                pass_fds=[oled_w, numpad_r, led_w], shell=False)


    # reopen as binary streams
    oled_rx = open(oled_r, 'rb', closefd=0, buffering=0)
    led_rx = open(led_r, 'rb', closefd=0, buffering=0)
    numpad_tx = open(numpad_w, 'wb', closefd=0, buffering=0)

    # setup no blocking
    for r in [oled_rx, led_rx]:
        fl = fcntl.fcntl(r, fcntl.F_GETFL)
        fcntl.fcntl(r, fcntl.F_SETFL, fl | os.O_NONBLOCK)

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

                # remap ESC/Enter 
                if ch == '\x1b':
                    ch = 'x'
                elif ch == '\x0d':
                    ch = 'y'

                if ch == 'q' and event.key.keysym.mod == 0x40:
                    # control-Q
                    running = False
                    break

                if ch in 'zse':
                    if event.type == sdl2.SDL_KEYDOWN:
                        if ch == 'z':
                            oled.snapshot()
                        if ch == 's':
                            oled.movie_start()
                        if ch == 'e':
                            oled.movie_end()
                    continue

                if ch not in '0123456789xy':
                    if ch.isprintable():
                        print("Invalid key: '%s'" % ch)
                    continue
                
                # need this to kill key-repeat

                ch = ch.encode('ascii')
                send_event(ch, event.type == sdl2.SDL_KEYDOWN)

            if event.type == sdl2.SDL_MOUSEBUTTONDOWN:
                #print('xy = %d, %d' % (event.button.x, event.button.y))
                col = ((event.button.x - KEYPAD_LEFT) // KEYPAD_PITCH)
                row = ((event.button.y - KEYPAD_TOP) // KEYPAD_PITCH)
                #print('rc= %d,%d' % (row,col))
                if not (0 <= row < 4): continue
                if not (0 <= col < 3): continue
                ch = '123456789x0y'[(row*3) + col]
                send_event(ch.encode('ascii'), True)

            if event.type == sdl2.SDL_MOUSEBUTTONUP:
                for ch in list(pressed):
                    send_event(ch, False)

        rs, ws, es = select([oled_rx, led_rx], [], [], .001)
        for r in rs:

            # Cheating: 1024 is size of OLED update, don't change.
            c = r.read(1024*1000)
            if not c:
                break
        
            if r is oled_rx:
                c = c[-1024:]
                oled.render(window, c)
                spriterenderer.render(oled.sprite)
                window.refresh()
            elif r is led_rx:
                assert len(c) == 1, repr(c)
                #print("LED change: 0x%02x" % c[0])

                mask = (c[0] >> 4) & 0xf
                lset = c[0] & 0xf
                GEN_LED = 0x1
                SD_LED = 0x2

                if mask & GEN_LED:
                    genuine_state = ((mask & lset) == GEN_LED)
                if mask & SD_LED:
                    sd_active = ((mask & lset) == SD_LED)

                #print("Genuine LED: %r" % genuine_state)
                spriterenderer.render(bg)
                spriterenderer.render(oled.sprite)
                spriterenderer.render(led_green if genuine_state else led_red)
                if sd_active:
                    spriterenderer.render(led_sdcard)

                window.refresh()
            else:
                pass

        if xterm.poll() != None:
            print("\r\n<xterm stopped: %s>\r\n" % xterm.poll())
            break

    xterm.kill()
    

if __name__ == '__main__':
    start()
