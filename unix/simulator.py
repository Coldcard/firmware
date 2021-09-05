#!/usr/bin/env python3
#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
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
from binascii import b2a_hex, a2b_hex
from select import select
import fcntl
import sdl2.ext
from PIL import Image

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

class BareMetal:
    #
    # Use a real Coldcard device's bootrom and SE
    #
    def __init__(self, req_r, resp_w):
        self.open()
        self.request = open(req_r, 'rt', closefd=0)
        self.response = open(resp_w, 'wb', closefd=0, buffering=0)

    def open(self):
        # return a file-descriptor ready to be used for access to a real Coldcard's console I/O.
        # - assume only one coldcard
        import sys, serial
        from serial.tools.list_ports import comports

        for d in comports():
            if d.pid != 0xcc10: continue
            sio = serial.Serial(d.device, write_timeout=1)

            print("Connecting to: %s" % d.device)
            break
        else:
            raise RuntimeError("Can't find usb serial port for real Coldcard")

        self.sio = sio
        sio.timeout = 0.250
        greet = sio.readlines()
        if greet and b'Welcome to Coldcard!' in greet[1]:
            sio.write(b'\x03')     # ctrl-C
            while 1:
                sio.timeout = 1
                lns = sio.readlines()
                if not lns: break

        # hit enter, expect prompt
        sio.timeout = 0.100
        sio.write(b'\r')
        ln = sio.readlines()
        #assert ln[-1] == b'>>> ', ln
        #assert ln[-1] == b'=== ', ln
        assert ln[-1] in {b'>>> ',  b'=== '}, ln         #ok if in paste mode

        print(" Connected to: %s" % d.device)

        sio.write(b'''\x05\
from main import dis
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
import ckcc
dis.fullscreen("BareMetal")
try:
 busy = dis.busy_bar
except:
 busy = lambda x: None
\x04'''.replace(b'\n', b'\r'))

        # above is quick but will be echoed, so clear it out
        lns = self.wait_done()
        #print(f"setup: {lns}")


    def read_sflash(self):
        # capture contents of SPI flash (settings area only: last 128k)
        # XXX not working
        self.sio.write(b'''\x05\
busy(1)
from main import sf
dis.fullscreen("SPI Flash")
buf = bytearray(256)
addr = 0xe0000
for i in range(0, 0x20000, 256):
    sf.read(addr+i, buf)
    print(b2a_hex(buf).decode())
busy(0)
dis.fullscreen("BareMetal")
\x04\r'''.replace(b'\n', b'\r'))

        count = 0
        self.sio.timeout = 0.5
        for ln in self.sio.readlines():
            ln = ln.decode('ascii')
            if len(ln) == 512 + 2:
                self.response.write(ln[:-2].encode('ascii') + b'\n')
                count += 1
            elif ln.startswith('>>> '):
                break
            elif not ln or not ln.strip() or ln.startswith('=== ') or 'paste mode' in ln:
                pass
            else:
                print(f'junk: {ln}')

        assert count == (128*1024)//256, count

        print("Sent real SPI Flash contents to simulated Coldcard.")

    def wait_done(self, timeout=1):
        sio = self.sio
        sio.timeout = timeout
        rv = sio.read_until(terminator='>>> ')
        return [str(i, 'ascii') for i in rv.split(b'\r\n')]

    def readable(self):
        # expects   (method, hex, arg2) as string on one line
        ln = self.request.readline()

        arg1, bb, arg2 = ln.split(', ')

        method = int(arg1)
        arg2 = int(arg2)
        buf_io = a2b_hex(bb) if bb != 'None' else None

        if method == -99:
            # internal to us: read SPI flash contents
            return self.read_sflash()
        elif method in {2, 3}:
            # these methods always die; not helpful for testing
            print(f"FATAL Callgate(method={method}, arg2={arg2}) => execution would stop")
            self.response.write(b'0,\n')
            return

        sio = self.sio

        sio.timeout = 0.1
        sio.read_all()

        sio.write(b'\r\x05')      # CTRL-E => paste mode

        if buf_io is None:
            sio.write(b'bb = None\r')
        else:
            sio.write(b'bb = bytearray(a2b_hex("%s"))\r' % b2a_hex(buf_io))

        sio.write(b'busy(1)\r')
        sio.write(b'rv = ckcc.gate(%d, bb, %d)\r' % (method, arg2))
        sio.write(b'busy(0)\r')
        if buf_io is None:
            sio.write(b'print("%d," % rv)\r')
        else:
            sio.write(b'print("%d, %s" % (rv, b2a_hex(bb).decode()))\r')
        sio.write(b'\x04\r')        # CTRL-D, end paste; start exec

        lines = []
        for retries in range(10):
            lines.extend(self.wait_done())
            #print('back: \n' + '\n'.join( f'[{n}] {l}' for n,l in enumerate(lines)))
            if len(lines) >= 2 and lines[-1] == lines[-2] == '>>> ':
                break
        else:
            raise RuntimeError("timed out")

        # result is in lines between final === and first >>> ... typically a single
        # line, but might overflow into next 'line'
        assert '=== ' in lines and '>>> ' in lines
        a = -list(reversed(lines)).index('=== ')
        b = lines[a:].index('>>> ')
        rv = ''.join(lines[a:a+b]).strip()

        assert rv
        assert ',' in rv
        assert not rv.startswith('===')

        if 1:
            print(f"Callgate(method={method}, {len(buf_io) if buf_io else 0} bytes, arg2={arg2}) => rv={rv}")

        self.response.write(rv.encode('ascii') + b'\n')


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
    def sock_cleanup():
        import os
        fp = '/tmp/ckcc-simulator.sock'
        if os.path.exists(fp):
            os.unlink(fp)
    sock_cleanup()
    import atexit
    atexit.register(sock_cleanup)

    # handle connection to real hardware, on command line
    # - open the serial device
    # - get buffering/non-blocking right
    # - pass in open fd numbers
    pass_fds = [oled_w, numpad_r, led_w]

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
    cc_cmd = ['../coldcard-mpy', '-i', '../sim_boot.py',
                        str(oled_w), str(numpad_r), str(led_w)] \
                        + metal_args + sys.argv[1:]
    xterm = subprocess.Popen(['xterm', '-title', 'Coldcard Simulator REPL',
                                '-geom', '132x40+450+40', '-e'] + cc_cmd,
                                env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                pass_fds=pass_fds, shell=False)


    # reopen as binary streams
    oled_rx = open(oled_r, 'rb', closefd=0, buffering=0)
    led_rx = open(led_r, 'rb', closefd=0, buffering=0)
    numpad_tx = open(numpad_w, 'wb', closefd=0, buffering=0)

    # setup no blocking
    for r in [oled_rx, led_rx]:
        fl = fcntl.fcntl(r, fcntl.F_GETFL)
        fcntl.fcntl(r, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    readables = [oled_rx, led_rx]
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

                if ch == 'm':
                    # do many OK's in a row ... for word nest menu
                    for i in range(30):
                        numpad_tx.write(b'y\n')
                        numpad_tx.write(b'\n')
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

        rs, ws, es = select(readables, [], [], .001)
        for r in rs:

            if bare_metal and r == bare_metal.request:
                bare_metal.readable()
                continue

            # Cheating: 1024 is size of OLED update, don't change.
            buf = r.read(1024*1000)
            if not buf:
                break

            if r is oled_rx:
                buf = buf[-1024:]
                oled.render(window, buf)
                spriterenderer.render(oled.sprite)
                window.refresh()
            elif r is led_rx:

                for c in buf:
                    #print("LED change: 0x%02x" % c[0])

                    mask = (c >> 4) & 0xf
                    lset = c & 0xf
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
