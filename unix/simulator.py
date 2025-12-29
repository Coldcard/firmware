#!/usr/bin/env python
#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Simulate the hardware of a Coldcard. Particularly the OLED display (128x32) and 
# the number pad.
#
# Can be run in headless mode (--headless) mostly useful for unit tests
#
# This is a normal python3 program, not micropython. It communicates with a running
# instance of micropython that simulates the micropython that would be running in the main
# chip.
#
# Limitations:
# - USB light not fully implemented, because happens at irq level on real product
#
import os, sys, signal, time, pdb, tempfile, struct, zlib, subprocess, shutil
from dataclasses import dataclass
import sdl2.ext
from PIL import Image, ImageOps
from select import select
import fcntl
from bare import BareMetal
from sdl2.scancode import *     # SDL_SCANCODE_F1.. etc

MPY_UNIX = 'l-port/micropython'

UNIX_SOCKET_PATH = '/tmp/ckcc-simulator.sock'

current_led_state = 0x0


def activate_file(filename):
    # see <https://stackoverflow.com/questions/17317219>
    if sys.platform == "win32":
        os.startfile(filename)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, filename])

class SimulatedScreen:
    # a base class

    def snapshot(self, fn_in=None):
        # save to file
        fn = fn_in or time.strftime('../snapshot-%j-%H%M%S.png')
        with tempfile.NamedTemporaryFile() as tmp:
            sdl2.SDL_SaveBMP(self.sprite.surface, tmp.name.encode('ascii'))
            tmp.file.seek(0)
            img = Image.open(tmp.file)
            img.save(fn)

        if not fn_in:
            print("Snapshot saved: %s" % fn.split('/', 1)[1])
            activate_file(fn)

        return fn

    def movie_start(self):
        self.movie = []
        self.last_frame = time.time() - 0.1
        print("Movie recording started.")
        self.new_frame()

    def movie_end(self):
        fn = time.strftime('../movie-%j-%H%M%S.gif')

        if not self.movie: return

        dt0, img = self.movie[0]

        img.save(fn, save_all=True, append_images=[fr for _,fr in self.movie[1:]],
                        duration=[max(dt, 20) for dt,_ in self.movie], loop=50)

        print("Movie saved: %s (%d frames)" % (fn.split('/', 1)[1], len(self.movie)))
        activate_file(fn)

        self.movie = None

    def new_frame(self):
        dt = int((time.time() - self.last_frame) * 1000)
        self.last_frame = time.time()

        with tempfile.NamedTemporaryFile() as tmp:
            sdl2.SDL_SaveBMP(self.sprite.surface, tmp.name.encode('ascii'))
            tmp.file.seek(0)
            img = Image.open(tmp.file)
            img = img.convert('P')
            self.movie.append((dt, img))

    def vsync_handler(self, sr, w):
        # subclass thing
        return

class LCDSimulator(SimulatedScreen):
    # Simulate the LCD found on the Q1: 320x240xRGB565
    # - written with little-endian (16 bit) data

    background_img = 'q1-images/background.png'

    # where the simulated screen is, relative to fixed background
    #TOPLEFT = (90, 91)
    TOPLEFT = (95, 96)

    @dataclass
    class CursorSpec:
        x: int
        y: int
        cur_type: int

    def __init__(self, factory):
        self.movie = None

        self.sprite = s = factory.create_software_sprite( (320,240), bpp=16)
        s.x, s.y = self.TOPLEFT
        s.depth = 100

        # selftest
        try:
            assert sdl2.ext.prepare_color('#0f0', s) == 0x07e0, 'need RGB565 sprite (got 555?)'
            assert sdl2.ext.prepare_color('#f00', s) == 0xf800, 'need RGB565 sprite (got BGR?)'
        except:
            print('red = ' + hex(sdl2.ext.prepare_color('#f00', s)))
            print('grn = ' + hex(sdl2.ext.prepare_color('#0f0', s)))
            print('blu = ' + hex(sdl2.ext.prepare_color('#00f', s)))
            raise

        sdl2.ext.fill(s, 0x0)

        self.mv = sdl2.ext.pixels2d(self.sprite)
    
        # for any LED's .. no position implied
        self.led_red = factory.from_image("q1-images/led-red.png")
        self.led_green = factory.from_image("q1-images/led-green.png")

        # state for LCD animations normally handled by GPU
        self.busy_bar = False
        self.cursor = None
        self.phase = 0
        self.animate = False

        # GPU stuff needs to know implementation details... because it re-implements
        self.COL_BLACK = 0
        self.COL_WHITE = 0xffff
        self.COL_FOREGROUND = 0xfd60     # brand orange (not byte-swapped here)
        

    def vsync_handler(self, spriterenderer, window):
        # will be called at 61Hz, just like the real LCD's TEAR output signal
        if not self.animate:
            return

        activity = False

        if self.busy_bar:
            activity |= self.gpu_draw_busy()

        if self.cursor:
            activity |= self.gpu_draw_cursor()

        self.phase = (self.phase + 1) % 256

        if not activity:
            # nothing got drawn
            return

        # maybe save
        if self.movie is not None:
            # problem: other stuff may be in mid-update; should look at 
            # time since last save, and if longer than 60Hz, save then?
            self.new_frame()

        # draw to screen
        spriterenderer.render(self.sprite)
        window.refresh()


    def gpu_draw_busy(self):
        # infinite progress bar
        PROG_HEIGHT = 5
        PROG_Y = 240 - PROG_HEIGHT
        NUM_PHASES = 16
        LCD_WIDTH = 320
        bg = self.COL_BLACK
        fg = self.COL_FOREGROUND

        ph = self.phase % NUM_PHASES

        sz = LCD_WIDTH + NUM_PHASES + 1
        row = [bg if ((i % 8) < 2) else fg for i in range(sz)]

        for y in range(PROG_Y, PROG_Y+PROG_HEIGHT):
            for x in range(LCD_WIDTH):
                self.mv[x][y] = row[NUM_PHASES - ph - 1 + x]

        return True

    def gpu_draw_cursor(self):
        # screen layout constants.
        # see shared/lcd.py and shared/font_iosevka.py
        LEFT_MARGIN = 7
        TOP_MARGIN = 15
        CHARS_W = 34
        CHARS_H = 10
        CELL_W = 9
        CELL_H = 22

        # cur_type encoding
        CURSOR_SOLID = 0x01
        CURSOR_OUTLINE = 0x02
        CURSOR_MENU = 0x03
        CURSOR_DW_OUTLINE = 0x11
        CURSOR_DW_SOLID = 0x12
        CURSOR_DW_Mask = 0x10

        # flash cursor at frame rate / 32
        if self.phase & 31 != 0: return False
        phase = bool(self.phase & 32)

        # GPU is silent on errors
        char_x = self.cursor.x
        char_y = self.cursor.y
        if char_x >= CHARS_W: return False
        if char_y >= CHARS_H: return False

        dbl_wide = bool(self.cursor.cur_type & CURSOR_DW_Mask)
        ctype = self.cursor.cur_type & 0xf
        assert CELL_H > 2*CELL_W           # for dbl_wide case

        # top left corner, just on edge of character cell
        x = LEFT_MARGIN + (char_x * CELL_W)
        y = TOP_MARGIN + (char_y * CELL_H)
        cell_w = CELL_W + (CELL_W if dbl_wide else 0)

        # make some pixels big enough for either vert or horz lines
        colour = self.COL_FOREGROUND if not phase else self.COL_BLACK

        def fill_solid(X,Y, w, h, col):
            for x in range(X, X+w):
                for y in range(Y, Y+h):
                    self.mv[x][y] = col

        if ctype == CURSOR_OUTLINE:
            # horz
            fill_solid(x,y, cell_w, 1, colour)
            fill_solid(x,y+CELL_H-1, cell_w, 1, colour)

            # vert
            fill_solid(x, y+1, 1, CELL_H-2, colour)
            fill_solid(x+cell_w-1, y+1, 1, CELL_H-2, colour)
        elif ctype == CURSOR_SOLID:
            if not phase:
                # solid fill -- draw first time
                fill_solid(x,y, cell_w, CELL_H, self.COL_FOREGROUND)
            else:
                # box shape, blank interior pixels
                fill_solid(x+1,y+1, cell_w-2, CELL_H-2, self.COL_BLACK)
        elif ctype == CURSOR_MENU:
            # half-wide thing for menus
            fill_solid(x,y, 4, CELL_H, colour)
        else:
            raise ValueError(ctype)

        return True
        

    def new_contents(self, readable):
        # got bytes for new update. expect a header and packed pixels
        while 1:
            prefix = readable.read(13)
            if not prefix:
                break

            mode, X,Y, w, h, count, argX = struct.unpack('<s6H', prefix)
            mode = mode.decode('ascii')
            here = readable.read(count)

            if mode == 's':
                # trigger a snapshot, data is filename to save PNG into
                self.snapshot(here.decode())
                continue

            try:
                assert X>=0 and Y>=0
                assert X+w <= 320
                assert Y+h <= 240
                assert len(here) == count
            except AssertionError:
                print(f"Bad LCD update: x,y={X},{Y} w,h={w}x{h} mode={mode}")
                if 1: # these are serious, so crash..
                    self.snapshot()
                    raise
                continue

            pos = 0
            if mode in 't':
                # palette lookup mode for text: packed 4-bit / pixel
                # ? no longer used ?
                assert count == ((w*h)//2)+(2*16), [w,h,count]

                pal = struct.unpack('>16H', here[:2*16])

                unpacked = bytearray()
                for b in here[2*16:]:
                    unpacked.append(b >> 4)
                    unpacked.append(b & 0xf)

                for y in range(Y, Y+h):
                    for x in range(X, X+w):
                        val = unpacked[pos]
                        self.mv[x][y] = pal[val & 0xf]
                        pos += 1

            elif mode == 'z':
                # compressed RGB565 pixels
                raw = zlib.decompress(here, wbits=-12)
                assert w*h*2 == len(raw)
                for y in range(Y, Y+h):
                    for x in range(X, X+w):
                        #val = (raw[pos] << 8) + raw[pos+1]
                        #val = raw[pos+1] + (raw[pos] << 8)
                        val, = struct.unpack('>H', raw[pos:pos+2])
                        self.mv[x][y] = val
                        pos += 2

            elif mode == 'q':
                # 8-bit packed black vs. white values for QR's
                # - we do the expansion
                # - we add one unit of whitespace around
                expand = h
                h = w
                scan_w = (w+7)//8
                trim_lines = argX

                #print(f'QR: {scan_w=} {expand=} {w=}')
                assert 21 <= w <= 177 and (w%2) == 1, w

                # use PIL to resize and add border
                # - but pasting img into sprite is too hard, so use self.mv instead
                W = (w+2) * expand
                tmp = Image.frombytes('1', (w, w), here).resize( (w*expand, w*expand),
                                                        resample=Image.Resampling.NEAREST)
                qr = ImageOps.expand(tmp, expand, 0)
                assert qr.size == (W, W)

                delme = {}
                if trim_lines:
                    # remove every 47th line, up to trim_lines qty
                    delme = list(range(47, W, 47))[0:trim_lines]

                pos = 0
                pixels = list(qr.getdata(0))
                for y in range(Y, Y+W-trim_lines):
                    if y in delme:
                        pos += W
                    for x in range(X, X+W):
                        self.mv[x][y] = 0x0000 if pixels[pos] else 0xffff
                        pos += 1

            elif mode == 'r':
                # raw RGB565 pixels (not compressed, packed)
                # slow, avoid
                assert count == w * h * 2, [count, w, h]
                for y in range(Y, Y+h):
                    for x in range(X, X+w):
                        val, = struct.unpack('<H', here[pos:pos+2])
                        self.mv[x][y] = val
                        pos += 2

            elif mode == 'f':
                # fill a region to single pixel value
                px, = struct.unpack("<H", here)
                for y in range(Y, Y+h):
                    for x in range(X, X+w):
                        self.mv[x][y] = px

            elif mode in 'TPBCG':
                # emulated GPU commands
                # see vsync_handler() for implementation
                if mode == 'T':
                    # stop animating: "taking" the SPI bus away from GPU
                    self.animate = False
                elif mode == 'G':
                    # continue animating
                    self.animate = True
                elif mode == 'P':
                    # test pattern: a fixed bar code is shown in real deal
                    pass
                elif mode == 'B':
                    # show busy bar (infinite progress bar)
                    self.cursor = None
                    self.busy_bar = True
                    self.animate = True
                elif mode == 'C':
                    # show a cursor
                    self.cursor = self.CursorSpec(X,Y, cur_type=w)
                    self.phase = 0      # make update happen immediately
                    self.busy_bar = False
                    self.animate = True

            else:
                raise ValueError(mode)

        if self.movie is not None:
            self.new_frame()

    def click_to_key(self, x, y):
        # take a click on image => keypad key if valid
        # - not planning to support, tedious
        return None

    def draw_single_led(self, spriterenderer, x, y, red=False):
        sp = self.led_red if red else self.led_green
        sp.position = (x, y)
        spriterenderer.render(sp)

    def draw_leds(self, spriterenderer, active_set=0):
        # redraw all LED's in their current state, indicated
        SE1_LED = 0x1
        SD1_LED = 0x2
        USB_LED = 0x4
        SD2_LED = 0x8
        NFC_LED = 0x10

        if active_set & SE1_LED:
            self.draw_single_led(spriterenderer, 30, 35, red=False)
        else:
            # Test with:
            #   from ckcc import led_pipe; led_pipe.write(b'\x01\x00')
            self.draw_single_led(spriterenderer, 85, 33, red=True)

        if active_set & SD1_LED:
            self.draw_single_led(spriterenderer, 8, 135)
        if active_set & SD2_LED:
            self.draw_single_led(spriterenderer, 8, 260)
        if active_set & USB_LED:
            self.draw_single_led(spriterenderer, 240, 805, red=True)
        if active_set & NFC_LED:
            self.draw_single_led(spriterenderer, 465, 315)

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

        self.mv = sdl2.ext.pixels2d(self.sprite, transpose=False)
    
        # for genuine/caution lights and other LED's
        self.led_red = factory.from_image("mk4-images/led-red.png")
        self.led_green = factory.from_image("mk4-images/led-green.png")
        self.led_sdcard = factory.from_image("mk4-images/led-sd.png")
        self.led_usb = factory.from_image("mk4-images/led-usb.png")

    def new_contents(self, readable):
        # got bytes for new update.

        # Must be bigger than a full screen update.
        buf = readable.read(1024*1000)
        if not buf:
            return

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

def load_shared_mod(name, path):
    # load indicated file.py as a module
    # from <https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path>
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

q1_charmap = load_shared_mod('charcodes', '../shared/charcodes.py')

def scancode_remap(sc):
    # return an ACSII (non standard) char to represent arrows and other similar
    # special keys on Q1 only.
    # - see ENV/lib/python3.10/site-packages/sdl2/scancode.py
    # - select/cancel/tab/bs all handled already 
    # - NFC, lamp, QR buttons in alt_up()

    m = {
        SDL_SCANCODE_RIGHT: q1_charmap.KEY_RIGHT,
        SDL_SCANCODE_LEFT: q1_charmap.KEY_LEFT,
        SDL_SCANCODE_DOWN: q1_charmap.KEY_DOWN,
        SDL_SCANCODE_UP: q1_charmap.KEY_UP,
        SDL_SCANCODE_HOME: q1_charmap.KEY_HOME,
        SDL_SCANCODE_END: q1_charmap.KEY_END,
        SDL_SCANCODE_PAGEDOWN: q1_charmap.KEY_PAGE_DOWN,
        SDL_SCANCODE_PAGEUP: q1_charmap.KEY_PAGE_UP,

        SDL_SCANCODE_F1: q1_charmap.KEY_F1,
        SDL_SCANCODE_F2: q1_charmap.KEY_F2,
        SDL_SCANCODE_F3: q1_charmap.KEY_F3,
        SDL_SCANCODE_F4: q1_charmap.KEY_F4,
        SDL_SCANCODE_F5: q1_charmap.KEY_F5,
        SDL_SCANCODE_F6: q1_charmap.KEY_F6,
    }

    return m[sc] if sc in m else None

def special_q1_keys(ch):
    # special keys on Q1 keyboard that do not have anything similar on
    # normal desktop.
    # Press META + key
    # - on MacOS META = flower (command) key

    if ch == 'n':
        return q1_charmap.KEY_NFC
    if ch == 'r':               # cant be Q, sadly
        return q1_charmap.KEY_QR
    if ch == 'l':
        return q1_charmap.KEY_LAMP

    return None

def q1_click_to_keynum(x, y):
    # convert on-screen position to a keynumber, or None if they missing

    # handle screen click as "paste"
    if (90 <= x <= 430) and (90 <= y <= 345):
        # click on screen
        return 'SCREEN'
    
    # detect click near USB to simulate unplug/plug events
    if (230 <= x <= 290) and (810 <= y <= 852):
        # click near USB connector
        return 'PLUGGER'

    # keypad area
    left = 29
    right = 490
    top = 398
    bottom = 790

    if (y > bottom) or (y < top):
        return None

    # put onto a grid; better would have dead zones between them
    pitch_x = (right-left) / 10
    pitch_y = (bottom-top) / 7

    gx = int((x - left) / pitch_x)
    gy = int((y - top) / pitch_y)

    #print(f'{x=} {y=} => {gx=} {gy=}')

    # main qwerty area, nice grid
    if 2 <= gy <= 5:
        return ((gy-1) * 10) + gx

    # top area; two rows really
    if (0 <= gy <= 1):
        if 2 <= gx <= 3:
            return 0x03      # KEY_LEFT
        if 6 <= gx <= 7:
            return 0x06      # KEY_RIGHT

    if gy == 0:
        if gx == 0:
            # power key?
            raise SystemExit
        if gx == 1:
            return 0x02      # KEY_QR
        if 4 <= gx <= 5:
            return 0x04      # KEY_UP
        if gx >= 8:
            return 0x07      # KEY_CANCEL

    if gy == 1:
        if gx == 0:
            return 0x00      # KEY_NFC
        if gx == 1:
            return 0x01      # KEY_TAB
        if 4 <= gx <= 5:
            return 0x05      # KEY_DOWN
        if gx >= 8:
            return 0x08      # KEY_ENTER
        
    if gy == 6:
        # bottom row
        if gx == 0:     # too narrow, but meh
            return q1_charmap.KEYNUM_LAMP
        if 1 <= gx <= 3:
            return q1_charmap.KEYNUM_SHIFT
        if 4 <= gx <= 6:
            return 52       # space
        if 7 <= gx <= 8:
            return q1_charmap.KEYNUM_SYMBOL
        if gx == 9:
            return 54       # delete

    return None

q1_pressed = set()
def handle_q1_key_events(event, numpad_tx, data_tx):
    # Map SDL2 (unix, desktop) keyscan code into keynumber on Q1
    # - allow Q1 to do shift logic
    # - support up to 5 keys down at once
    global q1_pressed

    if event.type in (sdl2.SDL_MOUSEBUTTONDOWN, sdl2.SDL_MOUSEBUTTONUP):
        is_press = (event.type == sdl2.SDL_MOUSEBUTTONDOWN)
        kn = q1_click_to_keynum(event.button.x, event.button.y)

        if kn == 'SCREEN':
            # click on screen to paste clipboard into QR scanner or NFC tag
            if is_press:
                txt = sdl2.SDL_GetClipboardText()
                if txt:
                    print(f"Doing paste: {txt.decode()}")
                    data_tx.write(txt + b'\n')
            return None

        if kn == 'PLUGGER':
            kn = 0xfe       # see variant/touch.py

        if kn is None: return

        if is_press:
            q1_pressed.add(kn)
        else:
            q1_pressed.discard(kn)
    else:
        assert event.type in { sdl2.SDL_KEYUP, sdl2.SDL_KEYDOWN}
        is_press = (event.type == sdl2.SDL_KEYDOWN)

        # first, see if we can convert to ascii char
        scancode = event.key.keysym.sym & 0xffff
        try:
            ch = chr(event.key.keysym.sym)
        except:
            ch = scancode_remap(scancode)

        #print(f'scan 0x{scancode:04x} mod=0x{event.key.keysym.mod:04x}=> char={ch}=0x{ord(ch) if ch else 0:02x}')

        shift_down = bool(event.key.keysym.mod & 0x3)         # left or right shift
        symbol_down = bool(event.key.keysym.mod & 0x200)      # right ALT
        special_down = bool(event.key.keysym.mod & 0xc00)     # left or right META

        #print(f"modifier = 0x{event.key.keysym.mod:04x} => shift={shift_down} symb={symbol_down} spec={special_down}")

        if special_down:
            ch = special_q1_keys(ch)
            if not ch:
                return

        # reverse char to a keynum, and perhaps the meta key too
        kn = None

        if ch:
            if ch in q1_charmap.DECODER:
                kn = q1_charmap.DECODER.find(ch)
            elif ch in q1_charmap.DECODER_SHIFT:
                kn = q1_charmap.DECODER_SHIFT.find(ch)
                shift_down = is_press
            elif ch in q1_charmap.DECODER_SYMBOL:
                kn = q1_charmap.DECODER_SYMBOL.find(ch)
                symbol_down = is_press

        # XXX handle shift+char where char doesn't exist, like + or {} 
        # - basically all symbols not on top row?

        #print(f"{ch=} => keynum={kn} => shift={shift_down} sym={symbol_down}")


        if kn is not None:
            if is_press:
                q1_pressed.add(kn)
            else:
                q1_pressed.discard(kn)

        q1_pressed.discard(q1_charmap.KEYNUM_SHIFT)
        q1_pressed.discard(q1_charmap.KEYNUM_SYMBOL)

        if shift_down: 
            q1_pressed.add(q1_charmap.KEYNUM_SHIFT)
        if symbol_down: 
            q1_pressed.add(q1_charmap.KEYNUM_SYMBOL)

        #print(f" .. => pressed: {q1_pressed}")

    # see variant/touch.py where this is decoded.
    if len(q1_pressed) > 5:
        q1_pressed.clear()      ## keep going?!
    report = bytes(list(q1_pressed) + [ 255, 255, 255, 255, 255])[0:5]
    numpad_tx.write(report)


def start():
    is_q1 = ('--q1' in sys.argv)
    segregate = ("--segregate" in sys.argv)
    pid = os.getpid()
    # for compatibility with old clients
    # UNIX_SOCKET_PATH is always used if not segregate
    socket_path = UNIX_SOCKET_PATH
    if segregate:
        socket_path = '/tmp/ckcc-simulator-%d.sock' % pid

    if "--headless" in sys.argv:
        sys.argv.remove("--headless")
        is_headless = True
    else:
        is_headless = False

    if is_headless:
        print("\nColdcard Simulator (headless). Output below is from the simulated system:\n\n")
    else:
        print('''\nColdcard Simulator: Commands (over simulated window):
  - Control-Q to quit
  - ^Z to snapshot screen.
  - ^S/^E to start/end movie recording
  - ^N to capture NFC data (tap it)'''
)
        print("  - socket: %s" % socket_path)
        if is_q1:
            print('''\
Q1 specials:
  Right-Alt = AltGr => SYM (symbol key)
  Meta-L - Lamp button
  Meta-N - NFC button
  Meta-R - QR button  (not Meta-Q, because that's quit!)
  Click Screen - Send clipboard contents to QR/NFC
''')
        sdl2.ext.init()
        sdl2.SDL_EnableScreenSaver()


        factory = sdl2.ext.SpriteFactory(sdl2.ext.SOFTWARE)

        simdis = (OLEDSimulator if not is_q1 else LCDSimulator)(factory)
        bg = factory.from_image(simdis.background_img)

        window = sdl2.ext.Window("Coldcard Simulator", size=bg.size, position=(100, 100))
        window.show()

        ico = factory.from_image('program-icon.png')
        sdl2.SDL_SetWindowIcon(window.window, ico.surface)

        spriterenderer = factory.create_sprite_render_system(window)

        # initial state
        spriterenderer.render(bg)
        spriterenderer.render(simdis.sprite)
        simdis.draw_leds(spriterenderer)

        if ('--bootup-movie' in sys.argv):
            simdis.movie_start()

    # capture exec path and move into intended working directory
    env = os.environ.copy()
    env['MICROPYPATH'] = ':' + os.path.realpath('../shared')

    # handle connection to real hardware, on command line
    # - open the serial device
    # - get buffering/non-blocking right
    # - pass in open fd numbers

    if is_headless:
        display_w = os.open('/dev/null', os.O_RDWR)
        led_w = os.open('/dev/null', os.O_RDWR)
        data_r = os.open('/dev/null', os.O_RDWR)
        pass_fds = [display_w, "-1", led_w, data_r]
    else:
        display_r, display_w = os.pipe()      # fancy OLED display
        led_r, led_w = os.pipe()        # genuine LED
        numpad_r, numpad_w = os.pipe()  # keys
        data_r, data_w = os.pipe()      # data dumps
        pass_fds = [display_w, numpad_r, led_w, data_r]

    # manage unix socket cleanup for client
    def sock_cleanup():
        import os
        fp = socket_path
        if os.path.exists(fp):
            os.remove(fp)

    import atexit
    atexit.register(sock_cleanup)

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

    scan_args = []
    if '--scan' in sys.argv:
        import serial       # pyserial module
        assert is_q1
        port = serial.Serial('/dev/tty.usbserial-B001BC7Y', 9600, timeout=None)
        #port = open('/dev/cu.usbmodem1234567890abcd1', 'w+b')
        pass_fds.append(port.fileno())
        scan_args = [ '--scan', str(port.fileno()) ]
        sys.argv.remove('--scan')

    # unix
    cwd = os.getcwd()
    # abs paths
    cc_mpy = os.path.join(cwd, "coldcard-mpy")
    sim_boot = os.path.join(cwd, "sim_boot.py")

    if segregate:
        os.makedirs("/tmp/cc-simulators", exist_ok=True)
        os.chdir("/tmp/cc-simulators")
        # our new work /tmp/cc-simulators/<PID>
        os.mkdir(str(pid))
        os.chdir(str(pid))
        os.mkdir("MicroSD")
        os.mkdir("settings")
        os.mkdir("VirtDisk")
        os.mkdir("debug")
        # needed for VirtDisk test
        shutil.copy(os.path.join(cwd, "work", "VirtDisk", "README.md"),
                    os.path.join(os.getcwd(), "VirtDisk", "README.md"))
    else:
        os.chdir('./work')

    cc_cmd = [cc_mpy, '-X', 'heapsize=9m', '-i', sim_boot] + [str(i) for i in pass_fds] \
                        + metal_args + scan_args + sys.argv[1:] + [socket_path]

    if is_headless:
        pass_fds.remove("-1")
        args = dict(env=env, pass_fds=pass_fds, shell=False)

        if '-i' not in sys.argv:
            # we can do REPL, if given '-i' argument
            args['stdin'] = subprocess.DEVNULL
            # args['stdout'] = subprocess.DEVNULL

        child = subprocess.Popen(cc_cmd, **args)

        # always prefer to interrupt child, vs. us
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        rv = child.wait()
        if rv:
            print("\r\n<child stopped: %s>\r\n" % rv)

        child.kill()
        return

    logfile = '/tmp/cc_simulator.log'

    # truncate logfile and set correct permissions before starting xterm
    open(logfile, 'w').close()
    os.chmod(logfile, 0o644)

    xterm = subprocess.Popen(['xterm', '-title', 'Coldcard Simulator REPL',
                                '-geom', '132x40+650+40', '-l', '-lf', logfile, '-e'] + cc_cmd,
                                env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                pass_fds=pass_fds, shell=False)


    # reopen as binary streams
    display_rx = open(display_r, 'rb', closefd=0, buffering=0)
    led_rx = open(led_r, 'rb', closefd=0, buffering=0)
    numpad_tx = open(numpad_w, 'wb', closefd=0, buffering=0)
    data_tx = open(data_w, 'wb', closefd=0, buffering=0)

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
        #print(f'{ch} down={is_down}')
        if is_down:
            if ch not in pressed:
                numpad_tx.write(ch.encode())
                pressed.add(ch)
        else:
            pressed.discard(ch)
            if not pressed:
                numpad_tx.write(b'\0')      # all up signal

    while running:
        events = sdl2.ext.get_events()
        for event in events:
            if event.type == sdl2.SDL_QUIT:
                # META-Q comes here for some SDL reason
                running = False
                break

            if is_q1 and event.type in { sdl2.SDL_KEYUP, sdl2.SDL_KEYDOWN} :
                if event.key.keysym.mod == 0x40:
                    # ctrl key down, not used on Q1, so process as simulator
                    # command, see lower.
                    pass
                else:
                    # all other key events for Q1 get handled here
                    handle_q1_key_events(event, numpad_tx, data_tx)
                    continue

            if event.type == sdl2.SDL_KEYUP or event.type == sdl2.SDL_KEYDOWN:
                try:
                    ch = chr(event.key.keysym.sym)
                except:
                    # things like 'shift' by itself and anything not really ascii

                    scancode = event.key.keysym.sym & 0xffff
                    #print(f'keysym=0x%0x => {scancode}' % event.key.keysym.sym)
                    if SDL_SCANCODE_RIGHT <= scancode <= SDL_SCANCODE_UP:
                        # arrow keys remap for Mk4
                        ch = '9785'[scancode - SDL_SCANCODE_RIGHT]
                    else:
                        #print('Ignore: 0x%0x' % event.key.keysym.sym)
                        continue

                # control+KEY => for our use
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

                    if not is_q1 and ch == 'm':
                        # do many OK's in a row ... for word nest menu
                        for i in range(30):
                            numpad_tx.write(b'y\n')
                            numpad_tx.write(b'\n')
                        continue

                if event.key.keysym.mod == 0x40 and event.type == sdl2.SDL_KEYUP:
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
                send_event(ch, event.type == sdl2.SDL_KEYDOWN)

            if is_q1 and event.type in (sdl2.SDL_MOUSEBUTTONDOWN, sdl2.SDL_MOUSEBUTTONUP):
                handle_q1_key_events(event, numpad_tx, data_tx)
            else:
                if event.type == sdl2.SDL_MOUSEBUTTONDOWN:
                    #print('xy = %d, %d' % (event.button.x, event.button.y))
                    ch = simdis.click_to_key(event.button.x, event.button.y)
                    if ch is not None:
                        send_event(ch, True)

                if event.type == sdl2.SDL_MOUSEBUTTONUP:
                    for ch in list(pressed):
                        send_event(ch, False)

            if event.type == sdl2.SDL_DROPFILE:
                # failed to get sdl2.SDL_DROPTEXT to work, but also not convenient to use
                print(f"Sending file: {event.drop.file.decode()}")
                try:
                    data = open(event.drop.file, 'rb').read(4096)        # size limit < pipe depth
                    if data[-1] != b'\n':
                        data += b'\n'       # must end w/ NL, probably needs to be text too
                    data_tx.write(data)
                    print(f".. sent {len(data)} bytes")
                except Exception as exc:
                    print(repr(exc))
                    

        rs, ws, es = select(readables, [], [], 0)
        for r in rs:

            if bare_metal and r == bare_metal.request:
                bare_metal.readable()
                continue
        
            if r is display_rx:
                simdis.new_contents(r)
                spriterenderer.render(simdis.sprite)
                window.refresh()
            elif r is led_rx:
                # was 4+4 bits, now two bytes: [mask, state]
                c = r.read(2)
                if not c:
                    break

                global current_led_state
                mask, lset = c
                current_led_state |= (mask & lset)
                current_led_state &= ~(mask & ~lset)
                #print(f'LED: mask={mask:x} lset={lset:x} => active={current_led_state:x}')

                spriterenderer.render(bg)
                spriterenderer.render(simdis.sprite)
                simdis.draw_leds(spriterenderer, current_led_state)

                window.refresh()
            else:
                pass

        if xterm.poll() != None:
            print("\r\n<xterm stopped: %s>\r\n" % xterm.poll())
            break

        sdl2.SDL_Delay(16)       # 60-61Hz ish
        simdis.vsync_handler(spriterenderer, window)

    xterm.kill()
    

if __name__ == '__main__':
    start()
