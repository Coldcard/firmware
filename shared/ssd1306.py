# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ssd1306.py - MicroPython SSD1306 OLED driver, with SPI interface
#
# Copied from ../external/micropython/drivers/display/ssd1306.py
#
import time
from micropython import const
import framebuf

# register definitions
SET_CONTRAST        = const(0x81)
SET_ENTIRE_ON       = const(0xa4)
SET_NORM_INV        = const(0xa6)
SET_DISP            = const(0xae)
SET_MEM_ADDR        = const(0x20)
SET_COL_ADDR        = const(0x21)
SET_PAGE_ADDR       = const(0x22)
SET_DISP_START_LINE = const(0x40)
SET_SEG_REMAP       = const(0xa0)
SET_MUX_RATIO       = const(0xa8)
SET_COM_OUT_DIR     = const(0xc0)
SET_DISP_OFFSET     = const(0xd3)
SET_COM_PIN_CFG     = const(0xda)
SET_DISP_CLK_DIV    = const(0xd5)
SET_PRECHARGE       = const(0xd9)
SET_VCOM_DESEL      = const(0xdb)
SET_CHARGE_PUMP     = const(0x8d)

# Subclassing FrameBuffer provides support for graphics primitives
# see <http://docs.micropython.org/en/latest/pyboard/library/framebuf.html>
#
class SSD1306(framebuf.FrameBuffer):
    def __init__(self, width, height, is_mk5):
        self.width = width
        self.height = height
        self.is_mk5 = is_mk5
        self.pages = self.height // 8

        self.buffer = bytearray(1024)
        #assert len(self.buffer) == self.pages * self.width

        super().__init__(self.buffer, self.width, self.height, framebuf.MONO_VLSB)
        self.init_display()

    def init_display(self):
        if not self.is_mk5:
            # Mk4 and earlier
            cmds = (
                SET_DISP | 0x00, # display off
                # address setting
                SET_MEM_ADDR, 0x00, # horizontal
                # resolution and layout
                SET_DISP_START_LINE | 0x00,
                SET_SEG_REMAP | 0x01, # column addr 127 mapped to SEG0
                SET_MUX_RATIO, self.height - 1,
                SET_COM_OUT_DIR | 0x08, # scan from COM[N] to COM0
                SET_DISP_OFFSET, 0x00,
                SET_COM_PIN_CFG, 0x12,
                # timing and driving scheme
                SET_DISP_CLK_DIV, 0xF0,
                SET_PRECHARGE, 0xf1,
                SET_VCOM_DESEL, 0x30, # 0.83*Vcc
                # display
                SET_CONTRAST, 0xff, # maximum
                SET_ENTIRE_ON, # output follows RAM contents
                SET_NORM_INV, # not inverted
                # charge pump
                SET_CHARGE_PUMP, 0x14)
        else:
            # Mk5 has external +12v power supply, and different setup protocol

            cmds = (
                SET_DISP | 0x00,        # display off
                # address setting
                SET_MEM_ADDR, 0x00, # horizontal
                # resolution and layout
                SET_DISP_START_LINE | 0x00,
                SET_SEG_REMAP | 0x00, # column addr 0 mapped to SEG127
                SET_MUX_RATIO, self.height - 1,
                SET_COM_OUT_DIR | 0x00, # scan from COM[8] to COM[N]
                SET_DISP_OFFSET, 0x00,
                SET_COM_PIN_CFG, 0x12,
                # timing and driving scheme
                SET_DISP_CLK_DIV, 0xF0,
                SET_PRECHARGE, 0x22,
                SET_VCOM_DESEL, 0x40, # per spec sheet
                # display
                SET_CONTRAST, 0x85, # NOT maximum, because spec sheet
                SET_ENTIRE_ON,      # output follows RAM contents
                SET_NORM_INV,       # not inverted
                SET_CHARGE_PUMP, 0x10,  # charge pump: DISABLE
                )

        self.write_cmds(cmds)

        self.fill(0)
        self.show()

        self.write_cmd(SET_DISP | 0x01)

    def write_cmds(self, cmds):
        for c in cmds:
            self.write_cmd(c)

    def poweroff(self):
        self.write_cmd(SET_DISP | 0x00)

    def poweron(self):
        self.write_cmd(SET_DISP | 0x01)

    def contrast(self, contrast):
        # brightness: normal = 0x7f, brightness=0xff, dim=0x00 (but they are all very similar)
        if self.is_mk5:
            # - limit to a specific max value from OLED specs used on Mk5
            contrast = max(contrast, 0x85)
        self.write_cmd(SET_CONTRAST)
        self.write_cmd(contrast)

    def invert(self, invert):
        self.write_cmd(SET_NORM_INV | (invert & 1))

    def show(self):
        self.write_cmd(SET_COL_ADDR)
        self.write_cmd(0)
        self.write_cmd(self.width - 1)

        self.write_cmd(SET_PAGE_ADDR)
        self.write_cmd(0)
        self.write_cmd(self.pages - 1)

        self.write_data(self.buffer)

    def busy_bar(self, enable, pattern):
        # Render a continuous activity (not progress) bar in lower 8 lines of display
        # - using OLED itself to do the animation, so smooth and CPU free
        # - cannot preserve bottom 8 lines, since we have to destructively write there
        # - assumes normal horz addr mode: 0x20, 0x00
        # - speed_code=>framedelay: 0=5fr, 1=64fr, 2=128, 3=256, 4=3, 5=4, 6=25, 7=2frames
        #   unused: assert 0 <= speed_code <= 7

        setup = bytes([
            0x21, 0x00, 0x7f,       # setup column address range (start, end): 0-127
            0x22, 7, 7,             # setup page start/end address: page 7=last 8 lines
        ])
        if not self.is_mk5:
            animate = bytes([ 
                0x2e,               # stop animations in progress
                0x26,               # scroll leftwards (stock ticker mode)
                    0,              # placeholder
                    7,              # start 'page' (vertical)
                    5,              # "speed_code" # scroll speed: 7=fastest, but no order to it
                    7,              # end 'page'
                    0, 0x7f,        # start/end columns
                0x2f                # start
            ])
        else:
            # SSD1309? doesn't implement 0x26 but has other commands
            animate = bytes([ 
                0x2e,               # stop animations in progress
                0x29,               # Vert+Right horz animation setup
                    1,              # A: enable horz scroll
                    7,              # B: start 'page' (vertical)
                    5,              # C: "speed_code" # scroll speed: 7=fastest, but no order to it
                    7,              # D: end 'page'
                    1,              # E: vert scrolling offset (unused)
                    0, 0x7f,        # F,G: start/end columns
                0xa3,               # Set Vertical scroll Area
                    0, 0,           # A, B: # of rows in fixed vs. scroll area
                0x2f                # start animating
            ])

        cleanup = bytes([
            0x2e,               # stop animation
            0x20, 0x00,         # horz addr-ing mode
            0x21, 0x00, 0x7f,   # setup column address range (start, end): 0-127
            0x22, 7, 7,         # setup page start/end address: page 7=last 8 lines
        ])

        if not enable:
            # stop animation, and redraw old (new) screen
            self.write_cmds(cleanup)
        else:
            # needs a pattern that repeats nicely mod 128
            self.write_cmds(setup)
            self.write_data(pattern)
            self.write_cmds(animate)

class SSD1306_SPI(SSD1306):
    def __init__(self, width, height, spi, dc, res, cs, is_mk5=False):
        self.spi = spi
        self.dc = dc
        self.cs = cs
        self.res = res

        # initial states
        dc(0)
        cs(1)

        # reset sequence
        res(1)
        time.sleep_ms(1)
        res(0)
        time.sleep_ms(10)
        res(1)

        super().__init__(width, height, is_mk5)

    def _setup_spi(self):
        # need to re-do this constantly
        # max chip can do, still slower than display limit tho
        # - 40Mhz (target) is fine for short-cabled Mk4 (actual is lower?)
        # - max spec is 10Mhz on Mk5
        rate = 40_000_000 if not self.is_mk5 else 10_000_000
        self.spi.init(baudrate=rate, polarity=0, phase=0)

    def write_cmd(self, cmd):
        self._setup_spi()
        self.cs(1)
        self.dc(0)
        self.cs(0)
        self.spi.write(bytearray([cmd]))
        self.cs(1)

    def write_data(self, buf):
        self._setup_spi()
        self.cs(1)
        self.dc(1)
        self.cs(0)
        self.spi.write(buf)
        self.cs(1)

# EOF
