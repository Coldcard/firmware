#!/usr/bin/env python
#
# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# render.py - Build compressed data for font rendering on the Q1.
#
import os, sys, pdb, math, zlib
from PIL import Image, ImageDraw, ImageFont, ImageColor
from collections import Counter
from struct import pack, unpack

FONT = 'iosevka-extrabold.ttf'
FONT_SIZE = 18

# each character will be in a cell this size of pixels
# - yields final screen size, in chars of: 53x12
CELL_SIZE = (9, 22)
CELL_W, CELL_H = CELL_SIZE
DBL_CELL_SIZE = (CELL_W*2, CELL_H)

print(f'Each char: {CELL_W} x {CELL_H} pixels')
print(f'Screen: {320//CELL_W} x {240//CELL_H} chars')

# quantization for unique grey levels, system-wide
# - needs to be power of two, so divides bytes nicely
# - 4 not enough, 8 decent, 16 even better
NUM_GREYS = 16

# specially-named symbols=keys
KEY_NFC = '\x0e'        # ctrl-N
KEY_QR = '\x11'         # ctrl-Q
KEY_TAB = '\t'          # tab = ctrl-I
KEY_F1 = '\x0f'
KEY_F2 = '\x12'
KEY_F3 = '\x13'
KEY_F4 = '\x14'
KEY_F5 = '\x16'
KEY_F6 = '\x17'
KEYS_FUNCTION = KEY_F1 + KEY_F2 + KEY_F3 + KEY_F4 + KEY_F5 + KEY_F6

KEYCAP_SYMBOLS = [ KEY_NFC, KEY_QR, KEY_TAB ] + list(KEYS_FUNCTION)

# we override these w/ our own art, but the chars involved are still these
# - dashed version for bottom/right sides of things
LINEDRAW_SYMBOLS = [ '━', '┅', '┃', '┇', '┓', '┏', '┛','┗' ]        # 'heavy' versions

CHARSET = [chr(x) for x in range(32,127)] \
            + ['→', '←', '↳', '•', '⋯',
                '█', '▌', '▐', 
                '▼', '▲', '▶', '◀', '⏵',
                '₿', '✔', '✓', '↦', '␣',
                '◉', '◯', '◌', '⬚', '░',
                '™', '©', '⬧', '※',
                '─', '—',
          ] + KEYCAP_SYMBOLS + LINEDRAW_SYMBOLS

# these are be better as double-wide chars
DBL_WIDTH = ['⋯', '✔', '✓','→', '←', '↦',        
                '◉', '◯', '◌', '※', '—',
            ] + KEYCAP_SYMBOLS

NUM_CHARS = len(CHARSET)

# use a different glyph for these unicode values
# - useful for multi-codepoint sequences, which we want to encode as single char
REMAPS = {
    KEY_NFC: 'NFC',
    KEY_QR:  'QR',
    #KEY_TAB: '➔',
    #KEY_TAB: '➜',
    #KEY_TAB: '↦',
    KEY_TAB: '➡︎',
}
for n, fn in enumerate(KEYS_FUNCTION):
    REMAPS[fn] = f'F{n+1}'

# find hidden zero-width junk
assert all(len(ch) == 1 for ch in CHARSET), [ch for ch in CHARSET if len(ch) > 1]

MEM_PER_CHAR = int(round((math.log2(NUM_GREYS) * CELL_W * CELL_H) / 8, 0))
print(f'Font has {NUM_CHARS} chars')
print(f"Per char, memory: {MEM_PER_CHAR} bytes")
print(f"Total font memory: {NUM_CHARS * MEM_PER_CHAR // 1024} KiBytes")

# NOTE: compressing data per-char only saves 50% and requires 1k of ram to decompress
# plus lots of overhead, so don't do that.


def remap_colour(c, amt):
    # take colour (RGB tuple) and give it intensity (amt) and then return RGB565
    amt /= 255.0
    r = int(c[0] * amt * 0x1f)
    g = int(c[1] * amt * 0x3f)
    b = int(c[2] * amt * 0x1f)

    return (r<<11) | (g << 5) | b

def device_endian(col):
    # take a RGB565 value and swap endian for real device
    # XXX unneeded?
    return unpack('<H', pack('>H', col))[0]

def make_palette(shades, col, darken=1.0):
    # make bytes representing a NUM_GREYS palette to map back to a RGB565 colour

    assert len(col) == 3, 'want RGB'
    assert col[0] > 20, 'expect 8-bit RGB values'
    col = [i/255.0 for i in col]
    assert max(col) <= 1.0
    assert 0 <= min(col)

    assert len(shades) == NUM_GREYS
    vals = [remap_colour(col, s*darken) for s in shades]
    txt = ', '.join('0x%04x'% i for i in vals)
    return vals, txt, pack('>%dH' % NUM_GREYS, *vals)

def draw_linedrawing(ch, img, draw):
    # Draw box-drawing chars
    # PROBLEM: cell is odd width, so no way to pixel-align veritcals
    # SOLUTION: leftwards on left of box, and rightwards on right side... two vertical lines
    # - same for top/bottom lines; except in that case we wanted to move inwards
    lw = 2      # line width
    w, h = CELL_W, CELL_H
    mw = (w // 2) - (lw//2)
    mh1 = (h // 2) - lw + 3+4    # top
    mh2 = (h // 2) - lw - 5    # bot
    if ch == '┃':
        print(f"{mw=} {mh1=} {mh2=}  CELL={CELL_W}x{CELL_H}")
        
    # erase old attempt from font
    draw.rectangle( (0,0, w, h), fill=0)

    # order of points matters (but it shouldn't)
    # - cannot do subpixel here, must be integer
    if ch == '┃':       # for left side of box
        draw.line( (mw-1, 0, mw-1, h), width=lw, fill=255)
    elif ch == '┇':     # for right side of box
        draw.line( (mw+2, 0, mw+2, h), width=lw, fill=255)
    elif ch == '━':     # top lines
        draw.line( (0, mh1, w, mh1), width=lw, fill=255)
    elif ch == '┅':     # bottom lines
        draw.line( (0, mh2, w, mh2), width=lw, fill=255)
    elif ch == '┓':
        draw.line( [(0, mh1), (mw+2, mh1), (mw+2, h)], width=lw, fill=255, joint='curve')
    elif ch == '┏':
        draw.line( [(mw, h), (mw, mh1), (w, mh1)], width=lw, fill=255, joint='curve')
    elif ch == '┛':
        draw.line( [(mw+2, 0), (mw+2, mh2+1), (0, mh2+1)], width=lw, fill=255, joint='curve')
    elif ch == '┗':
        draw.line( [(mw-1, 0), (mw-1, mh2), (w, mh2)], width=lw, fill=255, joint='curve')

    else:
        raise ValueError(ch)
    

def doit(out_fname='font_iosevka.py', cls_name='FontIosevka'):
    font = ImageFont.truetype(FONT, FONT_SIZE)
    keycap_font = ImageFont.truetype(FONT, FONT_SIZE-7)     # see KEY_NFC

    left, top, right, bottom = font.getbbox("|")
    char_h = bottom - top
    left, top, right, bottom = font.getbbox("M")
    char_w = right - left

    assert char_h <= CELL_H
    assert char_w <= CELL_W

    # want this one to fit in cell -- the worst descender?
    left, top, right, bottom = font.getbbox("j")
    y_offset = CELL_H - bottom - 1

    NUM_COL = 24
    samples = Image.new('L', (((CELL_W + 1) * NUM_COL) + 1,
                                ((CELL_H+1) * (NUM_CHARS//NUM_COL + 4))), 255)

    cells = Image.new('L', (CELL_W*NUM_CHARS*2, CELL_H), 0)

    data = {}
    pos = {}
    out_x = 0
    n = 0
    for ch in CHARSET:
        # render each one
        is_dbl = (ch in DBL_WIDTH)
        img = Image.new('L', CELL_SIZE if not is_dbl else DBL_CELL_SIZE)
        draw = ImageDraw.Draw(img)

        x_shift = 0
        left, top, right, bottom = font.getbbox(ch)
        if (right-left > CELL_W) and not is_dbl:
            # char is too wide: some will be lost
            if ch in '←↦':
                # keep left edge of these
                x_shift = -left
            elif ch in '→':
                # keep right edge of these
                x_shift = (CELL_W - (right-left))
            else:
                # center it
                x_shift = (CELL_W - (right-left)) / 2.0

        # Vertical tweaks
        this_y = 0
        if ch == '↳':
            # this one up a little, so arrow is more mid-line-ish
            # - looks awesome for random keyboard PIN entry mode
            this_y = -4
        if ch == '•':
            # bullet; needs perfect alignment inside full-cell box cursor
            #x_shift += 4.6      # right side of perfect (FOR DOUBLE WIDE)
            this_y = 1          # perfect

        if ch == KEY_TAB:
            # special code for tab keycap image
            draw.text((x_shift, y_offset + 0), '➡︎', 'white', font)
            draw.rectangle( ( 2,4, 2+2, CELL_H-7), 'white')
            draw.rectangle( ( 1,4, 1+1, CELL_H-7), 'black')
            #img.save('tab-key.png')
            draw.rounded_rectangle( ( 0,0, (CELL_W*2)-1, CELL_H-1), 4, outline='white')
            #img.save('tab-key-framed.png')
        elif ch in KEYCAP_SYMBOLS:
            if ch == KEY_NFC:
                x_shift += 1
            elif ch == KEY_QR:
                x_shift += 3
            else:
                x_shift += 3
            this_y += 5

            draw.text((x_shift, y_offset + this_y), REMAPS.get(ch, ch), 'white', keycap_font)

            # add a border
            draw.rounded_rectangle( ( 0,0, (CELL_W*2)-1, CELL_H-1), 4, outline='white')
        else:
            draw.text((x_shift, y_offset + this_y), REMAPS.get(ch, ch), 'white', font)

        if ch in LINEDRAW_SYMBOLS:
            # replace line draw stuff w/ own art (altho normal works)
            draw_linedrawing(ch, img, draw)

        # check 
        actual = img.getcolors()
        if ch not in ' █':
            assert len(actual) >= 2, f'blank char? {ch}'

        # build sample
        if is_dbl and (n % NUM_COL) == NUM_COL-1:
            n += 1
        samples.paste(img, box=(
                    ((n % NUM_COL) * (CELL_W+1)) + 1,
                    ((n // NUM_COL) * (CELL_H+1)) +1))
        n += (1 if not is_dbl else 2)

        # track actual pixels we'll use
        cells.paste(img, box=(out_x, 0))
        assert ch not in pos, repr(ch)
        pos[ch] = out_x
        out_x += img.width

        data[ch] = img

        #if ch in 'iM_0': img.show()
        #if ch in 'Aj': img.show()

    x, y = 0, (samples.height-CELL_H)
    for ch in 'Lazy dog jumpsX123':
        samples.paste(data[ch], box=(x, y))
        x += CELL_W

    x, y = (samples.width-(CELL_W*4)), (samples.height-(CELL_H*3))
    for n, ch in enumerate('┏━┓┃ ┇┗━┛'):
        if n in { 3, 6}:
            y += CELL_H
            x -= CELL_W * 3
        samples.paste(data[ch], box=(x, y))
        x += CELL_W

    # quantize the same, so they all share palette
    # - resulting pallette is not obvious: kinda an exponential curve between white/black

    #samples.show()         # before quant
    q_s = samples.quantize(colors=NUM_GREYS, method=Image.Quantize.MAXCOVERAGE).convert('L')
    #q_s.show()              # after quant
    q_s.save('sample.png')

    cells = cells.quantize(colors=NUM_GREYS, method=Image.Quantize.MAXCOVERAGE)
    #cells.convert('L').show()
    #colours = list(col for (cnt, col) in cells.getcolors())
    #print(f'Shades: {colours}')
    shades = cells.getpalette('RGB')
    assert set(shades[3*NUM_GREYS:]) == {0}     # unused positions in 8-bit /256 value pal
    shades = shades[0:3*NUM_GREYS]
    assert shades[0::3] == shades[1::3] == shades[2::3], 'not all greyscale?'


    # remap palette so it's in order by luma
    by_luma = sorted([(n, gl) for n, gl in enumerate(shades[0::3])], key=lambda x:x[1])
    mapping = list(n for n,gl in by_luma)

    # apply new palette
    cells = cells.remap_palette(mapping)
    nsh = cells.getpalette('RGB')[0::3]
    assert sorted(nsh) == nsh       # error here means wrong/no virtual env
    print(f'Shades: {nsh}')
    shades = nsh

    # remainder of file only tries to handle this case.
    assert NUM_GREYS == 16

    # slice into chars, packed and encoded by the palette
    results = []
    for n, ch in enumerate(CHARSET):
        is_dbl = (ch in DBL_WIDTH)
        x = pos[ch]
        w = CELL_W*2 if is_dbl else CELL_W

        here = cells.crop( (x, 0, x+w, CELL_H) ).tobytes()
        assert len(here) == w * CELL_H
        # pack into nibbles
        assert all(px < 16 for px in here)
        here = bytes((a<<4)|b for a,b in zip(here[0::2], here[1::2]))
        assert len(here) in (MEM_PER_CHAR, 2*MEM_PER_CHAR)

        if ch == ' ':
            # space should be blank = all zeros
            assert set(here) == {0}

        results.append((ch, here))

    BRAND_TEXT_COLOUR = (255, 176, 0)       # amber phospher colour #ffb000
    pal_nums, pal_vals, text_pal = make_palette(shades, BRAND_TEXT_COLOUR)
    _, pal_vals_inv, text_pal_inv = make_palette([255-i for i in shades], BRAND_TEXT_COLOUR)
    pal_dark_nums, _, text_pal_dark =  make_palette(shades, BRAND_TEXT_COLOUR, 0.66)

    # the "background" colour for the scroll bar
    scroll_dark = remap_colour(BRAND_TEXT_COLOUR, 0.33)

    with open(out_fname, 'w') as fp:
        tmpl = open('template.py').read()
        fp.write(tmpl)

        fp.write(f'''
#FONT_SHADES = {shades}
TEXT_PALETTES = [
 {text_pal}, #normal
 {text_pal_inv}, # inverted
 {text_pal_dark}, # darker
]

# same, but w/o byte swapping, packing (useful for simulator)
#TEXT_PALETTE = [{pal_vals}]
COL_TEXT = const(0x{pal_nums[15]:04x})   # text foreground colour
COL_DARK_TEXT = const(0x{pal_dark_nums[15]:04x})   # "dark" pallette text foreground colour
COL_SCROLL_DARK = const(0x{scroll_dark:04x})   # "dark" colour for scrollbar

CELL_W = const({CELL_W})
CELL_H = const({CELL_H})
BYTES_PER_CHAR = const({MEM_PER_CHAR})

#SPECIAL_CHARS = {[c for c in CHARSET if ord(c) >= 128]}

class {cls_name}:
    DOUBLE_WIDE = {DBL_WIDTH}

    @classmethod
    def lookup(cls, cp):
        # lookup glyph data for a single codepoint, or return None
        px = cls._data.get(cp)
        if not px: return None

        return GlyphInfo(len(px) * 2 // {CELL_H}, {CELL_H}, px)

    _data = ''' + '{\n')
        for ch, raw in results:
            fp.write(f'       {ch!r}: {raw},\n')
        fp.write('    }\n')
        

if __name__ == '__main__':
    doit()

# EOF
