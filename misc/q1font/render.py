#!/usr/bin/env python
#
# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# render.py - Build compressed data for font rendering on the Q1.
#
import os, sys, pdb, math, zlib
from PIL import Image, ImageDraw, ImageFont, ImageColor
from collections import Counter

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

CHARSET = list(sorted(
            [chr(x) for x in range(32,127)] 
            + ['→', '←', '↳', '•', '⋯', '█', '▐', '⎸',
                '▼', '▲', '►', '◀',
                '₿', '✔', '™', '©',
              ]))
DBL_WIDTH = ['⋯', '✔︎', '→', '←']        # these are be better as double-wide chars
NUM_CHARS = len(CHARSET)

# use a different glyph for these unicode values
# - useful for multi-codepoint sequences, which we want to encode as single char
REMAPS = {
}

assert all(len(ch) == 1 for ch in CHARSET)      # hidden zero-width junk

MEM_PER_CHAR = int(round((math.log2(NUM_GREYS) * CELL_W * CELL_H) / 8, 0))
print(f'Font has {NUM_CHARS} chars')
print(f"Per char, memory: {MEM_PER_CHAR} bytes")
print(f"Total font memory: {NUM_CHARS * MEM_PER_CHAR // 1024} KiBytes")

# NOTE: compressing data per-char only saves 50% and requires 1k of ram to decompress
# plus lots of overhead, so don't do that.


def make_palette(shades, col):
    # make bytes representing a NUM_GREYS palette to map back to a RGB565 colour
    from struct import pack

    assert len(col) == 3, 'want RGB'
    assert col[0] > 20, 'expect 8-bit RGB values'
    col = [i/255.0 for i in col]
    assert max(col) <= 1.0
    assert 0 <= min(col)

    def remap(c, amt):
        amt /= 255.0
        r = int(c[0] * amt * 0x1f)
        g = int(c[1] * amt * 0x3f)
        b = int(c[2] * amt * 0x1f)

        return (r<<11) | (g << 5) | b

    assert len(shades) == NUM_GREYS
    vals = [remap(col, s) for s in shades]
    txt = ', '.join('0x%04x'% i for i in vals)
    return txt, pack('<%dH' % NUM_GREYS, *vals)

def doit(out_fname='font_iosevka.py', cls_name='FontIosevka'):
    font = ImageFont.truetype(FONT, FONT_SIZE)

    left, top, right, bottom = font.getbbox("|")
    char_h = bottom - top
    left, top, right, bottom = font.getbbox("M")
    char_w = right - left

    assert char_h <= CELL_H
    assert char_w <= CELL_W

    # want this one to fit in cell -- the worst descender?
    left, top, right, bottom = font.getbbox("j")
    y_offset = CELL_H - bottom - 1

    NUM_COL = 16
    samples = Image.new('L', (((CELL_W + 1) * NUM_COL) + 1,
                                ((CELL_H+1) * (NUM_CHARS//NUM_COL + 2))), 255)

    cells = Image.new('L', (CELL_W*NUM_CHARS*2, CELL_H), 0)

    data = {}
    pos = {}
    out_x = 0
    for n, ch in enumerate(CHARSET):
        # render each one
        is_dbl = (ch in DBL_WIDTH)
        img = Image.new('L', CELL_SIZE if not is_dbl else DBL_CELL_SIZE)
        draw = ImageDraw.Draw(img)

        x_shift = 0
        left, top, right, bottom = font.getbbox(ch)
        if (right-left > CELL_W) and not is_dbl:
            # char is too wide: some will be lost
            if ch in '←':
                # keep left edge of these
                x_shift = -left
            elif ch in '→':
                # keep right edge of these
                x_shift = (CELL_W - (right-left))
            else:
                # center it
                x_shift = (CELL_W - (right-left)) / 2.0

        draw.text((x_shift, y_offset), REMAPS.get(ch, ch), 'white', font)

        # check 
        actual = img.getcolors()
        if ch not in ' █':
            assert len(actual) >= 2, f'blank char? {ch}'

        # build sample
        samples.paste(img, box=(
                    ((n % NUM_COL) * (CELL_W+1)) + 1,
                    ((n // NUM_COL) * (CELL_H+1)) +1))

        # track actual pixels we'll use
        cells.paste(img, box=(out_x, 0))
        assert ch not in pos
        pos[ch] = out_x
        out_x += img.width

        data[ch] = img

        #if ch in 'iM_0': img.show()
        #if ch in 'Aj': img.show()

    x, y = 0, (samples.height-CELL_H)
    for ch in 'Lazy dog jumpsX123':
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
    assert sorted(nsh) == nsh
    print(f'Shades: {nsh}')
    shades = nsh

    # remainder of file only tries to handle this case.
    assert NUM_GREYS == 16

    # slice into chars, packed and encoded by the palette
    results = []
    size_avg = 0
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
    
    print(f"Avg char size: {size_avg / NUM_CHARS:.2f} bytes")

    pal_vals, text_pal = make_palette(shades, (255, 255, 255))

    with open(out_fname, 'w') as fp:
        tmpl = open('template.py').read()
        fp.write(tmpl)

        fp.write(f'''
FONT_SHADES = {shades}
TEXT_PALETTE = {text_pal}

# same, but w/o byte swapping, packing (useful for simulator)
#TEXT_PALETTE = [{pal_vals}]

CELL_W = const({CELL_W})
CELL_H = const({CELL_H})
BYTES_PER_CHAR = const({MEM_PER_CHAR})
#DOUBLE_WIDE = {DBL_WIDTH}

class {cls_name}:

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
