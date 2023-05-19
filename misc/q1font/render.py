#!/usr/bin/env python
#
# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# render.py - Build compressed data for font rendering on the Q1.
#
import os, sys, pdb
from PIL import Image, ImageDraw, ImageFont, ImageColor
from collections import Counter

FONT = 'iosevka-extrabold.ttf'
FONT_SIZE = 18

# each character will be in a cell this size of pixels
# - yields final screen size, in chars of: 53x12
CELL_SIZE = (9, 22)

CELL_W, CELL_H = CELL_SIZE

print(f'Each char will be {CELL_W} x {CELL_H} pixels')
print(f'Screen will be {320//CELL_W} x {240//CELL_H} chars')

# quantization for unique grey levels, system-wide
NUM_GREYS = 8

CHARSET = [chr(x) for x in range(32,127)] + ['→', '←', '↳', '•', '⋯' ] + list('▋▼▲|')


def doit():
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
                                ((CELL_H+1) * (len(CHARSET)//NUM_COL + 2))), 255)

    data = {}
    for n, ch in enumerate(CHARSET):
        # render each one
        img = Image.new('L', CELL_SIZE)
        draw = ImageDraw.Draw(img)

        x_shift = 0
        left, top, right, bottom = font.getbbox(ch)
        if right-left > CELL_W:
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

        draw.text((x_shift, y_offset), ch, 'white', font)

        data[ch] = img

        samples.paste(img, box=(
                    ((n % NUM_COL) * (CELL_W+1)) + 1,
                    ((n // NUM_COL) * (CELL_H+1)) +1))

        actual = img.getcolors()
        if ch != ' ':
            assert len(actual) >= 2, f'blank char? {ch}'

        #if ch in 'iM_0': img.show()
        #if ch in 'Aj': img.show()

    x, y = 0, (samples.height-CELL_H)
    for ch in 'Lazy dog jumps 123':
        samples.paste(data[ch], box=(x, y))
        x += CELL_W

    #samples.show()
    q_s = samples.quantize(colors=NUM_GREYS, method=Image.Quantize.MAXCOVERAGE).convert('L')
    q_s.show()
    q_s.save('sample.png')

    # resulting pallette is not obvious: kinda an exponential curve between white/black
    palette = Image.new('L', (NUM_GREYS, 1))
    colours = list(sorted(col for (cnt, col) in q_s.getcolors()))
    for x, col in enumerate(colours):
        palette.putpixel( (x,0), col)
        assert x < NUM_GREYS

    #cv = cv.quantize(args.quantize, palette=palette, dither=Image.Dither.NONE)


if __name__ == '__main__':
    doit()

# EOF
