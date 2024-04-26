#!/usr/bin/env python3
#
# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Read in PNG (or even JPG) and output heavily compressed RGB565 data suited to Q1's LCD panel.
#
# - also renders status bar icons/indicators
#
import os, sys, pdb
from PIL import Image, ImageOps, ImageFont, ImageDraw
import zlib
from struct import pack

WBITS = -10

FONT_PATH = './fonts/'

def read_img(fn):
    img = Image.open(fn)
    w,h = img.size
    assert 1 <= w <= 320, f'too wide; {w}'
    assert 1 <= h <= 240, f'too tall: {h}'

    img = img.convert('RGB')

    # maybe: quantitize to a reasonable num colours, so compression
    # can work better?

    return img

def compress(n, wbits=WBITS):
    # NOTE: neg wbits implies no zlib header, and receiver may need to know it?
    z = zlib.compressobj(wbits=wbits, level=zlib.Z_BEST_COMPRESSION)
    rv = z.compress(n)
    rv += z.flush(zlib.Z_FINISH)
    return rv

def crunch(n):
    # try them all... not finding any difference tho.
    a = [(wb,compress(n, wb)) for wb in range(-9, -15, -1)]

    a.sort(key=lambda i: (-len(i[1]), -i[0]))

    print("Wbit values:")
    print('\n'.join("%3d => %d" % (wb,len(d)) for wb,d in a))

    return a[0]

# LCD Display wants RGB565 values, but big endian, so green gets split weird.
def swizzle(r,g,b):
    # from 0-255 per component => two bytes
    b = (b >> 3)
    g = (g >> 3)        # should be >> 2 for 6 bits; but looks trash?
    r = (r >> 3)

    return pack('>H', ((r<<11) | (g<<6) | b))

# these values tested on real hardware
assert swizzle(255, 0, 0) == b'\xf8\x00'        # red
##assert swizzle(0, 255, 0) == b'\xc0\x0f'        # green (6 bits)
assert swizzle(0, 255, 0) == b'\x07\xc0'        # green (5 bits)
assert swizzle(0, 0, 255) == b'\x00\x1f'        # blue

        
def into_bgr565(img):
    # get the raw bytes needed for this specific display
    rv = bytearray()
    for y in range(img.height):
        for x in range(img.width):
            px = img.getpixel((x, y))
            assert len(px) == 3
            r,g,b = px
            rv.extend(swizzle(r,g,b))

    return rv

def make_icons():
    # return list of (varname, img) for each image
    
    # - see  shared/lcd_display.py TOP_MARGIN for this
    ICON_SIZE = 14
    MAX_HEIGHT = 14

    # PROBLEM: this file costs money... altho free version looks okay too
    try:
        awesome = ImageFont.truetype(FONT_PATH + 'Font Awesome 6 Sharp-Regular-400.otf', ICON_SIZE)
    except:
        raise

    # use a bitmap font for best readability
    sm_font = ImageFont.load('ter-powerline-x12b.pil')

    targets = [
        #( 'brand', True, 'Q', dict(col='#ffb000') ),
        ( 'shift', True, 'SHIFT', {} ),
        ( 'symbol', True, 'SYM', {} ),
        ( 'caps', True, 'CAPS', {} ),
        ( 'bip39', True, 'PASSPHRASE', dict(col_1='yellow') ),
        ( 'tmp', True, 'TMP.SEED', dict(col_0='black', col_1='red') ),
        ( 'devmode', True, 'DEV', dict(col='#66E6FF') ),
        ( 'edge', True, 'EDGE', dict(col='#66E6FF') ),
        ( 'bat_0', False, '\uf244', dict(col='red', y=-1, pad=1)),
        ( 'bat_1', False, '\uf243', dict(col='yellow', y=-1, pad=1)),
        ( 'bat_2', False, '\uf242', dict(col='amber', y=-1, pad=1)),
        ( 'bat_3', False, '\uf240', dict(col='amber', y=-1, pad=1)),
        ( 'plugged', False, '\uf1e6', dict(col='amber', x=3, w=16, y=-2)),   # to match width of bat_*
        #( 'locked', False, '\uf023', dict(col='green')),
        #( 'unlocked', False, '\uf3c1', dict(col='green')),      # why tho?
    ]

    targets += [ ( 'ch_'+c, True, c.upper(), dict(col='white') ) for c in 
                    '0123456789abcdef']

    samples = Image.new('RGB', (320*3, ICON_SIZE+1))
    s_x = 5

    for basename, is_text, body, opts in targets:
        for state in [0, 1]:
            col = opts.get('col', '#fff' if state else '#444')
            vn = f'{basename}_{state}'

            if 'col' in opts:
                if state == 0: continue
                vn = basename

            if state == 0 and 'col_0' in opts:
                col = opts['col_0']
            if state == 1 and 'col_1' in opts:
                col = opts['col_1']

            img = Image.new('RGB', (100,100))
            d = ImageDraw.Draw(img)
            f = sm_font if is_text else awesome


            x, y = (0, 1 if is_text else 0)
            y += opts.get('y', 0)
            x += opts.get('x', 0)

            tl = (x, y)
            _,_, w,h = d.textbbox(tl, body, font=f)

            w = opts.get('w', w)

            if h > MAX_HEIGHT:
                h = MAX_HEIGHT
                print(f'"{vn}" too tall, cropped')
            elif opts.get('pad'):
                h = MAX_HEIGHT

            if col == 'amber':
                # brand colour
                col = '#ffb000'

            d.text(tl, body, font=f, fill=col)
            rv = img.crop( (0, 0, w,h) )

            samples.paste(rv, (s_x, 0))
            s_x += w + 10

            yield (vn, rv)
            
    samples = samples.crop( (0,0, s_x, samples.height ))
    samples.save('icon-samples.png')
            
    

def doit(outfname, fnames):

    assert outfname.endswith('.py')
    assert outfname != 'compress.py'
    assert fnames, "need some files"

    fp = open(outfname, 'wt')

    fp.write("""\
# autogenerated; don't edit
#
# BGR565 pixel data
#
class Graphics:
    # (w,h, data)

""")

    fnames += make_icons()

    for fn in fnames:
        if isinstance(fn, str):
            img = read_img(fn)
            varname = fn.split('/')[-1].split('.')[0].replace('-', '_')
        else:
            varname, img = fn

        assert img.mode == 'RGB'

        w,h = img.size
        raw = into_bgr565(img)
        comp = compress(raw)
        #crunch(raw)

        print("    %s = (%d, %d,\n     %r\n    )\n" % (varname, w, h, comp), file=fp)

        print("done: '%s' (%d x %d) => %d raw => %d compressed bytes" % (
                    varname, w, h, len(raw), len(comp)))

    fp.write("\n# EOF\n")

if 1:
    doit(sys.argv[1], sys.argv[2:])

# EOF
