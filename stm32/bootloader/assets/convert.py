#!/usr/bin/env python3
#
# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Plan:
# - take a fixed background image and compose a number of info screens ontop
# - RLE compress that and create binary object to go in flash
# - simple logo/border plus a large symbol in middle
# - one line of small text for english speakers
#
# pip3 install Pillow
#
import os
from PIL import Image, ImageOps, ImageFont, ImageDraw
from itertools import groupby

# screen size
WH = (128, 64)

ICON_SIZE = 24      # was 40 ... anything less than 24 is ugly.

# PROBLEM: this file costs money... altho free version looks okay too
if os.path.exists('FontAwesome5Pro-Light-300.otf'):
    awesome = ImageFont.truetype('FontAwesome5Pro-Light-300.otf', ICON_SIZE)
else:
    awesome = ImageFont.truetype('FontAwesome407.otf', ICON_SIZE)

sm_font = ImageFont.load('zevv-peep-iso8859-15-07x14.pil')
lg_font = ImageFont.load('zevv-peep-iso8859-15-10x20.pil')

# I loaded FontAwesome as a system font my desktop, and cut-n-pasted the symbols from FontBook.
# You can also copy the Unicode code point from the FA website.
icons = {
    'lemon':    '',
    'clock': '',
    'usb': '\uf287',
    'download': '',
    'history': '',
    'bug':  '',
    'x-circle':  '',
    #'bomb-spook':  ' ',        # bomb / half-space / sunglasses guy
    'bomb-spook':  '  ',        # bomb / spaces / sunglasses guy
    'spook':  '',        # sunglasses guy
    'recycle':  '\uf1b8',
    'trash':  '\uf2ed',
    'thumbs-down': '',
    'thumbs-up': '',
    'graph-up': '',
    'logout': '',
    'dots': '',
}

def make_background():
    img = Image.open('background.png').convert('1', dither=0)
    assert img.size == WH

    if 0:
        # LATER: this costs too many bytes!
        # add a logo
        logo = Image.open('chip-logo.png').convert('1', dither=0)
        img.paste(logo, (4,4))

    # version # .. but little time to see it, and consumes too much ROM
    #d = ImageDraw.Draw(img)
    #d.text( (128-20, 5), 'v1', font=sm_font, fill=1)

    return img

def make_frame(img, txt, icon_name, text_pos=None, icon_pos=3, icon_xpos=0):
    rv = img.copy()
    d = ImageDraw.Draw(rv)

    if icon_name:
        w,h = d.textsize(icons[icon_name], font=awesome)
        icon_pos += (40 - ICON_SIZE)/2
        d.text( (64-(w/2)+icon_xpos, icon_pos), icons[icon_name], font=awesome, fill=1)
        text_pos = text_pos or 56
    else:
        text_pos = text_pos or 40

    w,h = d.textsize(txt, font=sm_font)
    assert w <= 128, "Message too wide: " + repr(txt)
    d.text( (64-(w/2), text_pos-h), txt, font=sm_font, fill=1)

    return rv

def rev(n):
    return int('{:08b}'.format(n)[::-1], 2)

def rle_compress(orig):
    # simple RLE: 
    # - first byte is flag + length (flag mask=0x80)
    # - next byte is repeated length times if flag=0
    # - or folloing length bytes are sent verbatim
    # - must add up to full screen contents.
    # - add zero at end

    def flush(misc):
        rv = b''
        while misc:
            here = min(len(misc), 127)
            rv += bytes([0x80 + here]) + misc[0:here]
            misc = misc[here:]
        return rv

    out = b''
    misc = b''

    for ch, group in groupby(orig):
        dups = len(list(group))
        if dups <= 2:
            misc += bytes([ch] * dups)
            continue

        out += flush(misc)
        misc = b''

        while dups:
            here = min(dups, 127)
            out += bytes([0x00 + here, ch])
            dups -= here

    out += flush(misc)
            
    return out + b'\0'
            

def serialize(img, label, fp):

    img = ImageOps.mirror(img)
    #img = ImageOps.flip(img)

    assert img.size == WH, "wrong size: " + repr(img.size)

    img = img.rotate(-90, expand=1)
    assert img.size == (64, 128)

    img = ImageOps.mirror(img)
    img = ImageOps.flip(img)

    raw = img.tobytes()

    # OLED layout (dependant on settings during it's config)
    # - FF81818100.. will draw a C shape in top left corner
    #   raw = b'\xff\x81\x81\x81' + (b'\0'*1020)
    # - and each byte is reversed, etc.

    assert len(raw) == 64*128//8, "Wrong size?"

    reorg = bytearray(1024)
    j = 0
    for x in range(8):
        for y in range(128):
            reorg[j] = rev(raw[(y*8)+x])
            j += 1

    final = rle_compress(reorg)

    fp.write('const unsigned char %s[%d] = {\n' % (label, len(final)))
    fp.write(', '.join('0x%02x'%i for i in final))
    fp.write('\n};\n\n')

    return len(final)

# Actual screens and their contents:
#
results = [
    ( 'verify', 'Verifying', 'clock', {} ),
    ( 'blank', '. . .', None, dict(text_pos=36) ), # shown while we boot micropython (momentary)
    ( 'fatal', '#fwfail', None, {} ),           # don't waste space on rarely-seen screens
    ( 'brick', 'Bricked', None, {} ),           # was: icon=Trash / I am brick.
    #( 'dfu', 'Send Upgrade', 'download', {} ), # was beautiful, but won't be seen with RDP=2
    ( 'dfu', 'DFU', None, {} ),
    ( 'downgrade', 'Downgrade?', 'history', {} ),
    ( 'corrupt', 'Firmware?', 'lemon', {} ),
    ( 'logout', 'Logout Done', 'logout', {}),
    ( 'devmode', 'Danger! Caution!', 'bomb-spook', dict(icon_xpos=0)),       # was 2
    ( 'upgrading', 'Upgrading', 'graph-up', {}),
    ( 'replug', 'Replug', None, {}),        # visible in factory only
]

if __name__ == '__main__':
    prefix = 'screen_';
    out = open("screens.c", 'wt')
    out.write("// autogenerated by assets/convert.py\n\n")

    bg = make_background()
    sampler = Image.new('1', (128+8, len(results) * (64+8)), 1)
    
    y = 6
    total = 0
    for label, txt, icon, args in results:
        #icon = None     # XXX saves a lot of memory!
        img = make_frame(bg, txt, icon, **args)
        sampler.paste(img, (4, y))
        y += 64+4

        total += serialize(img, prefix+label, out)

    out.close()

    out = open("screens.h", 'wt')
    out.write("// autogenerated by assets/convert.py\n\n")

    for label, txt, icon, _ in results:
        out.write('\nextern const unsigned char %s[];\n\n' % (prefix+label))

    print("Files created! %d bytes ROM used. See 'sampler.png'" % total)
    #sampler.show()
    sampler.save('sampler.png')

