#!/usr/bin/env python3
#
# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Plan:
# - RLE compress that and create binary object to go in flash
# - large symbol in middle and some text under it
# - one line of small text for english speakers
# - limited or no colour; pixel expansion happens at run time.
#
# pip3 install Pillow
#
import os, pdb
from PIL import Image, ImageOps, ImageFont, ImageDraw
from itertools import groupby

# screen size
WH = (320, 240)
LCD_W = 320
LCD_H = 240

ICON_SIZE = 60      # anything less than 24 is ugly.

# PROBLEM: this file costs money... altho free version looks okay too
if os.path.exists('FontAwesome5Pro-Light-300.otf'):
    awesome = ImageFont.truetype('FontAwesome5Pro-Light-300.otf', ICON_SIZE)
else:
    awesome = ImageFont.truetype('FontAwesome407.otf', ICON_SIZE)

sm_font = ImageFont.load('zevv-peep-iso8859-15-10x20.pil')

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
    'ticket': '',
    'dots': '',
    'sdcard': '',
    'maglass': '',
    'insert-card': ' ',
    'search-card': ' ',
    'power': '',
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

def make_frame(img, txt, icon_name, text_pos=None, icon_pos=20, icon_xpos=0, crossout=False):
    rv = img.copy()
    d = ImageDraw.Draw(rv)

    CX = LCD_W // 2
    TH = LCD_H // 2
    GAP = 50

    if icon_name:
        _,_, w,h = d.textbbox((0,0), icons[icon_name], font=awesome)
        icon_pos += (TH - ICON_SIZE)/2
        d.text( (CX-(w/2)+icon_xpos, icon_pos), icons[icon_name], font=awesome, fill=1)
        text_pos = text_pos or TH+GAP
    else:
        text_pos = text_pos or TH

    _,_, w,h = d.textbbox((0,0), txt, font=sm_font)
    assert w <= LCD_W, "Message too wide: " + repr(txt)
    d.text( (CX-(w/2), text_pos-h), txt, font=sm_font, fill=1)

    if crossout:
        # ugly and covers info
        x,y = (CX-(w/2), text_pos-h)
        d.line( (x-2,y-2, x+w, y+h), fill=1)

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

    img = ImageOps.mirror(img)

    raw = img.tobytes()

    # LCD layout (dependant on settings during it's config)
    # - FF81818100.. will draw a C shape in top left corner
    #   raw = b'\xff\x81\x81\x81' + (b'\0'*1020)
    # - and each byte is reversed, etc.

    assert len(raw) == 320*240//8, "Wrong size?"

    if 0:
        reorg = bytearray(1024)
        j = 0
        for x in range(8):
            for y in range(128):
                reorg[j] = rev(raw[(y*8)+x])
                j += 1

    final = rle_compress(raw)

    fp.write('const unsigned char %s[%d] = {\n' % (label, len(final)))
    fp.write(', '.join('0x%02x'%i for i in final))
    fp.write('\n};\n\n')

    return len(final)

# Actual screens and their contents.
#
# - getting the exact hight/position of the text aligned w/ 8-bits helps alot sometimes
# - rare screens don't need to be pretty
#
results = [
    ( 'verify', 'Verifying', 'clock', {} ),
    ( 'blankish', '. . .', None, dict() ), # shown while we boot micropython (momentary)
    ( 'fatal', '#fwf', None, dict() ),    # don't waste space on rarely-seen screens
    ( 'mitm', '-/-', None, {} ),                # don't waste space on rarely-seen screens
    #( 'brick', '', 'ticket', dict(icon_pos=12) ),           # was: icon=Trash / I am brick.
    ( 'brick', 'Bricked', None, dict() ),           # was: icon=ticket
    #( 'dfu', 'Send Upgrade', 'download', {} ), # was beautiful, but won't be seen with RDP=2
    #( 'dfu', 'DFU', None, dict(text_pos=37) ), # removed
    ( 'downgrade', 'Downgrade?', 'history', {} ),
    ( 'corrupt', 'Firmware?', 'lemon', {} ),
    ( 'logout', 'Logout Done', 'logout', {}),
    ( 'poweroff', 'Power Off', 'power', {}),
    ( 'devmode', 'Danger! Custom!', 'bomb-spook', dict(icon_xpos=0)),       # was 2
    ( 'red_light', 'Danger! Caution!', 'bomb-spook', dict(icon_xpos=0)),       # was 2
    ( 'upgrading', 'Upgrading', 'graph-up', {}),
    ( 'replug', 'Power Cycle', None, {}),        # visible in factory only
    ( 'search', 'Searching...', 'search-card', {}),
    ( 'recovery', 'Insert Card', 'insert-card', {}),
    #( 'recovery', 'Recovery!', 'sdcard', {}),
    ( 'se1_issue', 'U4=SE1', 'bug', dict(crossout=0) ), 
    ( 'se2_issue', 'U5=SE2', 'bug', dict(crossout=0) ), 
    ( 'wiped', 'Seed Wiped', 'power', {}),
]

if __name__ == '__main__':
    prefix = 'screen_';
    out = open("q1_screens.c", 'wt')
    out.write("// autogenerated by assets/convert.py\n\n")

    bg = make_background()
    sampler = Image.new('1', (LCD_W+8, len(results) * (LCD_H+8)), 1)
    
    y = 6
    total = 0
    for label, txt, icon, args in results:
        if 0:
            # no icons at all
            icon = None
        elif 0:
            # minimal icons
            icon = None if label not in ('verify', 'devmode', 'logout', 'brick') else icon

        img = make_frame(bg, txt, icon, **args)
        sampler.paste(img, (4, y))
        y += LCD_H+4

        total += serialize(img, prefix+label, out)

    out.close()

    out = open("q1_screens.h", 'wt')
    out.write("// autogenerated by assets/convert.py\n\n")

    for label, txt, icon, _ in results:
        out.write('\nextern const unsigned char %s[];\n\n' % (prefix+label))

    print("Files created! %d bytes ROM used. See 'sampler.png'" % total)
    #sampler.show()
    sampler.save('sampler.png')

