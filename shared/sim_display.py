# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# DEBUG ONLY -- only installed for debug builds
# Hack to monitor screen contents, as text.
# Import this file to install the hacks.
#
import ux, version

global contents, full_contents, story

# dictionary, where key is the line number on screen, and rest is text line
contents = {}

# text string of screen, using newlines
full_contents = ''

# copy of the story being shown
story = None

if version.hw_label == 'q1':
    from lcd_display import Display
    has_lcd = True
else:
    from display import Display
    has_lcd = False

orig_text = Display.text
orig_clear = Display.clear
orig_show = Display.show


if not has_lcd:
    Display.text = lambda *a, **kw: hack_text(*a, **kw)
    def hack_text(themself, *a, **kw):
        #print('of=%r ts=%r a=%r kw=%r' % (orig_func, themself, a, kw))

        x, y, msg = a[0:3]

        global contents
        contents[y] = msg

        #print('text (%s, %s): %s' % (x,y, msg))

        return orig_text(themself, *a, **kw)

    Display.clear = lambda *a, **kw: hack_clear(*a, **kw)
    def hack_clear(themself, *a, **kw):
        global contents
        contents = {}
        return orig_clear(themself, *a, **kw)

Display.show = lambda *a, **kw: hack_show(*a, **kw)
def hack_show(themself, *a, **kw):
    global contents, full_contents

    if not has_lcd:
        scr = '\n'.join(contents[y] for y in sorted(contents))
        #print("\n---\n%s\n---\n" % scr)
        full_contents = scr
    else:
        lines = [themself.next_buf[y] for y in range(10)]
        lines = [bytes(i&0x7f for i in ln).decode('ascii') for ln in lines]
        full_contents = '\n'.join(i.strip() for i in lines)
        
    return orig_show(themself, *a, **kw)


# Also monitor "UX stories"

orig_show_story = ux.ux_show_story

async def hack_story(msg, title=None, **kw):
    global story

    if hasattr(msg, 'readline'):
        story = (title or 'NO-TITLE', msg.getvalue())
    else:
        story = (title or 'NO-TITLE', msg)

    #print("Story: %s: %s" % (title, msg))

    rv = await orig_show_story(msg, title, **kw)

    story = None
    
    return rv
ux.ux_show_story = hack_story

# remove pauses that lengthen test case times...
async def no_drama(msg, seconds):
    print("Pause (%ds): %s" % (seconds, msg))
ux.ux_dramatic_pause = no_drama

# EOF
