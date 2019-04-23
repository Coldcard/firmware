# Hack to monitor screen contents, as text.
# Import this file to install the hacks.

global contents, full_contents, story

# dictionary, where key is the line number on screen, and rest is text line
contents = {}

# text string of screen, using newlines
full_contents = ''

# copy of the story being shown
story = None


from display import Display

orig_text = Display.text
orig_clear = Display.clear
orig_show = Display.show

Display.text = lambda *a, **kw: hack_text(*a, **kw)
Display.clear = lambda *a, **kw: hack_clear(*a, **kw)
Display.show = lambda *a, **kw: hack_show(*a, **kw)

def hack_text(themself, *a, **kw):
    #print('of=%r ts=%r a=%r kw=%r' % (orig_func, themself, a, kw))

    x, y, msg = a[0:3]

    global contents
    contents[y] = msg

    #print('text (%s, %s): %s' % (x,y, msg))

    return orig_text(themself, *a, **kw)

def hack_clear(themself, *a, **kw):
    global contents
    contents = {}
    return orig_clear(themself, *a, **kw)

def hack_show(themself, *a, **kw):
    global contents, full_contents
    scr = '\n'.join(contents[y] for y in sorted(contents))

    #print("\n---\n%s\n---\n" % scr)
    full_contents = scr
        
    return orig_show(themself, *a, **kw)


# Also monitor "UX stories"
import ux

orig_show_story = ux.ux_show_story

ux.ux_show_story = lambda *a, **kw: hack_story(*a, **kw)

def hack_story(*a, **kw):
    msg = a[0]
    title = kw.get('title', 'NO-TITLE')

    global story

    if hasattr(msg, 'readline'):
        story = (title, msg.getvalue())
    else:
        story = (title, msg)

    #print("Story: %s: %s" % (title, msg))

    return orig_show_story(*a, **kw)

# And menus

def read_menu():
    # helper: return contents of current menu
    from ux import the_ux
    from menu import MenuSystem

    top = the_ux.top_of_stack()
    if not top: return None

    if not isinstance(top, MenuSystem):
        return repr(top)

    return list(it.label for it in top.items)
    

# EOF
