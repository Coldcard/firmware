# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# menu.py - Implement an interactive menu system.
#
import gc
from main import dis
from display import FontLarge, FontTiny
from ux import PressRelease, the_ux
from uasyncio import sleep_ms

# number of (full) lines per screen full
PER_M = 4

class MenuItem:
    def __init__(self, label, menu=None, f=None, chooser=None, arg=None, predicate=None):
        self.label = label
        self.arg = arg
        if menu:
            self.next_menu = menu
        if f:
            self.next_function = f
        if chooser:
            self.chooser = chooser
        if predicate:
            self.predicate = predicate
    
    async def activate(self, menu, idx):

        if getattr(self, 'chooser', None):
            # get which one to show as selected, list of choices, and fcn to call after
            selected, choices, setter = self.chooser()

            def picked(menu, picked, xx_self):
                menu.chosen = picked
                menu.show()
                await sleep_ms(100)     # visual feedback that we changed it
                setter(picked, choices[picked])

                the_ux.pop()

            # make a new menu, just for the choices
            m = MenuSystem([MenuItem(c, f=picked) for c in choices], chosen=selected)
            the_ux.push(m)

        else:
            # nesting menus, and functions and so on.
            f = getattr(self, 'next_function', None)
            if f:
                rv = await f(menu, idx, self)
                if isinstance(rv, MenuSystem):
                    # XXX the function should do this itself
                    # go to new menu
                    the_ux.replace(rv)

            m = getattr(self, 'next_menu', None)

            if callable(m):
                m = await m(menu, idx, self)

            if isinstance(m, list):
                m = MenuSystem(m)

            if m:
                the_ux.push(m)

class MenuSystem:

    def __init__(self, menu_items, chosen=None, should_cont=None, space_indicators=False):
        self.should_continue = should_cont or (lambda: True)
        self.replace_items(menu_items)
        self.space_indicators = space_indicators
        self.chosen = chosen
        if chosen is not None:
            self.goto_idx(chosen)

    # subclasses: override us
    #
    def late_draw(self, dis):
        pass
    def early_draw(self, dis):
        pass

    def update_contents(self):
        # something changed in system state; maybe re-construct menu contents
        pass

    def replace_items(self, menu_items):
        self.cursor = 0
        self.ypos = 0
        self.items = [m for m in menu_items if not getattr(m, 'predicate', None) or m.predicate()]
        self.count = len(self.items)

    def show(self):
        #
        # Redraw the menu.
        #
        dis.clear()

        #print('cur=%d ypos=%d' % (self.cursor, self.ypos))

        # subclass hook
        self.early_draw(dis)

        x,y = (10, 2)
        h = 14
        for n in range(self.ypos+PER_M+1):
            if n+self.ypos >= self.count: break
            msg = self.items[n+self.ypos].label
            is_sel = (self.cursor == n+self.ypos)
            if is_sel:
                dis.dis.fill_rect(0, y, 128, h-1, 1)
                dis.icon(2, y, 'wedge', invert=1)
                dis.text(x, y, msg, invert=1)
            else:
                dis.text(x, y, msg)

            if msg[0] == ' ' and self.space_indicators:
                dis.icon(x-2, y+11, 'space', invert=is_sel)

            if self.chosen is not None and (n+self.ypos) == self.chosen:
                dis.icon(108, y, 'selected', invert=is_sel)

            y += h
            if y > 128: break

        # subclass hook
        self.late_draw(dis)

        if self.count > PER_M:
            dis.scroll_bar(self.ypos / (self.count-PER_M))

        dis.show()

    def down(self):
        if self.cursor < self.count-1:
            self.cursor += 1
        if self.cursor - self.ypos >= (PER_M-1):
            self.ypos += 1

    def up(self):
        if self.cursor > 0:
            self.cursor -= 1
            if self.cursor < self.ypos:
                self.ypos -= 1

    def top(self):
        self.cursor = 0
        self.ypos = 0

    def goto_n(self, n):
        # goto N from top of (current) screen
        # change scroll only if needed to make it visible
        self.cursor = max(min(n + self.ypos, self.count-1), 0)
        self.ypos = max(self.cursor - n, 0)

    def goto_idx(self, n):
        # skip to any item, force cusor near middle of screen
        self.cursor = n
        if n < PER_M-1:
            self.ypos = 0
        else:
            self.ypos = n - 2

    def page(self, n):
        # relative page dn/up
        if n == 1:
            for i in range(PER_M):
                self.down()
        else:
            for i in range(PER_M):
                self.up()

    # events
    def on_cancel(self):
        # override me
        if the_ux.pop():
            # top of stack (main top-level menu)
            self.top()

    async def activate(self, idx):
        # Activate a specific choice in our menu.
        #
        if idx is None:
            # "go back" or cancel or something
            self.on_cancel()
        else:
            assert idx < self.count
            ch = self.items[idx]

            await ch.activate(self, idx)


    async def interact(self):
        # Only public entry point: do stuff.
        #
        while self.should_continue() and the_ux.top_of_stack() == self:
            ch = await self.wait_choice()
            gc.collect()
            await self.activate(ch)
            
    async def wait_choice(self):
        #
        # Wait until a menu choice is picked; let them move around
        # the menu, keep redrawing it and so on.

        key = None

        # 5,8 have key-repeat, not others
        pr = PressRelease('790xy')

        while 1:
            self.show()

            key = await pr.wait()

            if not key:
                continue
            if key == '5':
                self.up()
            elif key == '8':
                self.down()
            elif key == '7':
                self.page(-1)       # maybe should back out of nested menus?
            elif key == '9':
                self.page(1)
            elif key == '0':
                # zip to top, no selection
                self.cursor = 0
                self.ypos = 0
            elif key in '1234':
                # jump down, based on screen postion
                self.goto_n(ord(key)-ord('1'))
            elif key == 'y':
                # selected
                return self.cursor
            elif key == 'x':
                # abort/nothing selected/back out?
                return None


#demo()
