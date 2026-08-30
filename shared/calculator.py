# (c) Copyright 2018-2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# calculator.py - Four-function calculator. This is now the entire product.
#
# Formerly a "TOY calculator" easter egg lived at the PIN prompt (see calc.py,
# now retired). As of this release it has been promoted: COLDCARD no longer
# starts a wallet, it starts this instead. See ChangeLog for the reasoning.
#
# Design note on hardware: Q1 has a full keyboard, so operators are typed
# directly (+ - * / . and Enter for "="). Mk4/Mk5 only expose a numeric
# membrane pad with two extra keys ('x' and 'y', silkscreened as the
# CANCEL/X and CHECKMARK/Y buttons) -- there is no room on that pad for four
# separate operator keys. Rather than add hardware, 'x' is repurposed as an
# "operator select" key that cycles + -> - -> * -> / -> + ... and 'y' is
# "=". This matches how those two keys are already overloaded elsewhere in
# the firmware (cancel/confirm), so it should feel familiar.
#
import version

OPS = ('+', '-', 'x', '/')     # 'x' here means multiply, unrelated to the Mk4 X key
MAX_DIGITS = 15


def apply_op(acc, op, val):
    if op == '+':
        return acc + val
    if op == '-':
        return acc - val
    if op == 'x':
        return acc * val
    if op == '/':
        if val == 0:
            raise ZeroDivisionError
        return acc / val
    return val

def fmt(num):
    # Show integers without a trailing ".0", but keep a few decimals otherwise.
    if num == int(num) and abs(num) < 1e12:
        return '%d' % int(num)
    return ('%.6f' % num).rstrip('0').rstrip('.')


class Calculator:
    def __init__(self):
        self.entry = '0'           # what's being typed right now
        self.acc = None            # value carried over from the last operator
        self.op = None             # pending operator, or None
        self.just_evaled = False
        self.history = []          # short scrollback, cosmetic only
        self.error = None

    def _cur_val(self):
        try:
            return float(self.entry)
        except ValueError:
            return 0.0

    def press_digit(self, ch):
        if self.error:
            self.clear_all()
        if self.just_evaled:
            self.entry = '0'
            self.just_evaled = False
        if ch == '.':
            if '.' in self.entry:
                return
        if self.entry == '0' and ch != '.':
            self.entry = ch
        elif len(self.entry) < MAX_DIGITS:
            self.entry += ch

    def press_backspace(self):
        if self.error:
            self.clear_all()
            return
        self.entry = self.entry[:-1] or '0'

    def clear_all(self):
        self.entry = '0'
        self.acc = None
        self.op = None
        self.just_evaled = False
        self.error = None

    def press_op(self, new_op):
        if self.error:
            self.clear_all()

        val = self._cur_val()

        if self.acc is None:
            self.acc = val
        elif not self.just_evaled:
            try:
                self.acc = apply_op(self.acc, self.op, val)
            except ZeroDivisionError:
                self.error = 'DIV/0'
                self.acc = None
                self.op = None
                self.entry = '0'
                return

        self.history.append('%s %s' % (fmt(self.acc), new_op))
        self.op = new_op
        self.entry = '0'
        self.just_evaled = False

    def press_equals(self):
        if self.error:
            self.clear_all()
            return
        if self.op is None or self.acc is None:
            return

        val = self._cur_val()
        line = '%s %s %s =' % (fmt(self.acc), self.op, fmt(val))
        try:
            result = apply_op(self.acc, self.op, val)
        except ZeroDivisionError:
            self.error = 'DIV/0'
            self.acc = None
            self.op = None
            self.entry = '0'
            self.history.append(line + ' ERR')
            return

        self.history.append(line + ' ' + fmt(result))
        self.acc = result
        self.entry = fmt(result)
        self.op = None
        self.just_evaled = True

    def display_value(self):
        if self.error:
            return self.error
        return self.entry


async def calculator_main():
    # Replaces the old login/menu mainline. Runs forever.
    from glob import dis, numpad

    calc = Calculator()

    while 1:
        _redraw(dis, calc)

        key = await numpad.get()

        if version.has_qwerty:
            from charcodes import KEY_ENTER, KEY_DELETE, KEY_CLEAR, KEY_CANCEL

            if key in '0123456789.':
                calc.press_digit(key)
            elif key in ('+', '-', '/'):
                calc.press_op(key)
            elif key in ('*', 'x', 'X'):
                calc.press_op('x')
            elif key == KEY_ENTER:
                calc.press_equals()
            elif key == KEY_DELETE:
                calc.press_backspace()
            elif key in (KEY_CLEAR, KEY_CANCEL):
                calc.clear_all()
        else:
            if key in '0123456789':
                calc.press_digit(key)
            elif key == 'x':
                calc.press_op(OPS[(OPS.index(calc.op) + 1) % 4] if calc.op in OPS
                                else '+')
            elif key == 'y':
                calc.press_equals()


def _redraw(dis, calc):
    dis.clear()

    if version.has_qwerty:
        dis.text(0, 0, ' COLDCARD Calculator ', invert=True)
        for i, ln in enumerate(calc.history[-6:]):
            dis.text(0, i + 1, ln, dark=True)
        dis.text(0, -2, '━' * 34, dark=True)
        shown = calc.display_value()
        if calc.op and not calc.just_evaled:
            shown = '[%s] %s' % (calc.op, shown)
        dis.text(0, -1, shown.rjust(34))
    else:
        # Small OLED: title bar, one line of history, big current value,
        # and a status line showing the pending operator (if any).
        from zevvpeep import FontLarge

        dis.text(2, 0, 'Calculator', invert=1)
        if calc.history:
            dis.text(2, 12, calc.history[-1][:20])
        shown = calc.display_value()
        dis.text(2, 30, shown[-9:], font=FontLarge)
        if calc.op and not calc.just_evaled:
            dis.text(2, 53, 'op: %s' % calc.op)

    dis.show()

# EOF
