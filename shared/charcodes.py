# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Constants for Q1's keyboard.
#
# - using ascii internally
# - but 'key numbers' useful sometimes for some as well
# - power key is special, not a key (altho implemented in keyboard.py)
#
try:
    from micropython import const
    from version import has_qwerty
except ImportError:
    # this file also used by simulator.py and conftest.py
    const = int
    has_qwerty = True

# ascii key codes;
KEY_NFC = '\x0e'        # ctrl-N
KEY_QR = '\x11'         # ctrl-Q
KEY_TAB = '\t'          # tab = ctrl-I
KEY_ENTER = '\r'       # = CR
KEY_CANCEL = '\x1b'     # ESC = Cancel
KEY_LEFT = '\x03'           # ^B = left (incompatible)
KEY_UP = '\x0b'             # ^K = up on ADM-3A
KEY_RIGHT = '\x0c'          # ^L = right on ADM-3A
KEY_DOWN = '\x0a'           # ^J = LF = down on ADM-3A

KEY_PAGE_DOWN = '\x18'      # ^x 
KEY_PAGE_UP = '\x19'        # ^y
KEY_END = '\x1a'       # ^z
KEY_HOME = '\x1c'      # ^\

# these meta keys might not be visible to higher layers:
KEY_LAMP = '\x07'           # BELL = ^G
KEY_SHIFT = '\x01'
KEY_SPACE = ' '
KEY_SYMBOL = '\x02'
KEY_DELETE = '\x08'          # ^H = backspace
KEY_CLEAR = '\x15'           # ^U = clear entry

# save memory on Mk4
if has_qwerty:

    # function keys, filling gaps, running out of space!
    KEY_F1 = '\x0f'
    KEY_F2 = '\x12'
    KEY_F3 = '\x13'
    KEY_F4 = '\x14'
    KEY_F5 = '\x16'
    KEY_F6 = '\x17'
    KEYS_FUNCTION = KEY_F1 + KEY_F2 + KEY_F3 + KEY_F4 + KEY_F5 + KEY_F6

    NUM_ROWS = const(6)
    NUM_COLS = const(10)

    # (row, col) => keycode
    # - unused spots are \0
    # - these are unshifted values
    # - ten per row, gaps with zero
    DECODER = (KEY_NFC + KEY_TAB + KEY_QR 
                + KEY_LEFT + KEY_UP + KEY_DOWN + KEY_RIGHT + KEY_CANCEL + KEY_ENTER + '\0'
        + '1234567890'
        + 'qwertyuiop'
        + 'asdfghjkl\''
        + 'zxcvbnm,./'
        + KEY_LAMP + KEY_SHIFT + KEY_SPACE + KEY_SYMBOL + KEY_DELETE + '\0\0\0\0\0')

    # - same when shift is down
    # - make some unmarked combos dead (like shift+UP)
    # - but shift+' can be ", which really should be symb+'
    # - undocumented: shift+DEL => CLEAR
    DECODER_SHIFT = (
        '\0\0\0\0\0\0\0\0\0\0'
        + '!@#$%^&*()'
        + 'QWERTYUIOP'
        + 'ASDFGHJKL"'
        + 'ZXCVBNM<>?'
        '\0\0\0\0' + KEY_CLEAR + '\0\0\0\0\0' )

    # in caps mode: numbers unaffected, and also allow meta keys normally
    DECODER_CAPS = (KEY_NFC + KEY_TAB + KEY_QR
                + KEY_LEFT + KEY_UP + KEY_DOWN + KEY_RIGHT + KEY_CANCEL + KEY_ENTER + '\0'
        + '1234567890'
        + 'QWERTYUIOP'
        + "ASDFGHJKL\'"
        + 'ZXCVBNM,./'
        + KEY_LAMP + KEY_SHIFT + KEY_SPACE + KEY_SYMBOL + KEY_DELETE + '\0\0\0\0\0')

    # when SYMBOL pressed
    # - be nice and allow number+symbol == number+shift
    DECODER_SYMBOL = (KEY_NFC + KEY_TAB + KEY_QR 
                + KEY_HOME + KEY_PAGE_UP + KEY_PAGE_DOWN + KEY_END + KEY_CANCEL + KEY_ENTER + '\0'
        + '!@#$%^&*()'
        + '-_`\0\0\0[]{}'
        + '+\0\0=:;~|\\"'
        + KEY_F1 + KEY_F2 + KEY_F3 + KEY_F4 + KEY_F5 + KEY_F6 + '\0<>?'
        '\0\0\0\0\0\0\0\0\0\0' )

    KEYNUM_LAMP = const(50)
    KEYNUM_SHIFT = const(51)
    KEYNUM_SYMBOL = const(53)

    assert len(DECODER) == NUM_ROWS * NUM_COLS
    assert len(DECODER_SYMBOL) == NUM_ROWS * NUM_COLS
    assert len(DECODER_SHIFT) == NUM_ROWS * NUM_COLS
    assert DECODER[KEYNUM_SHIFT] == KEY_SHIFT
    assert DECODER[KEYNUM_SYMBOL] == KEY_SYMBOL
    assert DECODER[KEYNUM_LAMP] == KEY_LAMP

# These affect how 'ux stories' are rendered; they are control
# characters on the output side of things, not input.
OUT_CTRL_TITLE = '\x01'     # must be first char in line: be a title line
OUT_CTRL_ADDRESS = '\x02'   # must be first char in line: it's a payment address
OUT_CTRL_NOWRAP = '\x03'   # must be first char in line: do not word wrap this line

# EOF
