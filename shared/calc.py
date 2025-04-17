# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# calc.py - Simple TOY calculator, before login. Not meant to be useful, just fun!
#
# Test with: ./simulator.py --q1 --eff -g --set calc=1 
#
import utime, ngu, re
from utils import B2A, word_wrap
from ux_q1 import ux_input_text

async def login_repl():
    from glob import dis, settings
    from pincodes import pa

    NUM_LINES = 7       # 10 - title - 2 for prompt

    # recognise 12-12 / 12- but also accept underscore, or even space in pin: "12 12"
    re_prefix = re.compile(r'^(\d\d+)[-_]$')
    re_pin = re.compile(r'^(\d\d+)[-_ ](\d\d+)$')

    # in decreasing order of hazard...
    # - find these with: import builtins; help(builtins)
    blacklist = ['import', '__', 'exec', 'locals', 'globals', 'eval', 'input',
                    'getattr', 'setattr', 'delattr', 'open', 'execfile', 'compile' ]

    lines = '''\

Example Commands:
>> 23 + 55 / 22
>> 1.020 * 45.88
>> sha256('some message')
>> cls    # clear screen
>> help\
'''.split('\n')

    state = dict()
    state['sha256'] = lambda x: B2A(ngu.hash.sha256s(x))
    state['sha512'] = lambda x: B2A(ngu.hash.sha512(x).digest())
    state['ripemd'] = lambda x: B2A(ngu.hash.ripemd160(x))
    state['rand'] = lambda x=32: B2A(ngu.random.bytes(x))
    state['cls'] = lambda: lines.clear()
    state['help'] = lambda: 'Commands: ' + (', '.join(state))

    while 1:
        dis.clear()
        dis.text(0, 0, ' ECC Calculator ', invert=True)
        for i,ln in enumerate(lines):
            dis.text(0, i+1, ln, dark=ln.startswith('>> '))

        dis.text(0, -2, '━'*34, dark=True)
        dis.text(0, -1, '>> ')

        # prompt always a bottom of screen
        ln = await ux_input_text('', max_len=34-3, force_xy=(3, 9),
                        prompt='', min_len=1, scan_ok=True, placeholder=None)

        lines.append('>> ' + (ln or ''))
        ans = None
        try:
            dis.busy_bar(1)

            if ln is None :
                # Cancel key - do nothing
                ans = None
            elif ln in ('help', 'cls', 'rand'):
                # no need for () for these commands
                ans = state[ln]()
            elif re_pin.match(ln) and len(ln) <= 13:
                # try login
                m = re_pin.match(ln)
                ln = m.group(1)+ '-' + m.group(2)
                print(ln)
                try:
                    pa.setup(ln)
                    ok = pa.login()
                    if ok: return
                except RuntimeError as exc:
                    # I'm a brick and other stuff can happen here
                    # - especially AUTH_FAIL when pin is just wrong.
                    if exc.args[0] == 'AUTH_FAIL':
                        pa.attempts_left -= 1
                        ans = '%-7d          # %d tries remain' % (eval(ln), pa.attempts_left)
                    else:
                        ans = 'Error: ' + repr(exc.args)

            elif re_prefix.match(ln) and len(ln) <= 7:
                # show words
                ans = pa.prefix_words(ln[:-1].encode())
            else:
                if any((b in ln) for b in blacklist):
                    ans = None
                else:
                    ans = eval(ln, state.copy())

        except Exception as exc:
            lines.extend(word_wrap(str(exc), 34))
        finally:
            dis.busy_bar(0)

        if ans is not None:
            here = repr(ans) if not isinstance(ans, str) else ans
            lines.extend(word_wrap(here, 34))

        # trim lines to fit (scroll)
        lines = lines[-NUM_LINES:]


# EOF
