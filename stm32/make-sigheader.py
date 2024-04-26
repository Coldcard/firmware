#!/usr/bin/env python3
#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

# parse out some values from C header... and include them into globals
def doit(c_fname, py_file):
    lines = []
    for ln in open(c_fname, 'rt').readlines():
        if ln.startswith('#define'):
            lines.append(ln.split(' ', 2)[1:])
        if ln.startswith('// '):
            lines.append(ln[3:])
        if not ln.strip():
            lines.append(None)

    with open(py_file, 'wt') as o:
        print("# Autogen'ed file, don't edit. See stm32/sigheader.h for original\n",file=o)

        for ln in lines:
            if ln is None:
                print('', file=o)
            elif len(ln) == 2:
                k,v = ln
                k = k.strip()
                v = v.strip()
                print('%s = %s' % (k, v), file=o)
            else:
                print('# '+ln.strip(), file=o)

        print("\n# EOF", file=o)

if __name__ == '__main__':
    doit('sigheader.h', 'sigheader.py')

# EOF
