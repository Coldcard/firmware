#!/usr/bin/env python3
#
# Generate some data for hsm_ux.py animation
#
from math import sin, pi
from collections import Counter

W = 128         # screen width
PW = 12         # width of eye
parts = 53      # of animation steps

dr = (2*pi) / parts
RW = W - PW - 1

ampl = (RW/2) + .5
offset = (W/2) - (PW/2)

rv = []
r = 0
for n in range(parts):
    x = (ampl * sin(r)) + offset
    x = int(x+.5)
    print(f'{n:2d}: {x:3d}   ' + (' '*x) + 'X')
    r += dr
    rv.append(x)

assert rv[0]+(PW//2) == W//2, rv[0]
assert max(rv) == W-PW, max(rv)
assert min(rv) == 0, min(rv)

# only want it to hesitate at the ends
cnt = Counter(rv).most_common()
assert max(c for x,c in cnt) == 2, repr(cnt)

print("\nResult: " + ', '.join(str(i) for i in rv))
print("\ncylon = %r" % bytes(rv))
