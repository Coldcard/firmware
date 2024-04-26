# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# random.py -  subset of random module, with no compat, and using crypto-quality rng
#
import ngu

# use this instead of rand%n
randbelow = ngu.random.uniform

# for bytes, use ngu.random.byte(len)
#bytes = ngu.random.bytes

# In-place list shuffle using Fisher-Yates algo
#
# see <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Implementation_errors>
#
def shuffle(lst):
    # cpython random.py:L286 -- Fisher-Yates

    for i in reversed(range(1, len(lst))):
        j = randbelow(i+1)
        lst[i], lst[j] = lst[j], lst[i]
        

# EOF
