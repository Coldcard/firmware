# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# random.py -  subset of random module, with no compat, and using crypto-quality rng
#
from ckcc import rng

# In-place list shuffle using Fisher-Yates algo
#
# see <https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Implementation_errors>
#
def shuffle(seq):
    for i in range(len(seq)-1, 0, -1):
        j = rng() % (i+1)
        seq[i], seq[j] = seq[j], seq[i]

# EOF
