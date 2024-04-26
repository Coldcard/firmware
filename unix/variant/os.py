# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# "uos" module on unix is even more limited compared to micropython version!
#
from uos import *

def sync():
    pass

def fsdecode(s):
    if type(s) is str:
        return s
    return str(s, "utf-8")

def listdir(path="."):
    is_bytes = isinstance(path, bytes)
    res = []
    for dirent in ilistdir(path):
        fname = dirent[0]

        if not is_bytes:
            fname = fsdecode(fname)
        if fname in ('.', '..'):
            continue
        res.append(fname)

    return res

# so wipe_microsd_card() can pretend to work
def mount(*a, **kws):
    return
def umount(*a):
    return

# EOF
