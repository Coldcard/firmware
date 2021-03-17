# "uos" module on unix is even more limited compared to micropython version!
#
from uos import *

def sync(): pass

'''
# lifted from https://github.com/micropython/micropython-lib/blob/master/os/os/__init__.py
import ffilib, uctypes
import ustruct as struct

libc = ffilib.libc()
opendir_ = libc.func("P", "opendir", "s")
readdir_ = libc.func("P", "readdir", "P")


def OBSOLETE_ilistdir(path="."):
    dir = opendir_(path)
    if not dir:
        raise OSError(2)        # ENOENT
    res = []
    dirent_fmt = "IHBB256s"     # XXX darwin specific?
    while True:
        dirent = readdir_(dir)
        if not dirent:
            break
        import uctypes
        dirent = uctypes.bytes_at(dirent, struct.calcsize(dirent_fmt))
        dirent = struct.unpack(dirent_fmt, dirent)
        dirent = (dirent[-1].split(b'\0', 1)[0], dirent[-2], dirent[0])
        yield dirent
'''

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

