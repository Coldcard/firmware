# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import utime as time
import uerrno as errno
import sys

from machine import Pin

class USB_VCP:
    @staticmethod
    def isconnected():
        return True

    @staticmethod
    def any():
        return False

_umode = None

UNSET = object()
def usb_mode(nm=UNSET, **kws):
    global _umode

    if nm is not UNSET:
        #print("SET: usb_mode(%s)" % nm)
        _umode = nm

    return _umode

class USB_HID:
    fn = b'/tmp/ckcc-simulator.sock'

    def __init__(self):
        self.pipe = None
        self.last_from = None
        self._open()

    def _open(self):
        import sys
        import usocket as socket
        self.pipe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        # If on linux, try commenting the following line
        addr = bytes([len(self.fn)+2, socket.AF_UNIX] + list(self.fn))
        # If on linux, try uncommenting the following two lines
        #import struct
        #addr = struct.pack('H108s', socket.AF_UNIX, self.fn)
        while 1:
            try:
                self.pipe.bind(addr)
                break
            except OSError as exc:
                if exc.args[0] == errno.EADDRINUSE:
                    # handle restart after first run
                    import os
                    os.remove(self.fn)
                    continue
        
    def recv(self, buf, timeout=0):
        # recv-into, with from...
        if isinstance(buf, int):
            # can work in-place, or create buffer
            my_alloc = True
            maxlen = buf
        else:
            my_alloc = False
            maxlen = len(buf)

        if not timeout:
            self.pipe.setblocking(1)
            msg, frm = self.pipe.recvfrom(maxlen)
        else:
            self.pipe.setblocking(0)
            try:
                msg, frm = self.pipe.recvfrom(maxlen)
            except OSError as exc:
                if exc.args[0] == errno.EAGAIN:
                    return None if my_alloc else 0

        self.last_from = frm
        assert frm[2] != b'\0', "writer must bind to a name"

        if not _umode: return       # weak sauce

        #print("Rx[%d]: %r (from %r)" % (len(msg), msg, frm))

        assert _umode, "Got USB traffic, but disabled?"

        if my_alloc:
            return msg
        else:
            buf[0:len(msg)] = msg
            return len(msg)

    def send(self, buf):
        if not _umode: return  # weak sauce

        try:
            return self.pipe.sendto(buf, self.last_from)
        except OSError as exc:
            if exc.args[0] == errno.ENOENT:
                # caller is gone
                return None

    def _test(self):
        b = bytearray(64)
        while 1:
            count = self.recv(b)
            print("Tx[%d]: %r (from %r)" % (count, b, self.last_from))
            self.send(b)

class SDCard:
    ejected = bool('--eject' in sys.argv)

    @classmethod
    def present(cls):
        # after Q, this should not really be called anymore
        raise RuntimeError("avoid sd.present")
        if cls.ejected:
            return False
        SDCard.power(1)
        return True

    @classmethod
    def power(cls, st=0):
        # on real hardware, this resets the sdcard h/w module, which is important
        if st:
            time.sleep(0.100)       # drama
        return False

    @classmethod
    def info(cls):
        # num blocks, block size, "card type", CSD, CID registers
        return (493879296, 512, 0,
                    b'2\x00^\x00\xd6\x81Y[\x8f\xff\xb7\xed\x94\x00@\x16',
                    b'APA\tDU F\xd9\x92\x11\x10\x9a\x1a\x01\xdf')

    # so wipe_microsd_card() can pretend to work
    @classmethod
    def writeblocks(*a):
        pass


class ExtInt:
    def __init__(self, *a, **kw):
        return

    IRQ_RISING = 1
    IRQ_RISING_FALLING = 2

class Timer:
    def __init__(self, n):
        # hack in the fake "touch" for mark 2-4 boards.
        assert n == 7
        from touch import Touch
        Touch()

    def deinit(self): pass
    def init(self, **k): pass

# EOF
