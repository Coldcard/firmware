#!/usr/bin/env python
#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Connect to a real device, and allow simulator to use it's hardware for SE access.
#
# This is a normal python3 program, not micropython.
#
import os, sys, tty, pty, termios, time, pdb, tempfile
from PIL import Image
from select import select
import fcntl
from binascii import b2a_hex, a2b_hex


class BareMetal:
    #
    # Use a real Coldcard device's bootrom and Secure Elements
    #
    def __init__(self, req_r, resp_w):
        self.open()
        self.request = open(req_r, 'rt', closefd=0)
        self.response = open(resp_w, 'wb', closefd=0, buffering=0)

    def open(self, name='usbserial-AQ00T1RR'):
        # return a file-descriptor ready to be used for access to a real Coldcard's console I/O.
        # - assume only one coldcard
        import sys, serial
        from serial.tools.list_ports import comports

        for d in comports():
            if not name:
                if d.pid != 0xcc10: continue
            else:
                if name not in d.name: continue

            sio = serial.Serial(d.device, write_timeout=1, baudrate=115200)

            print("Connecting to: %s" % d.device)
            break
        else:
            raise RuntimeError("Can't find usb serial port for real Coldcard")

        self.sio = sio
        sio.timeout = 0.250

        if d.pid == 0xcc10:
            # USB mode a litte easier
            greet = sio.readlines()
            if greet and b'Welcome to Coldcard!' in greet[1]:
                sio.write(b'\x03')     # ctrl-C
                while 1:
                    sio.timeout = 1
                    lns = sio.readlines()
                    if not lns: break
        else:
            # real serial port
            sio.write(b'\x03')     # ctrl-C
            while 1:
                sio.timeout = 3
                lns = sio.readlines()
                print("ECHO: " + repr(lns))
                if not lns: break

        # hit enter, expect prompt
        sio.timeout = 0.100
        sio.write(b'\r')
        ln = sio.readlines()
        #assert ln[-1] == b'>>> ', ln
        #assert ln[-1] == b'=== ', ln
        assert ln[-1] in {b'>>> ',  b'=== '}, ln         #ok if in paste mode

        print(" Connected to: %s" % d.device)

        sio.write(b'''\x05\
from glob import dis
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex
import ckcc
dis.fullscreen("BareMetal")
try:
 busy = dis.busy_bar
except:
 busy = lambda x: None
\x04'''.replace(b'\n', b'\r'))

        # above is quick but will be echoed, so clear it out
        lns = self.wait_done()
        #print(f"setup: {lns}")


    def read_sflash(self):
        # capture contents of SPI flash (settings area only: last 128k)
        # XXX not working, and not for Mk4
        self.sio.write(b'''\x05\
busy(1)
from main import sf
dis.fullscreen("SPI Flash")
buf = bytearray(256)
addr = 0xe0000
for i in range(0, 0x20000, 256):
    sf.read(addr+i, buf)
    print(b2a_hex(buf).decode())
busy(0)
dis.fullscreen("BareMetal")
\x04\r'''.replace(b'\n', b'\r'))

        count = 0
        self.sio.timeout = 0.5
        for ln in self.sio.readlines():
            ln = ln.decode('ascii')
            if len(ln) == 512 + 2:
                self.response.write(ln[:-2].encode('ascii') + b'\n')
                count += 1
            elif ln.startswith('>>> '):
                break
            elif not ln or not ln.strip() or ln.startswith('=== ') or 'paste mode' in ln:
                pass
            else:
                print(f'junk: {ln}')

        assert count == (128*1024)//256, count

        print("Sent real SPI Flash contents to simulated Coldcard.")

    def wait_done(self, timeout=1):
        sio = self.sio
        sio.timeout = timeout
        rv = sio.read_until('>>> ')
        return [str(i, 'ascii') for i in rv.split(b'\r\n')]

    def readable(self):
        # expects   (method, hex, arg2) as string on one line
        ln = self.request.readline()

        arg1, bb, arg2 = ln.split(', ')

        method = int(arg1)
        arg2 = int(arg2)
        buf_io = a2b_hex(bb) if bb != 'None' else None

        if method == -99:
            # internal to us: read SPI flash contents
            return self.read_sflash()
        elif method in {2, 3}:
            # these methods always die; not helpful for testing
            print(f"FATAL Callgate(method={method}, arg2={arg2}) => execution would stop")
            self.response.write(b'0,\n')
            return

        sio = self.sio

        sio.timeout = 0.1
        sio.read_all()

        sio.write(b'\r\x05')      # CTRL-E => paste mode

        if buf_io is None:
            sio.write(b'bb = None\r')
        else:
            sio.write(b'bb = bytearray(a2b_hex("%s"))\r' % b2a_hex(buf_io))

        sio.write(b'busy(1)\r')
        sio.write(b'rv = ckcc.gate(%d, bb, %d)\r' % (method, arg2))
        sio.write(b'busy(0)\r')
        if buf_io is None:
            sio.write(b'print("%d," % rv)\r')
        else:
            sio.write(b'print("%d, %s" % (rv, b2a_hex(bb).decode()))\r')
        sio.write(b'\x04\r')        # CTRL-D, end paste; start exec

        lines = []
        for retries in range(10):
            lines.extend(self.wait_done())
            #print('back: \n' + '\n'.join( f'[{n}] {l}' for n,l in enumerate(lines)))
            if len(lines) >= 2 and lines[-1] == lines[-2] == '>>> ':
                break
        else:
            raise RuntimeError("timed out")

        # result is in lines between final === and first >>> ... typically a single
        # line, but might overflow into next 'line'
        assert '=== ' in lines and '>>> ' in lines
        a = -list(reversed(lines)).index('=== ')
        b = lines[a:].index('>>> ')
        rv = ''.join(lines[a:a+b]).strip()

        assert rv
        assert ',' in rv
        assert not rv.startswith('===')

        if 1:
            # trace output
            print(f"Callgate(method={method}, {len(buf_io) if buf_io else 0} bytes, "\
                    f"arg2={arg2}) => rv={rv}")

        self.response.write(rv.encode('ascii') + b'\n')
    
# EOF
