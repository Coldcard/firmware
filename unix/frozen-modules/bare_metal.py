# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Replace the lower-level parts of the simulator with actual hardware.
#
# - bootrom's callgate is the common interface point (ckcc.gate function)
# - requires hardware to be controled over USB serial emulation
# - see simulator.py which adds '--metal' argument to setup and support this
# - called early in startup by sim_boot.py
# - quick test:    
#       make && ./simulator --metal -q
#       (in xterm)
#       import callgate; callgate.get_bl_version()
#

def start(req_fd, resp_fd):
    from ubinascii import hexlify as b2a_hex
    from ubinascii import unhexlify as a2b_hex

    req = open(req_fd, 'wt')
    resp = open(resp_fd, 'rb')

    # We are overriding the simulated version of the ckcc module.
    # see unix/frozen-modules/ckcc.py

    def my_gate(method, buf_io, arg2):
        import main
        main.RP = resp
        main.RQ = req

        bb = b2a_hex(buf_io).decode('ascii') if buf_io is not None else 'None'
        msg = '%d, %s, %d\n' % (method, bb, arg2)

        # send to real python
        req.write(msg)
        print("wait resp")
        ln = resp.readline().decode('ascii')

        print("R: " + ln)

        rv, buf = ln.strip().split(',')
        if len(buf):
            buf_io[:] = a2b_hex(buf.strip())

        return int(rv)

    def my_oneway(method, arg2):
        # will not be returning from this.
        my_gate(method, None, arg2)

    # monkey-patch in our versions.
    import ckcc
    del ckcc.pin_prefix
    ckcc.gate = my_gate
    ckcc.oneway = my_oneway
