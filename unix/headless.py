#!/usr/bin/env python
#
# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Simulate the hardware of a Coldcard.. except not: be headless.
# - does simulate USB (altho that's not here, but part of mpy code for simulator)
# - mostly for unit testing
#
# This is a normal python3 program, not micropython. It communicates with a running
# instance of micropython that simulates the micropython that would be running in the main
# chip.
#
import os, sys, tty, pty, termios, time, pdb
import subprocess

def start():
    print("\nColdcard Simulator (headless). Output below is from the simulated system:\n\n")

    # capture exec path and move into intended working directory
    mpy_exec = os.path.realpath('l-port/coldcard-mpy')
    env = os.environ.copy()
    env['MICROPYPATH'] = ':' + os.path.realpath('../shared')

    # placeholders for all UI objects
    oled_w = os.open('/dev/null', os.O_RDWR)
    led_w = os.open('/dev/null', os.O_RDWR)
    data_r, data_w = os.pipe()

    # manage unix socket cleanup for client
    def cleanup():
        try:
            os.unlink('/tmp/ckcc-simulator.sock')
        except: pass

    cleanup()
    import atexit
    atexit.register(cleanup)

    # XXX obsolete w/ Q changes?

    os.chdir('./work')
    cc_cmd = ['../coldcard-mpy',
              '-X', 'heapsize=9m',
              '-i', '../sim_boot.py',
              str(oled_w), '-1', str(led_w), str(data_r)
    ] + sys.argv[1:]

    args = dict(env=env, pass_fds=[oled_w, led_w], shell=False)

    if '-i' not in sys.argv:
        # we can do REPL, if given '-i' argument
        args['stdin'] = subprocess.DEVNULL
        #args['stdout'] = subprocess.DEVNULL

    child = subprocess.Popen(cc_cmd, **args)

    # always prefer to interrupt child, vs. us
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    rv = child.wait()
    if rv:
        print("\r\n<child stopped: %s>\r\n" % rv)

    child.kill()

if __name__ == '__main__':
    start()

# EOF
