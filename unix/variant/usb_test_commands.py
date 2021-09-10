# items imported here may be useful to EVAL and EXEC commands, which tests depend on.
import uio, sys, version, nvstore, glob
try:
    from sflash import SF
except: pass
from glob import *

# Mk4:
#   copy this file to PSRAMdisk
#   a=open('/psram/usb_test_commands.py', 'rb').read()
#   open('/flash/lib/usb_test_commands.py', 'wb').write(a)

def do_usb_command(cmd, args):
    # TESTING commands!
    # - please don't freak out, stay calm.
    # - if you can trick us into running this, can run anything worse directly
    # - we don't ship this code on the real product
    # - commands must be upper case

    if cmd == 'XKEY':
        from glob import numpad
        try:
            numpad.inject(str(args, 'ascii'))
        except: pass
        return

    try:
        if cmd == 'EVAL':
            return b'biny' + repr(eval(str(args, 'utf8'))).encode()

        if cmd == 'EXEC':
            RV = uio.BytesIO()
            exec(str(args, 'utf8'), None, dict(RV=RV))
            return b'biny' + RV.getvalue()

    except BaseException as exc:
        tmp = uio.StringIO()
        sys.print_exception(exc, tmp)
        return b'biny' + tmp.getvalue().encode()

    return b'err_Unknown SIMULATOR cmd'
