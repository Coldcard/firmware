import uio, sys

def do_usb_command(cmd, args):
    # TESTING commands!
    # - only to be implemented on the simulator!!
    # - pleaes don't freak out, stay calm
    # - if you can trick us into running this, can run anything worse directly
    # - and we don't ship this code on the real product, only part of simulator

    if cmd == 'XKEY':
        from main import numpad
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
