# Regression tests for the simulator's LED pipe framing.
#
# simulator.py reads the LED pipe two bytes at a time: [mask, state]. Any writer
# that emits a different number of bytes desyncs the stream for good, and the
# reader eventually dies on `mask, lset = c` with a short read.
#
import ast, os, pytest

VARIANT_DIR = os.path.join(os.path.dirname(__file__), '..', 'unix', 'variant')

def led_pipe_writes():
    # yield (filename, lineno, bytes-literal) for each led_pipe.write(b'...') call
    for fn in sorted(os.listdir(VARIANT_DIR)):
        if not fn.endswith('.py'):
            continue
        path = os.path.join(VARIANT_DIR, fn)
        with open(path, 'rt') as fd:
            tree = ast.parse(fd.read(), filename=fn)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not (isinstance(f, ast.Attribute) and f.attr == 'write'):
                continue
            if not (isinstance(f.value, ast.Name) and f.value.id == 'led_pipe'):
                continue
            if not node.args:
                continue
            arg = node.args[0]
            # only constant byte strings can be checked statically
            if isinstance(arg, ast.Constant) and isinstance(arg.value, bytes):
                yield (fn, node.lineno, arg.value)

@pytest.mark.parametrize('fn, lineno, val', list(led_pipe_writes()))
def test_led_pipe_writes_are_two_bytes(fn, lineno, val):
    # every message on the LED pipe is exactly [mask, state]
    assert len(val) == 2, \
        "%s:%d writes %d byte(s) (%r) to led_pipe; must be 2: [mask, state]" \
                % (fn, lineno, len(val), val)

def test_led_pipe_writes_found():
    # guard against the scraper silently finding nothing
    assert len(list(led_pipe_writes())) >= 3

def test_led_pipe_stream_stays_aligned():
    # decode the real emitted sequence the way simulator.py does
    msgs = [v for _, _, v in led_pipe_writes()]

    r_fd, w_fd = os.pipe()
    tx = open(w_fd, 'wb', buffering=0)
    rx = open(r_fd, 'rb', closefd=0, buffering=0)
    try:
        for m in msgs:
            tx.write(m)
        tx.close()

        state = 0
        for _ in msgs:
            c = rx.read(2)
            assert len(c) == 2, "short read: %r - stream is desynced" % (c,)
            mask, lset = c
            state |= (mask & lset)
            state &= ~(mask & ~lset)

        assert rx.read(2) == b'', "trailing bytes left over - stream is desynced"
    finally:
        rx.close()
        os.close(r_fd)
