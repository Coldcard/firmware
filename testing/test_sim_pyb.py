# Regression tests for the simulator's `pyb` stand-in module.
#
# unix/variant/pyb.py fakes the pyb module for the unix simulator. Anything the
# shared firmware reaches for on `pyb` has to exist there, or the simulator dies
# with AttributeError at the moment that code path runs - which is typically deep
# in a menu action, long after boot.
#
import ast, os, pytest

HERE = os.path.dirname(__file__)
PYB = os.path.join(HERE, '..', 'unix', 'variant', 'pyb.py')
SHARED = os.path.join(HERE, '..', 'shared')

# used only on the real device: shared/usb.py guards it with `if is_simulator()`
GUARDED = {'hid_keyboard'}

def pyb_tree():
    with open(PYB, 'rt') as fd:
        return ast.parse(fd.read(), filename='pyb.py')

def sim_pyb_names():
    # top-level names the simulator's pyb module provides
    names = set()
    for node in pyb_tree().body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names

def pyb_attrs_used():
    # every pyb.<attr> the shared firmware references
    used = {}
    for fn in sorted(os.listdir(SHARED)):
        if not fn.endswith('.py'):
            continue
        try:
            with open(os.path.join(SHARED, fn), 'rt') as fd:
                src = fd.read()
        except OSError:
            continue        # symlink into an uninitialized submodule
        tree = ast.parse(src, filename=fn)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == 'pyb'):
                used.setdefault(node.attr, []).append('%s:%d' % (fn, node.lineno))
    return used

def load_flash_class():
    # compile just the Flash class - pyb.py as a whole imports utime/usocket,
    # which don't exist off-device
    for node in pyb_tree().body:
        if isinstance(node, ast.ClassDef) and node.name == 'Flash':
            mod = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(mod)
            ns = {}
            exec(compile(mod, 'pyb.py', 'exec'), ns)
            return ns['Flash']
    return None

@pytest.mark.parametrize('attr', sorted(a for a in pyb_attrs_used() if a not in GUARDED))
def test_pyb_attr_exists_in_simulator(attr):
    # every pyb.<attr> the firmware uses must exist in the simulator's stand-in
    where = ', '.join(pyb_attrs_used()[attr])
    assert attr in sim_pyb_names(), \
        "shared/ uses pyb.%s (%s) but unix/variant/pyb.py does not define it" % (attr, where)

def test_flash_is_a_block_device():
    # files.py wipe_flash_filesystem() drives it as a block device
    Flash = load_flash_class()
    assert Flash is not None, "unix/variant/pyb.py defines no Flash class"

    fl = Flash(start=0)         # files.py:59 - "start=0 does magic things"

    BP_IOCTL_SEC_COUNT, BP_IOCTL_SEC_SIZE = 4, 5
    bsize = fl.ioctl(BP_IOCTL_SEC_SIZE, 0)
    assert bsize == 512, "files.py asserts bsize == 512, got %r" % (bsize,)

    bcount = fl.ioctl(BP_IOCTL_SEC_COUNT, 0)
    assert isinstance(bcount, int) and bcount > 0, \
        "sector count must be a positive int, got %r" % (bcount,)

    # the wipe writes a full block of random bytes to every sector
    fl.writeblocks(0, bytearray(bsize))
    fl.writeblocks(bcount - 1, bytearray(bsize))
