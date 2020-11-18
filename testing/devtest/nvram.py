# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Unit test for shared/nvstore.py
#
# this will run on the simulator
# run manually with:
#   execfile('../../testing/devtest/nvram.py')

from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex

import tcc, ustruct
from main import settings, sf
from nvstore import SLOTS

# reset whatever's there
sf.chip_erase()
settings.load()

for v in [123, 'hello', 34.56, dict(a=45)]:
    settings.set('abc', v)
    assert settings.get('abc') == v

a = settings.get('_age', -1)
settings.save()
assert settings.get('_age') >= a+1, [settings.get('_age'), a+1]

chk = dict(settings.current)
settings.load()

# some minor differences in values: bytes vs. strings, so just check keys
assert sorted(list(chk)) == sorted(list(settings.current)), \
    'readback fail: \n%r != \n%r' % (chk, settings.current)

if 1:
    # fill it up
    covered = set()
    for x in range(256):
        settings.nvram_key = ustruct.pack('I', x+47) + bytes(32-4)
        settings.load()
        assert settings.my_pos == 0     # it found a new spot
        settings.current['test'] = 123
        settings.save()
        covered.add(settings.my_pos)
    assert len(covered) == 32, len(covered)

# we should not get one of those previously written versions,
# because new (corrected) key
# restore to normal mode.
settings.nvram_key = b'\0' * 32
settings.load()
assert 'test' not in settings.current


def count_busy():
    from main import sf
    from nvstore import SLOTS

    busy = 0
    b = bytearray(4096)
    for pos in SLOTS:
        sf.read(pos, b)
        if len(set(b)) > 200:
            busy += 1
    return busy

# everything should be encrypted now
assert count_busy() == len(SLOTS)

# check we hide initial values
sf.chip_erase()
settings.load()
settings.save()
assert count_busy() == 4

# check checksum/age stuff works
settings.set('wrecked', 768)
settings.save()

b = bytearray(4096)
sf.read(settings.my_pos, b)
was_age = settings.get('_age')

settings.set('wrecked', 123)
settings.save()
assert settings.get('_age') == was_age+1
was_pos = settings.my_pos

# write old data everywhere else
for pos in SLOTS:
    if pos != was_pos: 
        for i in range(0, 4096, 256):
            sf.write(pos+i, b[i:i+256])

settings.load()
assert was_pos == settings.my_pos
assert settings.get('_age') == was_age+1
assert settings.get('wrecked') == 123

# try changing one byte
b = bytearray(256)
sf.read(settings.my_pos, b)
for i in range(10, 100):
    # can only change non-zero bytes (ie. clear bits)
    if b[i] != 0:
        b[i] = 0
        break
sf.write(settings.my_pos, b)

# will load older data here, since we just destroyed newer version
# but 1/32 times, we will have destroyed older version
settings.load()
found = settings.get('wrecked', None)
if found == 768:
    assert settings.get('_age') == was_age
else:
    assert found == None
    assert settings.get('_age') in {44, 42, 0}, settings.get('_age')

# test recovery/reset
sf.chip_erase()
settings.load()


