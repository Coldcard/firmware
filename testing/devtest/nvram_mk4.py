# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Unit test for shared/nvstore.py
#
# this will run on the simulator
# run manually with:
#   execfile('../../testing/devtest/nvram_mk4.py')
import os

import ustruct
from glob import settings
from nvstore import SLOTS, MK4_WORKDIR, NUM_SLOTS, MK4_FILENAME

def get_files():
    import os
    return [fn for fn in os.listdir(MK4_WORKDIR) if fn.endswith('.aes')]
def count_busy():
    return len(get_files())

# reset whatever's there
def reset_all():
    import os
    global get_files, MK4_WORKDIR
    for fn in get_files():
        os.remove('%s/%s' % (MK4_WORKDIR, fn))
        
# get defaults
reset_all()
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
    # fill it up, then will start overwriting random spots
    covered = set()
    for x in range(NUM_SLOTS*2):
        settings.nvram_key = ustruct.pack('I', x+47) + bytes(32-4)
        settings.load()
        settings.current['test'] = 123
        settings.save()
        covered.add(settings.my_pos)
        print("%8d" % x, end="\r")
    # some odds these will not be met:
    assert len(covered) >= len(SLOTS)-2, len(covered)
    assert len(get_files()) == NUM_SLOTS-1      # because save always deletes last one

# we should not get one of those previously written versions,
# because new (corrected) key
# restore to normal mode.
settings.nvram_key = b'\0' * 32
settings.load()
assert 'test' not in settings.current

# check we save w/o affecting existing
settings.set('zerokey', 1)
b4 = count_busy()
settings.save()
assert count_busy() == b4, "b4=%d cb=%d" % (b4, count_busy())

# check checksum/age stuff works
settings.set('wrecked', 768)
settings.save()

# clear slot
was_age = settings.get('_age')
os.remove(MK4_FILENAME(settings.my_pos))

settings.set('wrecked', 123)
settings.save()
assert settings.get('_age') == was_age+1
was_pos = settings.my_pos

# write old data everywhere else
for pos in SLOTS:
    if pos != was_pos: 
        try:
            os.remove(MK4_FILENAME(pos))
        except: pass

settings.load()
assert was_pos == settings.my_pos
assert settings.get('_age') == was_age+1
assert settings.get('wrecked') == 123

# try changing few bytes
b = bytearray(256)
with open(MK4_FILENAME(settings.my_pos), 'wb+') as fd:
    fd.seek(10)
    fd.write(b'\xff\x00')

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
reset_all()
settings.load()


