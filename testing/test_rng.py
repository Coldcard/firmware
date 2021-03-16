# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Run tests on TRNG of the simulator or the real Coldcard (--dev flag).
#
# - needs "dieharder" installed, see 
#   <https://webhome.phy.duke.edu/~rgb/General/dieharder.php>
# - on mac: "brew install dieharder"
#
import pytest, subprocess, os
from helpers import B2A

@pytest.fixture(scope='module')
def dataset(sim_exec, blk_size=4096, num_bytes=1e6):
    # challenge: it's so slow to pull down enough random numbers to really pass
    # most of these tests. They want tens of millions of bytes...
    # - so do 1m once, save to disk
    # - delete rng.bin between runs if you want to get fresh data
    fname = 'rng.bin'

    if os.path.exists(fname):
        assert os.path.getsize(fname) >= num_bytes, f"delete {fname}"
        print("re-using data on-hand")
    else:
        with open(fname, 'wb') as fd:
            count = 0
            while count < num_bytes:
                blk = eval(sim_exec(f"import ngu; RV.write(repr(ngu.random.bytes({blk_size})))"))
                assert len(blk) == blk_size
                assert len(set(blk)) >= 250
                count += len(blk)
                print(f"    {count} so far", end='                      \r')

                fd.write(blk)

    yield fname

@pytest.mark.parametrize('testname', [ 'diehard_birthdays', 'diehard_2dsphere', 'diehard_3dsphere', 'diehard_sums', 'sts_monobit'])
def test_dieharder(testname, dataset):
    cmd = f'dieharder -g 201 -f {dataset} -d {testname}'
    print(f"CMD: {cmd}")
    rv = subprocess.check_output(cmd, shell=1, encoding='utf8')
    print(rv)
    assert ('PASSED' in rv) or ('WEAK' in rv)
    assert 'FAILED' not in rv

# EOF
