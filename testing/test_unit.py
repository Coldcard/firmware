# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Run tests on the simulator itself, not here... these are basically "unit tests"
#
import pytest, glob

def test_remote_exec(sim_exec):
    assert sim_exec("RV.write('testing123')") == 'testing123'

def test_codecs(sim_execfile):
    assert sim_execfile('devtest/segwit_addr.py') == ''

def test_public(sim_execfile):
    "verify contents of public 'dump' file"
    from pycoin.key.BIP32Node import BIP32Node
    from pycoin.contrib.segwit_addr import encode as sw_encode
    from pycoin.contrib.segwit_addr import decode as sw_decode
    from pycoin.encoding import a2b_hashed_base58, hash160

    pub = sim_execfile('devtest/dump_public.py')
    assert 'Error' not in pub

    #print(pub)

    pub, dev = pub.split('#DEBUG#', 1)
    assert 'pub' in pub
    assert 'prv' not in pub
    assert 'prv' in dev

    lines = [i.strip() for i in pub.split('\n')]

    for ln in lines:
        if ln[1:4] == 'pub':
            node_pub = BIP32Node.from_wallet_key(ln)
            break

    node_prv = BIP32Node.from_wallet_key(dev.strip())

    # pub and private are linked
    assert node_prv.hwif(as_private=False) == node_pub.hwif()

    # check every path we derived
    count = 0
    for ln in lines:
        if ln[0:1] == 'm' and '=>' in ln:
            subpath, result = ln.split(' => ', 1)

            sk = node_prv.subkey_for_path(subpath[2:])

            if result[1:4] == 'pub' and result[0] not in 'xt':
                # SLIP-132 garbage
                assert 'SLIP-132' in result
                result = result.split('#', 1)[0].strip()

                # just base58/checksum check
                assert a2b_hashed_base58(result)

            elif result[1:4] == 'pub':
                try:
                    expect = BIP32Node.from_wallet_key(result)
                except Exception as e:
                    if 'unknown prefix' in str(e):
                        # pycoin not yet ready for SLIP-132
                        assert result[0] != 'x'
                        print("SKIP: " + ln)
                        continue
                    raise
                assert sk.hwif(as_private=False) == result
            elif result[0] in '1mn':
                assert result == sk.address(False)
            elif result[0:3] in { 'bc1', 'tb1' }:
                h20 = sk.hash160()
                assert result == sw_encode(result[0:2], 0, h20)
            elif result[0] in '23':
                h20 = hash160(b'\x00\x14' + sk.hash160())
                assert h20 == a2b_hashed_base58(result)[1:]
            else:
                raise ValueError(result)

            count += 1
            print("OK: %s" % ln)
            

    assert count > 12


def test_nvram(unit_test):
    # exercise nvram simulation
    unit_test('devtest/nvram.py')

@pytest.mark.parametrize('mode', ['simple', 'blankish'])
def test_backups(unit_test, mode, set_seed_words):
    # exercise dump of pub data
    if mode == 'blankish':
        # want a zero in last byte of hex representation of raw secret...
        '''
        >>> tcc.bip39.from_data(bytes([0x10]*32))
        'avoid letter advice cage ... absurd amount doctor blanket'
        '''
        set_seed_words('avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor blanket')

    unit_test('devtest/backups.py')

def test_bip143(unit_test):
    # exercise hash digesting for bip143 signatures
    unit_test('devtest/unit_bip143.py')

def test_addr_decode(unit_test):
    # - runs som known examples thru CTxIn and check it categories, and extracts pubkey/pkh right
    unit_test('devtest/unit_addrs.py')

def test_clear_seed(unit_test):
    # just testing the test?
    unit_test('devtest/clear_seed.py')

def test_slip132(unit_test):
    # slip132 ?pub stuff
    unit_test('devtest/unit_slip132.py')

def test_multisig(unit_test):
    # scripts/multisig unit tests
    unit_test('devtest/unit_multisig.py')

def test_decoding(unit_test):
    # utils.py Hex/Base64 streaming decoders
    unit_test('devtest/unit_decoding.py')
# EOF
