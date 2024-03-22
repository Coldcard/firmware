# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Address ownership tests.
#
import pytest, time, random
from helpers import prandom
from binascii import a2b_hex
from txn import fake_address
from constants import AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
from constants import simulator_fixed_xprv, simulator_fixed_tprv, addr_fmt_names

@pytest.fixture
def wipe_cache(sim_exec):
    def doit():
        cmd = f'from ownership import OWNERSHIP; OWNERSHIP.wipe();'
        sim_exec(cmd)
    return doit


'''
    >>> [AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH]
        [14,       8,       26,            1,          7,         19]
'''
@pytest.mark.parametrize('addr_fmt', [
    AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH, AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
])
@pytest.mark.parametrize('testnet', [ False, True] )
def test_negative(addr_fmt, testnet, sim_exec):
    # unit test, no UX
    addr = fake_address(addr_fmt, testnet)

    cmd = f'from ownership import OWNERSHIP; w,path=OWNERSHIP.search({addr!r}); '\
            'RV.write(repr([w.name, path]))'
    lst = sim_exec(cmd)

    assert 'Explained' in lst

@pytest.mark.parametrize('addr_fmt', [
    AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH,
    #AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
])
@pytest.mark.parametrize('offset', [ 3, 760] )
@pytest.mark.parametrize('subaccount', [ 0, 34] )
@pytest.mark.parametrize('testnet', [ True, False ] )
@pytest.mark.parametrize('from_empty', [ False] )
def test_positive(addr_fmt, offset, subaccount, testnet, from_empty,
    sim_exec, wipe_cache, make_myself_wallet, use_testnet, goto_home, pick_menu_item,
    enter_number, press_cancel, settings_set
):
    from pycoin.key.BIP32Node import BIP32Node
    from bech32 import encode as bech32_encode
    from pycoin.encoding import b2a_hashed_base58, hash160

    if not testnet and addr_fmt in { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }:
        # multisig jigs assume testnet
        raise pytest.skip('testnet only')

    use_testnet(testnet)
    if from_empty:
        wipe_cache()        # very different codepaths
        settings_set('accts', [])

    coin_type = 1 if testnet else 0

    if addr_fmt in { AF_P2WSH, AF_P2SH, AF_P2WSH_P2SH }:
        from test_multisig import make_ms_address
        M = 1
        keys, select_wallet = make_myself_wallet(M, addr_fmt=addr_fmt_names[addr_fmt])
        expect_name = f'Myself-{M}of4'
        addr, scriptPubKey, script, details = make_ms_address(M, keys, idx=offset, addr_fmt=addr_fmt, testnet=int(testnet))
        path = fix + f'---/0/{offset}'
    else:
        if addr_fmt == AF_CLASSIC:
            menu_item = expect_name = 'Classic P2PKH'
            path = "m/44h/{ct}h/{acc}h"
        elif addr_fmt == AF_P2WPKH_P2SH:
            expect_name = 'P2WPKH-in-P2SH'
            menu_item = 'P2SH-Segwit'
            path = "m/49h/{ct}h/{acc}h"
        elif addr_fmt == AF_P2WPKH:
            menu_item = expect_name = 'Segwit P2WPKH'
            path = "m/84h/{ct}h/{acc}h"
        else:
            raise ValueError(addr_fmt)

        path_prefix = path.format(ct=coin_type, acc=subaccount)
        path = path_prefix + f'/0/{offset}'
        print(f'path = {path}')

        # see addr_vs_path
        mk = BIP32Node.from_wallet_key(simulator_fixed_tprv if testnet else simulator_fixed_xprv)
        sk = mk.subkey_for_path(path[2:].replace('h', "'"))

        if addr_fmt == AF_CLASSIC:
            addr = sk.address()
        elif addr_fmt == AF_P2WPKH_P2SH:
            pkh = sk.hash160(use_uncompressed=False)
            digest = hash160(b'\x00\x14' + pkh)
            addr = b2a_hashed_base58( bytes([196 if testnet else 5]) + digest)
        else:
            pkh = sk.hash160(use_uncompressed=False)
            addr = bech32_encode('tb' if testnet else 'bc', 0, pkh)
    
        if subaccount:
            # need to hint we're doing a non-zero acccount number
            goto_home()
            settings_set('axskip', True)
            pick_menu_item('Address Explorer')
            pick_menu_item('Account Number')
            enter_number(subaccount)
            pick_menu_item(menu_item)
            press_cancel()

    cmd = f'from ownership import OWNERSHIP; w,path=OWNERSHIP.search({addr!r}); '\
            'RV.write(repr([w.name, path]))'
    lst = sim_exec(cmd)
    if 'candidates without finding a match' in lst:
        # some kinda timing issue, but don't want big delays, so just retry
        print("RETRY search!")
        lst = sim_exec(cmd)
        
    assert 'Traceback' not in lst, lst

    lst = eval(lst)
    assert len(lst) == 2

    got_name, got_path = lst
    assert expect_name in got_name
    if subaccount:
        assert f'Acct#{subaccount}' in got_name

    assert got_path == (0, offset)


# EOF
