# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# unit test for address decoding for multisig
from h import a2b_hex, b2a_hex
from utils import xfp2str, str2xfp
from chains import BitcoinMain, BitcoinTestnet, BitcoinRegtest
from multisig import disassemble_multisig_mn
from public_constants import AF_CLASSIC, AF_P2SH, AF_P2WPKH, AF_P2WSH, AF_P2WPKH_P2SH, AF_P2WSH_P2SH
from public_constants import AFC_PUBKEY, AFC_SEGWIT, AFC_BECH32, AFC_SCRIPT, AFC_WRAPPED


pk =         a2b_hex('0202c68b0228cb577123c2f41275dadf8f4958890d3daf3728e38492f4913077dc')
script = a2b_hex('52210202c68b0228cb577123c2f41275dadf8f4958890d3daf3728e38492f4913077dc2102316dfd8d084a2b645061423013b52f513846e80c10816f66330f5609c8f6e7e221025328ece688cdc37d679b3af650f5d51487c1fe2fbd733b38cbfb58a9588a2155210288eb170b0661a6e86d1f1ab53a1099970d1b4d4cdd44d503d926effeec1e20842102fc3285261cccf4e7a44219758ee0383d25133b19a9fa14441ecb6ce9f3a4a52821038d00b6b4752dbba6afe6dcc00ef4b1fb0c212695f28a7908256808c2c201c43521038d5bcc32c89e363d181a08eb1c7613c0ba9aa02643d04cf00ae2cfea4192c9722103a11fd11e66e3d50818e3826a9b157245e6b361e32db9036768b54b4bc09adf092103d357b96bf98bcd5705d0f4745c2557d452d46a7cb9a6b193521de4516790f1182103f5bf5e00104c8956127ff926c0c5dd74690f8e67a21898cecb256dda34428a795aae')

M, N = disassemble_multisig_mn(script)

assert M == 2
assert N == 10
# assert pubkeys[0] == pk

#    assert keys == ['mpsMLTNqBNrsQuYNmZPj7ifqqMTSnZMMWH', 'mjoj9a1cFNPhvFkbrwzNPTBCWxhteAJHE5',
#                    'mkjqteuKMDApEzsZbdphtufvVPmCFafLhM', 'mvRSS7xmYBjDUEQsxvNefXLbwQHpwm76wb',
#                    'mhGBcrA9xDuBWttQLZFGRBJHcGEZyQpT3b', 'mkYFhxXQY6mMZbKxcuk6j6FD2Ff1gX6zgC',
#                    'mmgkFCdHKxCHuTMcJ9CPncRMA2UPainW6j', 'mg5fNCy7TJiZ8L4uxU3XerW2twNYAY3hmU',
#                    'myY1Xmhx6CdvFn6uzdUDo5EM2HxmsPXPJB', 'mozpwp3z32g9vBZxbpN6ySxx7A5EWw4Zfi']

addr = BitcoinMain.p2sh_address(AF_P2SH, script)
assert addr[0] == '3'
assert addr == '3Kt6KxjirrFS7GexJiXLLhmuaMzSbjp275'

addr = BitcoinTestnet.p2sh_address(AF_P2SH, script)
assert addr[0] == '2'
assert addr == '2NBSJPhfkUJknK4HVyr9CxemAniCcRfhqp4'

addr = BitcoinRegtest.p2sh_address(AF_P2SH, script)
assert addr[0] == '2'
assert addr == '2NBSJPhfkUJknK4HVyr9CxemAniCcRfhqp4'

addr = BitcoinMain.p2sh_address(AF_P2WSH, script)
assert addr[0:4] == 'bc1q', addr
assert len(addr) >= 62
assert addr == 'bc1qnjw7wy4e9tf4kkqaf43n2cyjwug0ystugum08c5j5hwhfncc4mkqftu4jr'

addr = BitcoinTestnet.p2sh_address(AF_P2WSH, script)
assert addr[0:4] == 'tb1q', addr
assert len(addr) >= 62
assert addr == 'tb1qnjw7wy4e9tf4kkqaf43n2cyjwug0ystugum08c5j5hwhfncc4mkq7r26gv'

addr = BitcoinRegtest.p2sh_address(AF_P2WSH, script)
assert addr[0:6] == 'bcrt1q', addr
assert len(addr) >= 64
assert addr == 'bcrt1qnjw7wy4e9tf4kkqaf43n2cyjwug0ystugum08c5j5hwhfncc4mkqn6quak'


assert xfp2str(0x10203040) == '40302010'
for i in 0, 1, 0x12345678:
    assert str2xfp(xfp2str(i)) == i
