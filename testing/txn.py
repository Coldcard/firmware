# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Creating fake transactions. Not simple.
#
import pytest, struct, os
from ckcc_protocol.protocol import MAX_TXN_LEN
from psbt import BasicPSBT, BasicPSBTInput, BasicPSBTOutput
from io import BytesIO
from helpers import fake_dest_addr, make_change_addr, hash160, taptweak, str_to_path
from base58 import decode_base58
from bip32 import BIP32Node
from constants import simulator_fixed_tprv
from serialize import uint256_from_str
from ctransaction import CTransaction, COutPoint, CTxIn, CTxOut


@pytest.fixture
def fake_txn(dev, pytestconfig):
    # make various size txn's ... completely fake and pointless values
    # - but has UTXO's to match needs
    # - input total = num_inputs * 1BTC

    def doit(inputs, outputs, master_xpub=None, psbt_hacker=None,
             add_xpub=None, psbt_v2=None, fee=200, addr_fmt="p2wpkh",
             input_amount=100_000_000, capture_scripts=None): # sats

        psbt = BasicPSBT()

        # support old argument types
        if isinstance(inputs, int):
            num_ins = inputs
            inputs = range(num_ins)
        else:
            num_ins = len(inputs)

        if isinstance(outputs, int):
            num_outs = outputs
            outputs = range(num_outs)
        else:
            num_outs = len(outputs)

        if psbt_v2 is None:
            # anything passed directly to this function overrides
            # pytest flag --psbt2 - only care about pytest flag
            # if psbt_v2 is not specified (None)
            psbt_v2 = pytestconfig.getoption('psbt2')

        if psbt_v2:
            psbt.version = 2
            psbt.txn_version = 2
            psbt.input_count = num_ins
            psbt.output_count = num_outs

        txn = CTransaction()
        txn.nVersion = 2
        master_xpub = master_xpub or dev.master_xpub or simulator_fixed_tprv
        
        # we have a key; use it to provide "plausible" value inputs
        my_mk = BIP32Node.from_wallet_key(master_xpub)
        my_xfp = my_mk.fingerprint()

        foreign_mk = BIP32Node.from_master_secret(os.urandom(32))
        foreign_xfp = foreign_mk.fingerprint()

        psbt.inputs = [BasicPSBTInput(idx=i) for i in range(num_ins)]
        psbt.outputs = [BasicPSBTOutput(idx=i) for i in range(num_outs)]

        inp_total = 0
        added_mine = False
        added_foreign = False
        for i, inp in enumerate(inputs):
            sp = f"0/{i}"
            af = addr_fmt
            ia = input_amount
            is_mine = True
            try:
                if inp[0] is not None:
                    af = inp[0]
                if inp[1] is not None:
                    sp = inp[1]
                if inp[2] is not None:
                    ia = inp[2]
                is_mine = inp[3]
            except: pass

            # make a fake txn to supply each of the inputs
            # - each input is 1BTC if not specified otherwise
            inp_total += ia

            # will this be my input that I cna sign
            if is_mine:
                mk = my_mk
                mfp = my_xfp
                added_mine = True
            else:
                mk = foreign_mk
                mfp = foreign_xfp
                added_foreign = True

            # addr where the fake money will be stored.
            int_path = str_to_path(sp)
            subkey = mk.subkey_for_path(sp)
            sec = subkey.sec()
            assert len(sec) == 33, "expect compressed"

            is_segwit = True
            if af == "p2tr":
                tweaked_xonly = taptweak(sec[1:])
                psbt.inputs[i].taproot_bip32_paths[sec[1:]] = b"\x00" + mfp + struct.pack(f'<{"I"*len(int_path)}', *int_path)
                scr = bytes([81, 32]) + tweaked_xonly

            elif af in ("p2wpkh", "p2sh-p2wpkh", "p2wpkh-p2sh"):
                psbt.inputs[i].bip32_paths[sec] = mfp + struct.pack(f'<{"I"*len(int_path)}', *int_path)
                scr = bytes([0x00, 0x14]) + subkey.hash160()

                if af != "p2wpkh":
                    # use classic p2wpkh (from above) as redeem script
                    psbt.inputs[i].redeem_script = scr
                    scr = bytes([0xa9, 0x14]) + hash160(scr) + bytes([0x87])

            elif af == "p2pkh":
                is_segwit = False
                psbt.inputs[i].bip32_paths[sec] = mfp + struct.pack('<II', 0, i)
                scr = bytes([0x76, 0xa9, 0x14]) + subkey.hash160() + bytes([0x88, 0xac])

            else:
                raise ValueError("unknown addr_fmt %s" % af)


            # UTXO that provides the funding for to-be-signed txn
            supply = CTransaction()
            supply.nVersion = 2
            out_point = COutPoint(
                uint256_from_str(struct.pack('4Q', 0xdead, 0xbeef, 0, 0)),
                73
            )
            supply.vin = [CTxIn(out_point, nSequence=0xffffffff)]
            supply.vout.append(CTxOut(ia, scr))

            if is_segwit:
                # just utxo for segwit
                psbt.inputs[i].witness_utxo = supply.vout[-1].serialize()
            else:
                # whole tx for pre-segwit
                psbt.inputs[i].utxo = supply.serialize_with_witness()

            supply.calc_sha256()

            if psbt_v2:
                psbt.inputs[i].previous_txid = supply.hash
                psbt.inputs[i].prevout_idx = 0
                # TODO sequence
                # TODO height timelock
                # TODO time timelock
            else:
                spendable = CTxIn(COutPoint(supply.sha256, 0), nSequence=0xffffffff)
                txn.vin.append(spendable)

        # calculate fee
        if num_outs:
            output_amount = int((inp_total - fee) / num_outs)
            for i, out in enumerate(outputs):
                change = False
                data = None
                af = addr_fmt
                oa = output_amount
                try:
                    if out[0] is not None:
                        af = out[0]
                    if out[1] is not None:
                        oa = out[1]
                    change = out[2]
                    data = out[3]
                except: pass

                if af == "op_return":
                    op_return_size = len(data)
                    act_scr = isw = None
                    if op_return_size < 76:
                        # OP_RETURN PUSHDATA
                        scr = bytes([106, op_return_size]) + data
                    elif op_return_size < 256:
                        # OP_RETURN PUSHDATA1
                        scr = bytes([106, 76, op_return_size]) + data
                    elif op_return_size < 65536:
                        # OP_RETURN PUSHDATA2
                        scr = bytes([106, 77]) + struct.pack(b'<H', op_return_size) + data
                    else:
                        assert False, "too big OP_RETURN"

                elif (af == "unknown") and data:
                    act_scr = isw = None
                    scr = bytes.fromhex(data)

                elif change:
                    scr, act_scr, isw, pubkey, sp = make_change_addr(mk, af)
                    if len(pubkey) == 32:  # xonly
                        psbt.outputs[i].taproot_bip32_paths[pubkey] = sp
                    else:
                        psbt.outputs[i].bip32_paths[pubkey] = sp
                else:
                    scr = act_scr = fake_dest_addr(af)
                    isw = ('w' in af)

                assert scr
                act_scr = act_scr or scr

                # one of these is not needed anymore in v2 as you have scriptPubkey provided by self.script
                if "p2sh" in af:# in ('p2sh-p2wpkh', 'p2wpkh-p2sh'):
                    psbt.outputs[i].redeem_script = scr
                elif isw:
                    psbt.outputs[i].witness_script = scr

                if psbt_v2:
                    psbt.outputs[i].script = act_scr
                    psbt.outputs[i].amount = oa
                else:
                    h = CTxOut(oa, act_scr)
                    txn.vout.append(h)

                if capture_scripts is not None:
                    capture_scripts.append(act_scr)

        if not psbt_v2:
            psbt.txn = txn.serialize_with_witness()

        if add_xpub:
            # some people want extra xpub data in their PSBTs
            psbt.xpubs = []
            if added_mine:
                psbt.xpubs.append((decode_base58(master_xpub),  my_xfp))
            if added_foreign:
                psbt.xpubs.append((decode_base58(foreign_mk.hwif()),  foreign_xfp))

        # last minute chance to mod PSBT object
        if psbt_hacker:
            psbt_hacker(psbt)

        rv = BytesIO()
        psbt.serialize(rv)
        pos = rv.tell()
        assert pos <= MAX_TXN_LEN, 'too fat %d' % pos

        return rv.getvalue()

    return doit

def render_address(script, testnet=True):
    # take a scriptPubKey (part of the CTxOut) and convert into conventional human-readable
    # string... aka: the "payment address"
    from base58 import encode_base58_checksum
    from bech32 import encode as bech32_encode
    from binascii import hexlify as b2a_hex

    ll = len(script)

    if not testnet:
        bech32_hrp = 'bc'
        b58_addr    = bytes([0])
        b58_script  = bytes([5])
        b58_privkey = bytes([128])
    else:
        bech32_hrp = 'tb'
        b58_addr    = bytes([111])
        b58_script  = bytes([196])
        b58_privkey = bytes([239])

    # P2PKH
    if ll == 25 and script[0:3] == b'\x76\xA9\x14' and script[23:26] == b'\x88\xAC':
        return encode_base58_checksum(b58_addr + script[3:3+20])

    # P2SH
    if ll == 23 and script[0:2] == b'\xA9\x14' and script[22] == 0x87:
        return encode_base58_checksum(b58_script + script[2:2+20])

    # segwit v0 (P2WPKH, P2WSH)
    if script[0] == 0 and script[1] in (0x14, 0x20) and (ll - 2) == script[1]:
        return bech32_encode(bech32_hrp, script[0], script[2:])

    # segwit v1 (P2TR) and later segwit version
    if ll == 34 and (0x51 <= script[0] <= 0x60) and script[1] == 0x20:
        return bech32_encode(bech32_hrp, script[0] - 80, script[2:])

    # OP_RETURN
    if script[0:1] == b'\x6a':
        return b2a_hex(script)

    raise ValueError('Unknown payment script', repr(script))

def fake_address(addr_fmt, testnet=False):
    # Make fake addresses of any type. Contents are noise... don't ever send to them!!
    # TODO add regtest option
    # LATER: dup of helper.py fake_dest_addr
    from constants import AFC_WRAPPED, AFC_PUBKEY, AFC_SEGWIT, AFC_BECH32M, AFC_SCRIPT
    from helpers import prandom
    from base58 import encode_base58_checksum
    from bech32 import encode as bech32_encode

    is_script = bool(addr_fmt & (AFC_SCRIPT | AFC_WRAPPED))
    body = prandom(32 if is_script else 20)

    if not testnet:
        bech32_hrp = 'bc'
        b58_addr    = bytes([0])
        b58_script  = bytes([5])
    else:
        bech32_hrp = 'tb'
        b58_addr    = bytes([111])
        b58_script  = bytes([196])

    if (addr_fmt & AFC_SEGWIT) and not (addr_fmt & AFC_WRAPPED):
        # bech32
        vers = 1 if (addr_fmt & AFC_BECH32M) == AFC_BECH32M else 0
        return bech32_encode(bech32_hrp, vers, body)
    else:
        # base58
        return encode_base58_checksum((b58_script if is_script else b58_addr) + body[0:20])

# EOF
