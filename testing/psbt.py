# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# psbt.py - yet another PSBT parser/serializer but used only for test cases.
#
import io, struct
from binascii import b2a_hex as _b2a_hex
from binascii import a2b_hex
from base64 import b64decode, b64encode
from serialize import ser_compact_size, deser_compact_size
from ctransaction import CTransaction, CTxOut, CTxIn, COutPoint, uint256_from_str, ser_uint256

b2a_hex = lambda a: str(_b2a_hex(a), 'ascii')

# BIP-174 aka PSBT defined values
#
# GLOBAL ===
PSBT_GLOBAL_UNSIGNED_TX 	     = 0x00
PSBT_GLOBAL_XPUB        	     = 0x01
PSBT_GLOBAL_VERSION              = 0xfb
PSBT_GLOBAL_PROPRIETARY          = 0xfc

# BIP-370
PSBT_GLOBAL_TX_VERSION           = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME    = 0x03
PSBT_GLOBAL_INPUT_COUNT          = 0x04
PSBT_GLOBAL_OUTPUT_COUNT         = 0x05
PSBT_GLOBAL_TX_MODIFIABLE        = 0x06

# INPUTS ===
PSBT_IN_NON_WITNESS_UTXO 	     = 0x00
PSBT_IN_WITNESS_UTXO 	         = 0x01
PSBT_IN_PARTIAL_SIG 	         = 0x02
PSBT_IN_SIGHASH_TYPE 	         = 0x03
PSBT_IN_REDEEM_SCRIPT 	         = 0x04
PSBT_IN_WITNESS_SCRIPT 	         = 0x05
PSBT_IN_BIP32_DERIVATION 	     = 0x06
PSBT_IN_FINAL_SCRIPTSIG 	     = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS      = 0x08
PSBT_IN_POR_COMMITMENT           = 0x09   # Proof of Reserves
PSBT_IN_RIPEMD160                = 0x0a
PSBT_IN_SHA256                   = 0x0b
PSBT_IN_HASH160                  = 0x0c
PSBT_IN_HASH256                  = 0x0d
# BIP-370
PSBT_IN_PREVIOUS_TXID            = 0x0e
PSBT_IN_OUTPUT_INDEX             = 0x0f
PSBT_IN_SEQUENCE                 = 0x10
PSBT_IN_REQUIRED_TIME_LOCKTIME   = 0x11
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
# BIP-371
PSBT_IN_TAP_KEY_SIG              = 0x13
PSBT_IN_TAP_SCRIPT_SIG           = 0x14
PSBT_IN_TAP_LEAF_SCRIPT          = 0x15
PSBT_IN_TAP_BIP32_DERIVATION     = 0x16
PSBT_IN_TAP_INTERNAL_KEY         = 0x17
PSBT_IN_TAP_MERKLE_ROOT          = 0x18

# OUTPUTS ===
PSBT_OUT_REDEEM_SCRIPT 	         = 0x00
PSBT_OUT_WITNESS_SCRIPT 	     = 0x01
PSBT_OUT_BIP32_DERIVATION 	     = 0x02
# BIP-370
PSBT_OUT_AMOUNT                  = 0x03
PSBT_OUT_SCRIPT                  = 0x04
# BIP-371
PSBT_OUT_TAP_INTERNAL_KEY        = 0x05
PSBT_OUT_TAP_TREE                = 0x06
PSBT_OUT_TAP_BIP32_DERIVATION    = 0x07

PSBT_PROP_CK_ID = b"COINKITE"


def ser_prop_key(identifier, subtype, keydata=b''):
    # arg types are: bytes, int (< 256), bytes
    key = b""
    key += ser_compact_size(len(identifier))
    key += identifier
    key += ser_compact_size(subtype)
    key += keydata
    return key


class PSBTSection:

    def __init__(self, fd=None, idx=None):
        self.defaults()
        self.my_index = idx

        if not fd: return

        while 1:
            ks = deser_compact_size(fd)
            if ks is None: break
            if ks == 0: break

            key = fd.read(ks)
            vs = deser_compact_size(fd)
            val = fd.read(vs)

            kt = key[0]
            self.parse_kv(kt, key[1:], val)

    def serialize(self, fd, v2):

        def wr(ktype, val, key=b''):
            fd.write(ser_compact_size(1 + len(key)))
            fd.write(bytes([ktype]) + key)
            fd.write(ser_compact_size(len(val)))
            fd.write(val)

        self.serialize_kvs(wr, v2)

        fd.write(b'\0')


class BasicPSBTInput(PSBTSection):
    def defaults(self):
        self.utxo = None
        self.witness_utxo = None
        self.part_sigs = {}
        self.sighash = None
        self.bip32_paths = {}
        self.taproot_bip32_paths = {}
        self.taproot_internal_key = None
        self.taproot_key_sig = None
        self.taproot_merkle_root = None
        self.taproot_scripts = {}
        self.taproot_script_sigs = {}
        self.redeem_script = None
        self.witness_script = None
        self.previous_txid = None        # v2
        self.prevout_idx = None          # v2
        self.sequence = None             # v2
        self.req_time_locktime = None    # v2
        self.req_height_locktime = None  # v2
        self.others = {}
        self.unknown = {}

    def __eq__(a, b):
        if a.sighash != b.sighash:
            if a.sighash is not None and b.sighash is not None:
                return False

        rv = a.utxo == b.utxo and \
             a.witness_utxo == b.witness_utxo and \
             a.redeem_script == b.redeem_script and \
             a.witness_script == b.witness_script and \
             a.my_index == b.my_index and \
             a.bip32_paths == b.bip32_paths and \
             a.taproot_key_sig == b.taproot_key_sig and \
             a.taproot_bip32_paths == b.taproot_bip32_paths and \
             a.taproot_internal_key == b.taproot_internal_key and \
             a.taproot_merkle_root == b.taproot_merkle_root and \
             a.taproot_scripts == b.taproot_scripts and \
             a.taproot_script_sigs == b.taproot_script_sigs and \
             sorted(a.part_sigs.keys()) == sorted(b.part_sigs.keys()) and \
             a.previous_txid == b.previous_txid and \
             a.prevout_idx == b.prevout_idx and \
             a.sequence == b.sequence and \
             a.req_time_locktime == b.req_time_locktime and \
             a.req_height_locktime == b.req_height_locktime and \
             a.unknown == b.unknown
        if rv:
            # NOTE: equality test on signatures requires parsing DER stupidness
            #       and some maybe understanding of R/S values on curve that I don't have.
            assert all(a.part_sigs[k] == b.part_sigs[k] for k in a.part_sigs)
        return rv

    def parse_kv(self, kt, key, val):
        if kt == PSBT_IN_NON_WITNESS_UTXO:
            self.utxo = val
            assert not key
        elif kt == PSBT_IN_WITNESS_UTXO:
            self.witness_utxo = val
            assert not key
        elif kt == PSBT_IN_PARTIAL_SIG:
            self.part_sigs[key] = val
        elif kt == PSBT_IN_SIGHASH_TYPE:
            assert len(val) == 4
            self.sighash = struct.unpack("<I", val)[0]
            assert not key
        elif kt == PSBT_IN_BIP32_DERIVATION:
            self.bip32_paths[key] = val
        elif kt == PSBT_IN_REDEEM_SCRIPT:
            self.redeem_script = val
            assert not key
        elif kt == PSBT_IN_WITNESS_SCRIPT:
            self.witness_script = val
            assert not key
        elif kt in (PSBT_IN_REDEEM_SCRIPT,
                    PSBT_IN_WITNESS_SCRIPT,
                    PSBT_IN_FINAL_SCRIPTSIG,
                    PSBT_IN_FINAL_SCRIPTWITNESS):
            assert not key
            self.others[kt] = val
        elif kt == PSBT_IN_TAP_BIP32_DERIVATION:
            self.taproot_bip32_paths[key] = val
        elif kt == PSBT_IN_TAP_INTERNAL_KEY:
            self.taproot_internal_key = val
        elif kt == PSBT_IN_TAP_KEY_SIG:
            self.taproot_key_sig = val
        elif kt == PSBT_IN_PREVIOUS_TXID:
            self.previous_txid = val
        elif kt == PSBT_IN_OUTPUT_INDEX:
            self.prevout_idx = struct.unpack("<I", val)[0]
        elif kt == PSBT_IN_SEQUENCE:
            self.sequence = struct.unpack("<I", val)[0]
        elif kt == PSBT_IN_REQUIRED_TIME_LOCKTIME:
            self.req_time_locktime = struct.unpack("<I", val)[0]
        elif kt == PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
            self.req_height_locktime = struct.unpack("<I", val)[0]
        elif kt == PSBT_IN_TAP_SCRIPT_SIG:
            assert len(key) == 64, "PSBT_IN_TAP_SCRIPT_SIG key length != 64"
            assert len(val) in (64, 65), "PSBT_IN_TAP_SCRIPT_SIG signature length != 64 or 65"
            xonly_pubkey, script_hash = key[:32], key[32:]
            self.taproot_script_sigs[(xonly_pubkey, script_hash)] = val
        elif kt == PSBT_IN_TAP_LEAF_SCRIPT:
            assert len(key) > 32, "PSBT_IN_TAP_LEAF_SCRIPT control block is too short"
            assert (len(key) - 1) % 32 == 0, "PSBT_IN_TAP_LEAF_SCRIPT control block is not valid"
            assert len(val) != 0, "PSBT_IN_TAP_LEAF_SCRIPT cannot be empty"
            leaf_script = (val[:-1], int(val[-1]))
            if leaf_script not in self.taproot_scripts:
                self.taproot_scripts[leaf_script] = set()
            self.taproot_scripts[leaf_script].add(key)
        elif kt == PSBT_IN_TAP_MERKLE_ROOT:
            self.taproot_merkle_root = val
        else:
            self.unknown[bytes([kt]) + key] = val

    def serialize_kvs(self, wr, v2):
        if self.utxo:
            wr(PSBT_IN_NON_WITNESS_UTXO, self.utxo)
        if self.witness_utxo:
            wr(PSBT_IN_WITNESS_UTXO, self.witness_utxo)
        if self.redeem_script:
            wr(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)
        if self.witness_script:
            wr(PSBT_IN_WITNESS_SCRIPT, self.witness_script)

        if self.part_sigs:
            for pk, val in sorted(self.part_sigs.items()):
                wr(PSBT_IN_PARTIAL_SIG, val, pk)

        if self.sighash is not None:
            wr(PSBT_IN_SIGHASH_TYPE, struct.pack('<I', self.sighash))

        if self.bip32_paths:
            for k in self.bip32_paths:
                wr(PSBT_IN_BIP32_DERIVATION, self.bip32_paths[k], k)

        if self.taproot_bip32_paths:
            for k in self.taproot_bip32_paths:
                wr(PSBT_IN_TAP_BIP32_DERIVATION, self.taproot_bip32_paths[k], k)

        if self.taproot_internal_key:
            wr(PSBT_IN_TAP_INTERNAL_KEY, self.taproot_internal_key)
        if self.taproot_key_sig:
            wr(PSBT_IN_TAP_KEY_SIG, self.taproot_key_sig)

        if self.taproot_merkle_root:
            wr(PSBT_IN_TAP_MERKLE_ROOT, self.taproot_merkle_root)
        if self.taproot_scripts:
            for (script, leaf_ver), control_blocks in self.taproot_scripts.items():
                for control_block in control_blocks:
                    wr(PSBT_IN_TAP_LEAF_SCRIPT, script + struct.pack("B", leaf_ver), control_block)
        if self.taproot_script_sigs:
            for (xonly, leaf_hash), sig in self.taproot_script_sigs.items():
                wr(PSBT_IN_TAP_SCRIPT_SIG, sig, xonly + leaf_hash)

        if v2:
            if self.previous_txid is not None:
                wr(PSBT_IN_PREVIOUS_TXID, self.previous_txid)
            if self.prevout_idx is not None:
                wr(PSBT_IN_OUTPUT_INDEX, struct.pack("<I", self.prevout_idx))
            if self.sequence is not None:
                wr(PSBT_IN_SEQUENCE, struct.pack("<I", self.sequence))
            if self.req_time_locktime is not None:
                wr(PSBT_IN_REQUIRED_TIME_LOCKTIME, struct.pack("<I", self.req_time_locktime))
            if self.req_height_locktime is not None:
                wr(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, struct.pack("<I", self.req_height_locktime))

        for k in self.others:
            wr(k, self.others[k])
        if isinstance(self.unknown, list):
            # just so I can test duplicate unknown values
            # list of tuples [(key0, val0), (key1, val1)]
            for key, val in self.unknown:
                wr(key[0], val, key[1:])
        else:
            for key, val in self.unknown.items():
                wr(key[0], val, key[1:])


class BasicPSBTOutput(PSBTSection):
    def defaults(self):
        self.redeem_script = None
        self.witness_script = None
        self.bip32_paths = {}
        self.taproot_bip32_paths = {}
        self.taproot_internal_key = None
        self.taproot_tree = None
        self.script = None  # v2
        self.amount = None  # v2
        self.proprietary = {}
        self.unknown = {}

    def __eq__(a, b):
        return a.redeem_script == b.redeem_script and \
            a.witness_script == b.witness_script and \
            a.script == b.script and \
            a.amount == b.amount and \
            a.my_index == b.my_index and \
            a.bip32_paths == b.bip32_paths and \
            a.taproot_bip32_paths == b.taproot_bip32_paths and \
            a.taproot_internal_key == b.taproot_internal_key and \
            a.proprietary == b.proprietary and \
            a.taproot_tree == b.taproot_tree and \
            a.unknown == b.unknown

    def parse_kv(self, kt, key, val):
        if kt == PSBT_OUT_REDEEM_SCRIPT:
            self.redeem_script = val
            assert not key
        elif kt == PSBT_OUT_WITNESS_SCRIPT:
            self.witness_script = val
            assert not key
        elif kt == PSBT_OUT_BIP32_DERIVATION:
            self.bip32_paths[key] = val
        elif kt == PSBT_OUT_TAP_BIP32_DERIVATION:
            self.taproot_bip32_paths[key] = val
        elif kt == PSBT_OUT_TAP_INTERNAL_KEY:
            self.taproot_internal_key = val
        elif kt == PSBT_OUT_TAP_TREE:
            res = []
            reader = io.BytesIO(val)
            while True:
                depth = reader.read(1)
                if not depth:
                    break
                leaf_version = reader.read(1)[0]
                script_len = deser_compact_size(reader)
                script = reader.read(script_len)
                res.append((depth[0], leaf_version, script))
            self.taproot_tree = res
        elif kt == PSBT_OUT_SCRIPT:
            self.script = val
        elif kt == PSBT_OUT_AMOUNT:
            self.amount = struct.unpack("<q", val)[0]
        elif kt == PSBT_GLOBAL_PROPRIETARY:
            self.proprietary[key] = val
        else:
            self.unknown[bytes([kt]) + key] = val

    def serialize_kvs(self, wr, v2):
        if self.redeem_script:
            wr(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)
        if self.witness_script:
            wr(PSBT_OUT_WITNESS_SCRIPT, self.witness_script)
        if self.bip32_paths:
            for k in self.bip32_paths:
                wr(PSBT_OUT_BIP32_DERIVATION, self.bip32_paths[k], k)
        if self.taproot_bip32_paths:
            for k in self.taproot_bip32_paths:
                wr(PSBT_OUT_TAP_BIP32_DERIVATION, self.taproot_bip32_paths[k], k)
        if self.taproot_internal_key:
            wr(PSBT_OUT_TAP_INTERNAL_KEY, self.taproot_internal_key)
        if self.taproot_tree:
            res = b''
            for depth, leaf_version, script in self.taproot_tree:
                res += bytes([depth, leaf_version]) + ser_compact_size(len(script)) + script
            wr(PSBT_OUT_TAP_TREE, res)
        if v2 and self.script is not None:
            wr(PSBT_OUT_SCRIPT, self.script)
        if v2 and self.amount is not None:
            wr(PSBT_OUT_AMOUNT, struct.pack("<q", int(self.amount)))

        for k in self.proprietary:
            wr(PSBT_GLOBAL_PROPRIETARY, self.proprietary[k], k)

        if isinstance(self.unknown, list):
            # just so I can test duplicate unknown values
            # list of tuples [(key0, val0), (key1, val1)]
            for key, val in self.unknown:
                wr(key[0], val, key[1:])
        else:
            for key, val in self.unknown.items():
                wr(key[0], val, key[1:])


class BasicPSBT:
    "Just? parse and store"

    def __init__(self):
        self.version = None
        self.txn = None
        self.txn_version = None
        self.xpubs = []
        self.input_count = None
        self.output_count = None
        self.inputs = []
        self.outputs = []
        self.txn_modifiable = None
        self.fallback_locktime = None
        self.unknown = {}
        self.parsed_txn = None

    def __eq__(a, b):
        return a.txn == b.txn and \
            a.input_count == b.input_count and \
            a.output_count == b.output_count and \
            a.fallback_locktime == b.fallback_locktime and \
            a.txn_version == b.txn_version and \
            a.version == b.version and \
            len(a.inputs) == len(b.inputs) and \
            len(a.outputs) == len(b.outputs) and \
            all(a.inputs[i] == b.inputs[i] for i in range(len(a.inputs))) and \
            all(a.outputs[i] == b.outputs[i] for i in range(len(a.outputs))) and \
            sorted(a.xpubs) == sorted(b.xpubs) and \
            a.unknown == b.unknown

    def is_v2(self):
        return (self.version == 2) or (not self.txn)

    def parse(self, raw):
        # auto-detect and decode Base64 and Hex.
        if raw[0:10].lower() == b'70736274ff':
            raw = a2b_hex(raw.strip())
        if raw[0:6] == b'cHNidP':
            raw = b64decode(raw)
        assert raw[0:5] == b'psbt\xff', "bad magic {}".format(raw[0:5])
        with io.BytesIO(raw[5:]) as fd:

            # globals
            while 1:
                ks = deser_compact_size(fd)
                if ks is None: break

                if ks == 0: break

                key = fd.read(ks)
                vs = deser_compact_size(fd)
                val = fd.read(vs)

                kt = key[0]
                if kt == PSBT_GLOBAL_UNSIGNED_TX:
                    self.txn = val

                    t = CTransaction()
                    t.deserialize(io.BytesIO(val))
                    self.parsed_txn = t
                    num_ins = len(t.vin)
                    num_outs = len(t.vout)
                elif kt == PSBT_GLOBAL_XPUB:
                    # key=(xpub) => val=(path)
                    # ignore PSBT_GLOBAL_XPUB on 0th index (should not be part of parsed key)
                    self.xpubs.append((key[1:], val))
                elif kt == PSBT_GLOBAL_VERSION:
                    self.version = struct.unpack("<I", val)[0]
                elif kt == PSBT_GLOBAL_TX_VERSION:
                    self.txn_version = struct.unpack("<I", val)[0]
                elif kt == PSBT_GLOBAL_FALLBACK_LOCKTIME:
                    self.fallback_locktime = struct.unpack("<I", val)[0]
                elif kt == PSBT_GLOBAL_INPUT_COUNT:
                    self.input_count = deser_compact_size(io.BytesIO(val))
                    num_ins = self.input_count
                elif kt == PSBT_GLOBAL_OUTPUT_COUNT:
                    self.output_count = deser_compact_size(io.BytesIO(val))
                    num_outs = self.output_count
                elif kt == PSBT_GLOBAL_TX_MODIFIABLE:
                    self.txn_modifiable = val[0]
                else:
                    self.unknown[key] = val

            if self.version is None:
                # decide version based on PSBT_GLOBAL_UNSIGNED_TX field
                # v0 requires inclusion
                # v2 requires exclusion
                self.version = 0 if self.txn else 2

            if self.version == 0:
                assert self.txn, 'v0: missing reqd section - PSBT_GLOBAL_UNSIGNED_TX'
            elif self.version == 2:
                # tx version needs to be at least 2 because locktimes
                assert self.txn_version == 2, 'v2: missing reqd section - PSBT_GLOBAL_TX_VERSION'
                assert self.input_count is not None, 'v2: missing reqd section - PSBT_GLOBAL_INPUT_COUNT'
                assert self.output_count is not None, 'v2: missing reqd section - PSBT_GLOBAL_OUTPUT_COUNT'

            self.inputs = [BasicPSBTInput(fd, idx) for idx in range(num_ins)]
            self.outputs = [BasicPSBTOutput(fd, idx) for idx in range(num_outs)]

            sep = fd.read(1)
            assert sep == b''

        return self

    def serialize(self, fd):
        v2 = self.is_v2()
        def wr(ktype, val, key=b''):
            ktype_plus_key = bytes([ktype]) + key
            fd.write(ser_compact_size(len(ktype_plus_key)))
            fd.write(ktype_plus_key)
            fd.write(ser_compact_size(len(val)))
            fd.write(val)

        fd.write(b'psbt\xff')

        if (not v2) and self.txn:
            wr(PSBT_GLOBAL_UNSIGNED_TX, self.txn)

        for k, v in self.xpubs:
            wr(PSBT_GLOBAL_XPUB, v, key=k)

        if v2:
            if self.txn_version is not None:
                wr(PSBT_GLOBAL_TX_VERSION, struct.pack('<I', self.txn_version))

            if self.fallback_locktime is not None:
                wr(PSBT_GLOBAL_FALLBACK_LOCKTIME, struct.pack('<I', self.fallback_locktime))

            if self.input_count is not None:
                wr(PSBT_GLOBAL_INPUT_COUNT, ser_compact_size(self.input_count))

            if self.output_count is not None:
                wr(PSBT_GLOBAL_OUTPUT_COUNT, ser_compact_size(self.output_count))

            if self.txn_modifiable is not None:
                wr(PSBT_GLOBAL_TX_MODIFIABLE, bytes([self.txn_modifiable]))

        if self.version is not None:
            wr(PSBT_GLOBAL_VERSION, struct.pack('<I', self.version))

        if isinstance(self.unknown, list):
            # just so I can test duplicate unknown values
            # list of tuples [(key0, val0), (key1, val1)]
            for key, val in self.unknown:
                wr(key[0], val, key[1:])
        else:
            for key, val in self.unknown.items():
                wr(key[0], val, key[1:])

        # sep
        fd.write(b'\0')

        for idx, inp in enumerate(self.inputs):
            inp.serialize(fd, v2)

        for idx, outp in enumerate(self.outputs):
            outp.serialize(fd, v2)

    def as_bytes(self):
        with io.BytesIO() as fd:
            self.serialize(fd)
            return fd.getvalue()

    def as_b64_str(self):
        return b64encode(self.as_bytes()).decode()

    def to_v2(self):
        if self.version is None or self.version == 0:
            self.version = 2
            self.txn_version = 2
            self.txn = None
            self.input_count = len(self.parsed_txn.vin)
            self.output_count = len(self.parsed_txn.vout)
            self.fallback_locktime = self.parsed_txn.nLockTime
            for idx, inp in enumerate(self.parsed_txn.vin):
                i = self.inputs[idx]
                i.previous_txid = ser_uint256(inp.prevout.hash)
                i.prevout_idx = inp.prevout.n
                i.sequence = inp.nSequence
            for idx, out in enumerate(self.parsed_txn.vout):
                o = self.outputs[idx]
                o.script = out.scriptPubKey
                o.amount = out.nValue

        return self.as_bytes()

    def to_v0(self):
        if self.version == 2:
            tx_ins = []
            for inp in self.inputs:
                tx_ins.append(CTxIn(COutPoint(uint256_from_str(inp.previous_txid), inp.prevout_idx),
                                   nSequence=inp.sequence or 0xffffffff))
                inp.prevout_idx = None
                inp.previous_txid = None
                inp.sequence = None
                inp.req_time_locktime = None
                inp.req_height_locktime = None

            tx_outs = []
            for out in self.outputs:
                tx_outs.append(CTxOut(out.amount, out.script))
                out.amount = None
                out.script = None

            t = CTransaction()
            t.nVersion = self.txn_version
            t.vin = tx_ins
            t.vout = tx_outs
            t.nLockTime = self.fallback_locktime or 0
            self.txn_version = None
            self.input_count = None
            self.output_count = None
            self.txn_modifiable = None
            self.version = None
            self.parsed_txn = t
            self.txn = self.parsed_txn.serialize_with_witness()

        return self.as_bytes()


def test_my_psbt():
    import glob, io

    for fn in glob.glob('data/*.psbt'):
        if 'missing_txn.psbt' in fn: continue
        if 'unknowns-ins.psbt' in fn: continue

        raw = open(fn, 'rb').read()
        print("\n\nFILE: %s" % fn)

        p = BasicPSBT().parse(raw)

        fd = io.BytesIO()
        p.serialize(fd)
        assert p.txn in fd.getvalue()

        chk = BasicPSBT().parse(fd.getvalue())
        assert chk == p

# EOF

