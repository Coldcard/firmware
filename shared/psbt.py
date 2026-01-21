# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# psbt.py - understand PSBT file format: verify and generate them
#
import stash, gc, history, sys, ngu, ckcc, chains
from ustruct import unpack_from, unpack, pack
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, B2A, keypath_to_str
from utils import seconds2human_readable, datetime_from_timestamp, datetime_to_str
from chains import NLOCK_IS_TIME
from uhashlib import sha256
from uio import BytesIO
from sffile import SizerFile
from multisig import MultisigWallet, disassemble_multisig_mn
from exceptions import FatalPSBTIssue, FraudulentChangeOutput
from serializations import ser_compact_size, deser_compact_size, hash160
from serializations import CTxIn, CTxInWitness, CTxOut, ser_string, COutPoint
from serializations import ser_sig_der, uint256_from_str, ser_push_data
from serializations import SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE, SIGHASH_ANYONECANPAY
from serializations import ALL_SIGHASH_FLAGS
from opcodes import OP_CHECKMULTISIG, OP_RETURN
from glob import settings

from public_constants import (
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_XPUB, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT,
    PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_SCRIPT, PSBT_OUT_AMOUNT, PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_OUTPUT_COUNT, PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_TX_VERSION, PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX, PSBT_IN_SEQUENCE, PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, MAX_PATH_DEPTH, MAX_SIGNERS,
    AF_P2WSH_P2SH, AF_P2TR, AF_P2WSH, AF_P2SH, AF_CLASSIC, AF_P2WPKH_P2SH, AF_P2WPKH, AF_BARE_PK
)

# PSBT proprietary keytype
PSBT_PROPRIETARY = const(0xFC)

# PSBT proprietary identifier for Coinkite applications
PSBT_PROP_CK_ID = b"COINKITE"

# PSBT proprietary subtype for attestation entries
PSBT_ATTESTATION_SUBTYPE = const(0)

# Max miner's fee, as percentage of output value, that we will allow to be signed.
# Amounts over 5% are warned regardless.
DEFAULT_MAX_FEE_PERCENTAGE = const(10)

# print some things, sometimes
DEBUG = ckcc.is_simulator()

class HashNDump:
    def __init__(self, d=None):
        self.rv = sha256()
        print('Hashing: ', end='')
        if d:
            self.update(d)

    def update(self, d):
        print(b2a_hex(d), end=' ')
        self.rv.update(d)

    def digest(self):
        print(' END')
        return self.rv.digest()

def seq_to_str(seq):
    # take a set or list of numbers and show a tidy list in order.
    return ', '.join(str(i) for i in sorted(seq))

def _skip_n_objs(fd, n, cls):
    # skip N sized objects in the stream, for example a vectors of CTxIns
    # - returns starting position

    if cls == 'CTxIn':
        # output point(hash, n) + script sig + locktime
        pat = [32+4, None, 4]
    elif cls == 'CTxOut':
        # nValue + Script
        pat = [8, None]
    else:
        raise ValueError(cls)

    rv = fd.tell()
    for i in range(n):
        for p in pat:
            if p is None:
                # variable-length part
                sz = deser_compact_size(fd)
                fd.seek(sz, 1)
            else:
                fd.seek(p, 1)

    return rv

def calc_txid(fd, poslen, body_poslen=None):
    # Given the (pos,len) of a transaction in a file, return the txid for that txn.
    # - doesn't validate data
    # - does detect witness txn vs. old style
    # - simple double-sha256() if old style txn, otherwise witness data must be carefully skipped

    # see if witness encoding in effect
    fd.seek(poslen[0])

    txn_version, marker, flags = unpack("<iBB", fd.read(6))
    has_witness = (marker == 0 and flags != 0x0)

    if not has_witness:
        # txn does not have witness data, so txid==wtxix
        return get_hash256(fd, poslen)

    rv = sha256()

    # de/reserialize much of the txn -- but not the witness data
    rv.update(pack("<i", txn_version))

    if body_poslen is None:
        body_start = fd.tell()

        # determine how long ins + outs are...
        num_in = deser_compact_size(fd)
        _skip_n_objs(fd, num_in, 'CTxIn')
        num_out = deser_compact_size(fd)
        _skip_n_objs(fd, num_out, 'CTxOut')

        body_poslen = (body_start, fd.tell() - body_start)

    # hash the bulk of txn
    get_hash256(fd, body_poslen, hasher=rv)

    # assume last 4 bytes are the lock_time
    fd.seek(sum(poslen) - 4)

    rv.update(fd.read(4))

    return ngu.hash.sha256s(rv.digest())

def get_hash256(fd, poslen, hasher=None):
    # return the double-sha256 of a value, without loading it into memory
    # - if hasher provided, just updates over region of file (not a sha256d)
    pos, ll = poslen
    rv = hasher or sha256()

    tmp = bytearray(min(256, ll))

    fd.seek(pos)
    while ll:
        here = fd.readinto(tmp)
        if not here:
            raise ValueError
        if here > ll:
            here = ll
        rv.update(memoryview(tmp)[0:here])
        ll -= here

    if hasher:
        return

    return ngu.hash.sha256s(rv.digest())

def decode_prop_key(key):
    # decodes a proprietary (0xFC) key and breaks it down into:
    # - identifier
    # - subtype
    # - keydata
    with BytesIO(key) as fd:
        identifier_len = deser_compact_size(fd)
        identifier = fd.read(identifier_len)
        subtype = deser_compact_size(fd)
        keydata = fd.read()
        return identifier, subtype, keydata

def encode_prop_key(identifier, subtype, keydata = b''):
    # encodes a proprietary (0xFC) key into bytes
    key = b''
    key += ser_compact_size(len(identifier))
    key += identifier
    key += ser_compact_size(subtype)
    key += keydata
    return key

class psbtProxy:
    # store offsets to values, but track the keys in-memory.
    short_values = ()
    no_keys = ()

    # these fields will return None but are not stored unless a value is set
    blank_flds = ('unknown', )

    def __init__(self):
        self.fd = None

    def __getattr__(self, nm):
        if nm in self.blank_flds:
            return None
        raise AttributeError(nm)

    def parse(self, fd):
        self.fd = fd

        while 1:
            ks = deser_compact_size(fd)
            if ks is None: break
            if ks == 0: break

            key = fd.read(ks)
            vs = deser_compact_size(fd)
            assert vs is not None, 'eof'

            kt = key[0]

            if kt in self.no_keys:
                assert len(key) == 1        # not expecting key

            # storing offset and length only! Mostly.
            if kt in self.short_values:
                actual = fd.read(vs)

                self.store(kt, bytes(key), actual)
            else:
                # skip actual data for now
                # TODO: could this be stored more compactly?
                proxy = (fd.tell(), vs)
                fd.seek(vs, 1)

                self.store(kt, bytes(key), proxy)

    def write(self, out_fd, ktype, val, key=b''):
        # serialize helper: write w/ size and key byte
        out_fd.write(ser_compact_size(1 + len(key)))
        out_fd.write(bytes([ktype]) + key)

        if isinstance(val, tuple):
            (pos, ll) = val
            out_fd.write(ser_compact_size(ll))
            self.fd.seek(pos)
            while ll:
                t = self.fd.read(min(64, ll))
                out_fd.write(t)
                ll -= len(t)

        elif isinstance(val, list):
            # for subpaths lists (LE32 ints)
            assert ktype in (PSBT_IN_BIP32_DERIVATION, PSBT_OUT_BIP32_DERIVATION)
            out_fd.write(ser_compact_size(len(val) * 4))
            for i in val:
                out_fd.write(pack('<I', i))
        else:
            out_fd.write(ser_compact_size(len(val)))
            out_fd.write(val)

    def get(self, val):
        # get the raw bytes for a value.
        pos, ll = val
        self.fd.seek(pos)
        return self.fd.read(ll)

    def parse_subpaths(self, my_xfp, warnings):
        # Reformat self.subpaths into a more useful form for us; return # of them
        # that are ours (and track that as self.num_our_keys)
        # - works in-place, on self.subpaths
        # - creates dictionary: pubkey => [xfp, *path]
        # - will be single entry for non-p2sh ins and outs

        if not self.subpaths:
            return 0

        if self.num_our_keys is not None:
            # already been here once
            return self.num_our_keys

        num_ours = 0
        for pk in self.subpaths:
            assert len(pk) in {33, 65}, "hdpath pubkey len"
            if len(pk) == 33:
                assert pk[0] in {0x02, 0x03}, "uncompressed pubkey"

            vl = self.subpaths[pk][1]

            # force them to use a derived key, never the master
            assert vl >= 8, 'too short key path'
            assert (vl % 4) == 0, 'corrupt key path'
            assert (vl//4) <= MAX_PATH_DEPTH, 'too deep'

            # promote to a list of ints
            v = self.get(self.subpaths[pk])
            here = list(unpack_from('<%dI' % (vl//4), v))

            # Tricky & Useful: if xfp of zero is observed in file, assume that's a 
            # placeholder for my XFP value. Replace on the fly. Great when master
            # XFP is unknown because PSBT built from derived XPUB only. Also privacy.
            if here[0] == 0:
                here[0] = my_xfp
                if not any(True for k,_ in warnings if 'XFP' in k):
                    warnings.append(('Zero XFP',
                            'Assuming XFP of zero should be replaced by correct XFP'))

            # update in place
            self.subpaths[pk] = here

            if here[0] == my_xfp:
                num_ours += 1
            else:
                # Address that isn't based on my seed; might be another leg in a p2sh,
                # or an input we're not supposed to be able to sign... and that's okay.
                pass

        self.num_our_keys = num_ours
        return num_ours



# Track details of each output of PSBT
#
class psbtOutputProxy(psbtProxy):
    no_keys = { PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT }

    blank_flds = ('unknown', 'subpaths', 'redeem_script', 'witness_script',
                  'is_change', 'num_our_keys', 'amount', 'script', 'attestation')

    def __init__(self, fd, idx):
        super().__init__()

        # things we track
        #self.subpaths = None        # a dictionary if non-empty
        #self.redeem_script = None
        #self.witness_script = None
        #self.script = None
        #self.amount = None

        # this flag is set when we are assuming output will be change (same wallet)
        #self.is_change = False

        self.parse(fd)


    def store(self, kt, key, val):
        # do not forget that key[0] includes kt (type)
        if kt == PSBT_OUT_BIP32_DERIVATION:
            if not self.subpaths:
                self.subpaths = {}
            self.subpaths[key[1:]] = val
        elif kt == PSBT_OUT_REDEEM_SCRIPT:
            self.redeem_script = val
        elif kt == PSBT_OUT_WITNESS_SCRIPT:
            self.witness_script = val
        elif kt == PSBT_OUT_SCRIPT:
            self.script = val
        elif kt == PSBT_OUT_AMOUNT:
            self.amount = val
        elif kt == PSBT_PROPRIETARY:
            prefix, subtype, keydata = decode_prop_key(key[1:])
            # examine only Coinkite proprietary keys
            if prefix == PSBT_PROP_CK_ID:
                if subtype == PSBT_ATTESTATION_SUBTYPE:
                    # prop key for attestation does not have keydata because the
                    # value is a recoverable signature (already contains pubkey)
                    self.attestation = self.get(val)
        else:
            self.unknown = self.unknown or {}
            if key in self.unknown:
                raise FatalPSBTIssue("Duplicate key. Key for unknown value already provided in output.")
            self.unknown[key] = val

    def serialize(self, out_fd, is_v2):

        wr = lambda *a: self.write(out_fd, *a)

        if self.subpaths:
            for k in self.subpaths:
                wr(PSBT_OUT_BIP32_DERIVATION, self.subpaths[k], k)

        if self.redeem_script:
            wr(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            wr(PSBT_OUT_WITNESS_SCRIPT, self.witness_script)

        if is_v2:
            wr(PSBT_OUT_SCRIPT, self.script)
            wr(PSBT_OUT_AMOUNT, self.amount)

        if self.attestation:
            wr(PSBT_PROPRIETARY, self.attestation, encode_prop_key(PSBT_PROP_CK_ID, PSBT_ATTESTATION_SUBTYPE))

        if self.unknown:
            for k, v in self.unknown.items():
                wr(k[0], v, k[1:])

    def validate(self, out_idx, txo, my_xfp, active_multisig, parent):
        # Do things make sense for this output?
    
        # NOTE: We might think it's a change output just because the PSBT
        # creator has given us a key path. However, we must be **very** 
        # careful and fully validate all the details.
        # - no output info is needed, in general, so
        #   any output info provided better be right, or fail as "fraud"
        # - full key derivation and validation is done during signing, and critical.
        # - we raise fraud alarms, since these are not innocent errors
        #
        num_ours = self.parse_subpaths(my_xfp, parent.warnings)

        # - must match expected address for this output, coming from unsigned txn
        af, addr_or_pubkey, is_segwit = txo.get_address()

        if (num_ours == 0) or (af in [AF_P2TR, OP_RETURN, None]):
            # num_ours == 0
            # - not considered fraud because other signers looking at PSBT may have them
            # - user will see them as normal outputs, which they are from our PoV.
            # OP_RETURN
            # - nothing we can do with anchor outputs
            # UNKNOWN
            # - scripts that we do not understand
            # P2TR
            # - unsupported, will be properly rendered as address (no change check)
            return af

        if len(self.subpaths) == 1:
            # p2pk, p2pkh, p2wpkh cases
            expect_pubkey, = self.subpaths.keys()
        else:
            # p2wsh/p2sh cases need full set of pubkeys, and therefore redeem script
            expect_pubkey = None

        if af == AF_BARE_PK:
            # output is public key (not a hash, much less common)
            assert len(addr_or_pubkey) == 33

            if addr_or_pubkey != expect_pubkey:
                raise FraudulentChangeOutput(out_idx, "P2PK change output is fraudulent")

            self.is_change = True
            return af

        # Figure out what the hashed addr should be
        pkh = addr_or_pubkey

        if af in [AF_P2SH, AF_P2WSH]:
            # P2SH or Multisig output

            # Can be both, or either one depending on address type
            redeem_script = self.get(self.redeem_script) if self.redeem_script else None
            witness_script = self.get(self.witness_script) if self.witness_script else None

            if expect_pubkey:
                # num_ours == 1 and len(subpaths) == 1, single sig, we only allow p2sh-p2wpkh
                if not redeem_script:
                    # Perhaps an omission, so let's not call fraud on it
                    # But definitely required, else we don't know what script we're sending to.
                    raise FatalPSBTIssue("Missing redeem script for output #%d" % out_idx)

                target_spk, _ = chains.current_chain().script_pubkey(AF_P2WPKH_P2SH,
                                                                     pubkey=expect_pubkey)
                if not is_segwit and len(redeem_script) == 22 and \
                        redeem_script[0] == 0 and redeem_script[1] == 20 and \
                        txo.scriptPubKey == target_spk:
                    # it's actually segwit p2wpkh inside p2sh
                    pkh = redeem_script[2:22]
                    expect_pkh = hash160(expect_pubkey)
                else:
                    # unknown or wrong script
                    # p2sh-p2pkh also fall into this category
                    expect_pkh = None

            else:
                # Multisig change output, for wallet we're supposed to be a part of.
                # - our key must be part of it
                # - must look like input side redeem script (same fingerprints)
                # - assert M/N structure of output to match any inputs we have signed in PSBT!
                # - assert all provided pubkeys are in redeem script, not just ours
                # - we get all of that by re-constructing the script from our wallet details
                if not redeem_script and not witness_script:
                    # Perhaps an omission, so let's not call fraud on it
                    # But definately required, else we don't know what script we're sending to.
                    raise FatalPSBTIssue(
                        "Missing redeem/witness script for multisig output #%d" % out_idx
                    )

                # it cannot be change if it doesn't precisely match our multisig setup
                if not active_multisig:
                    # - might be a p2sh output for another wallet that isn't us
                    # - not fraud, just an output with more details than we need.
                    self.is_change = False
                    return af

                if MultisigWallet.disable_checks:
                    # Without validation, we have to assume all outputs
                    # will be taken from us, and are not really change.
                    self.is_change = False
                    return af

                if (af == AF_P2SH) and (redeem_script and witness_script) and \
                        (len(redeem_script) == 34) and \
                        (redeem_script[0]) == 0 and (redeem_script[1] == 32):
                    # can also check if redeem script hashes to hash160 and compare with scriptPubKey
                    af = AF_P2WSH_P2SH

                # no need to proceed to script verification if address format does not match
                if af != active_multisig.addr_fmt:
                    self.is_change = False
                    return af

                # redeem script must be exactly what we expect
                # - pubkeys will be reconstructed from derived paths here
                # - BIP-45, BIP-67 rules applied (BIP-67 optional from now - depending on imported descriptor)
                # - p2sh-p2wsh needs witness script here, not redeem script value
                # - if details provided in output section, must our match multisig wallet
                try:
                    active_multisig.validate_script(witness_script or redeem_script,
                                                            subpaths=self.subpaths)
                except BaseException as exc:
                    raise FraudulentChangeOutput(out_idx, 
                                "P2WSH or P2SH change output script: %s" % exc)

                if is_segwit:
                    # p2wsh case
                    # - need witness script and check it's hash against proposed p2wsh value
                    assert len(addr_or_pubkey) == 32
                    expect_wsh = ngu.hash.sha256s(witness_script)
                    if expect_wsh != addr_or_pubkey:
                        raise FraudulentChangeOutput(out_idx, "P2WSH witness script has wrong hash")

                    self.is_change = True
                    return af

                if witness_script:
                    # p2sh-p2wsh case (because it had witness script)
                    expect_rs = b'\x00\x20' + ngu.hash.sha256s(witness_script)
                    
                    if redeem_script and expect_rs != redeem_script:
                        # iff they provide a redeeem script, then it needs to match
                        # what we expect it to be
                        raise FraudulentChangeOutput(out_idx,
                                        "P2SH-P2WSH redeem script provided, and doesn't match")

                    expect_pkh = hash160(expect_rs)
                else:
                    # old BIP-16 style; looks like payment addr
                    expect_pkh = hash160(redeem_script)

        elif af in [AF_CLASSIC, AF_P2WPKH]:
            # input is hash160 of a single public key
            assert len(addr_or_pubkey) == 20
            expect_pkh = hash160(expect_pubkey)
        else:
            # we don't know how to "solve" this type of input
            return af

        if pkh != expect_pkh:
            raise FraudulentChangeOutput(out_idx, "Change output is fraudulent")

        # We will check pubkey value at the last second, during signing.
        self.is_change = True
        return af


# Track details of each input of PSBT
#
class psbtInputProxy(psbtProxy):

    # just need to store a simple number for these
    short_values = { PSBT_IN_SIGHASH_TYPE }

    # only part-sigs have a key to be stored.
    no_keys = { PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE,
                     PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_FINAL_SCRIPTSIG,
                     PSBT_IN_FINAL_SCRIPTWITNESS }

    blank_flds = (
        'unknown', 'utxo', 'witness_utxo', 'sighash', 'redeem_script', 'witness_script',
        'fully_signed', 'is_segwit', 'is_multisig', 'is_p2sh', 'num_our_keys',
        'required_key', 'scriptSig', 'amount', 'scriptCode', 'previous_txid',
        'prevout_idx', 'sequence', 'req_time_locktime', 'req_height_locktime'
    )

    def __init__(self, fd, idx):
        super().__init__()

        #self.utxo = None
        #self.witness_utxo = None
        self.part_sigs = {}
        self.added_sigs = {}  # signature that CC added (clearly separated from what can be already in part_sigs)
        #self.sighash = None
        self.subpaths = {}          # will typically be non-empty for all inputs
        #self.redeem_script = None
        #self.witness_script = None

        # Non-zero if one or more of our signing keys involved in input
        #self.num_our_keys = None

        # things we've learned
        #self.fully_signed = False

        # we can't really learn this until we take apart the UTXO's scriptPubKey
        #self.is_segwit = None
        #self.is_multisig = None
        #self.is_p2sh = False

        #self.required_key = None    # which of our keys will be used to sign input
        #self.scriptSig = None
        #self.amount = None
        #self.scriptCode = None      # only expected for segwit inputs

        # after signing, we'll have a signature to add to output PSBT

        #self.previous_txid = None
        #self.prevout_idx = None
        #self.sequence = None
        #self.req_time_locktime = None
        #self.req_height_locktime = None

        self.parse(fd)

    def has_relative_timelock(self, txin):
        # https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
        SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)
        SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)
        SEQUENCE_LOCKTIME_MASK = 0x0000ffff
        SEQUENCE_LOCKTIME_GRANULARITY = 9
        is_timebased = False

        if txin.nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            # RTL disabled
            return
        if txin.nSequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
            # Time-based relative lock-time
            is_timebased = True
            res = (txin.nSequence & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY
        else:
            # Block height relative lock-time
            res = txin.nSequence & SEQUENCE_LOCKTIME_MASK

        if res == 0:
            # any locktime that is zero, regardless of MPT or blocks
            # is always immediately spendable
            return

        return is_timebased, res

    def validate(self, idx, txin, my_xfp, parent):
        # Validate this txn input: given deserialized CTxIn and maybe witness

        # TODO: tighten these
        if self.witness_script:
            assert self.witness_script[1] >= 30
        if self.redeem_script:
            assert self.redeem_script[1] >= 22

        # require path for each addr, check some are ours

        # rework the pubkey => subpath mapping
        self.parse_subpaths(my_xfp, parent.warnings)

        if self.part_sigs:
            # How complete is the set of signatures so far?
            # - assuming PSBT creator doesn't give us extra data not required
            # - seems harmless if they fool us into thinking already signed; we do nothing
            # - could also look at pubkey needed vs. sig provided
            # - could consider structure of MofN in p2sh cases
            self.fully_signed = (len(self.part_sigs) >= len(self.subpaths))
        else:
            # No signatures at all yet for this input (typical non multisig)
            self.fully_signed = False

        if self.utxo:
            # Important: they might be trying to trick us with an un-related
            # funding transaction (UTXO) that does not match the input signature we're making
            # (but if it's segwit, the ploy wouldn't work, Segwit FtW)
            # - challenge: it's a straight dsha256() for old serializations, but not for newer
            #   segwit txn's... plus I don't want to deserialize it here.
            try:
                observed = uint256_from_str(calc_txid(self.fd, self.utxo))
            except:
                raise AssertionError("Trouble parsing UTXO given for input #%d" % idx)

            assert txin.prevout.hash == observed, "utxo hash mismatch for input #%d" % idx

    def handle_none_sighash(self):
        if self.sighash is None:
            self.sighash = SIGHASH_ALL

    def has_utxo(self):
        # do we have a copy of the corresponding UTXO?
        return bool(self.utxo) or bool(self.witness_utxo)

    def get_utxo(self, idx):
        # Load up the TxOut for specific output of the input txn associated with this in PSBT
        # Aka. the "spendable" for this input #.
        # - preserve the file pointer
        # - nValue needed for total_value_in, but all fields needed for signing
        #
        fd = self.fd
        old_pos = fd.tell()

        if self.witness_utxo:
            # Going forward? Just what we will witness; no other junk
            # - prefer this format, altho does that imply segwit txn must be generated?
            # - I don't know why we wouldn't always use this
            # - once we use this partial utxo data, we must create witness data out

            fd.seek(self.witness_utxo[0])
            utxo = CTxOut()
            utxo.deserialize(fd)
            fd.seek(old_pos)

            return utxo

        assert self.utxo, 'no utxo'

        # skip over all the parts of the txn we don't care about, without
        # fully parsing it... pull out a single TXO
        fd.seek(self.utxo[0])

        _, marker, flags = unpack("<iBB", fd.read(6))
        wit_format = (marker == 0 and flags != 0x0)
        if not wit_format:
            # rewind back over marker+flags
            fd.seek(-2, 1)

        # How many ins? We accept zero here because utxo's inputs might have been
        # trimmed to save space, and we have test cases like that.
        num_in = deser_compact_size(fd)
        _skip_n_objs(fd, num_in, 'CTxIn')

        num_out = deser_compact_size(fd)
        assert idx < num_out, "not enuf outs"
        _skip_n_objs(fd, idx, 'CTxOut')

        utxo = CTxOut()
        utxo.deserialize(fd)

        # ... followed by more outs, and maybe witness data, but we don't care ...

        fd.seek(old_pos)

        return utxo

    def determine_my_signing_key(self, my_idx, utxo, my_xfp, psbt, cosign_xfp=None):
        # See what it takes to sign this particular input
        # - type of script
        # - which pubkey needed
        # - scriptSig value
        # - also validates redeem_script when present

        self.amount = utxo.nValue

        if not self.subpaths or self.fully_signed:
            # without xfp+path we will not be able to sign this input
            # - okay if fully signed
            # - okay if payjoin or other multi-signer (not multisig) txn
            self.required_key = None
            return

        self.is_multisig = False
        self.is_p2sh = False
        which_key = None

        addr_type, addr_or_pubkey, addr_is_segwit = utxo.get_address()
        if addr_type == OP_RETURN:
            self.required_key = None
            return
        if addr_type == AF_P2TR:
            raise FatalPSBTIssue("Install EDGE firmware to spend taproot.")
        if addr_type is None:
            # If this is reached, we do not understand the output well
            # enough to allow the user to authorize the spend, so fail hard.
            raise FatalPSBTIssue('Unhandled scriptPubKey: ' + b2a_hex(addr_or_pubkey).decode())

        if addr_is_segwit and not self.is_segwit:
            self.is_segwit = True

        if addr_type in [AF_P2SH, AF_P2WSH]:
            # multisig input
            self.is_p2sh = True

            # we must have the redeem script already (else fail)
            ks = self.witness_script or self.redeem_script
            if not ks:
                raise FatalPSBTIssue("Missing redeem/witness script for input #%d" % my_idx)

            redeem_script = self.get(ks)
            self.scriptSig = redeem_script

            # new cheat: psbt creator probably telling us exactly what key
            # to use, by providing exactly one. This is ideal for p2sh wrapped p2pkh
            if len(self.subpaths) == 1:
                which_key, = self.subpaths.keys()
            else:
                # Assume we'll be signing with any key we know
                # - limitation: we cannot be two legs of a multisig (only if CCC feature used)
                # - but if partial sig already in place, ignore that one
                if not which_key:
                    which_key = set()

                for pubkey, path in self.subpaths.items():
                    if self.part_sigs and (pubkey in self.part_sigs):
                        # pubkey has already signed, so ignore
                        continue

                    if path[0] in (my_xfp, cosign_xfp):
                        # slight chance of dup xfps, so handle
                        which_key.add(pubkey)

            if not addr_is_segwit and \
                    len(redeem_script) == 22 and \
                    redeem_script[0] == 0 and redeem_script[1] == 20:
                # it's actually segwit p2pkh inside p2sh
                addr_type = AF_P2WPKH_P2SH
                addr = redeem_script[2:22]
                self.is_segwit = True
            else:
                # multiple keys involved
                self.is_multisig = True

            if self.witness_script and not self.is_segwit and self.is_multisig:
                # bugfix
                addr_type = AF_P2WSH_P2SH
                self.is_segwit = True

        elif addr_type in [AF_CLASSIC, AF_P2WPKH]:
            # input is hash160 of a single public key
            self.scriptSig = utxo.scriptPubKey
            addr = addr_or_pubkey

            for pubkey in self.subpaths:
                if hash160(pubkey) == addr:
                    which_key = pubkey
                    break
            else:
                # none of the pubkeys provided hashes to that address
                raise FatalPSBTIssue('Input #%d: pubkey vs. address wrong' % my_idx)

        elif addr_type == AF_BARE_PK:
            # input is single public key (less common)
            self.scriptSig = utxo.scriptPubKey
            assert len(addr_or_pubkey) == 33

            if addr_or_pubkey in self.subpaths:
                which_key = addr_or_pubkey
            else:
                # pubkey provided is just wrong vs. UTXO
                raise FatalPSBTIssue('Input #%d: pubkey wrong' % my_idx)

        else:
            # we don't know how to "solve" this type of input
            pass

        if self.is_multisig:
            # We will be signing this input, so 
            # - find which wallet it is or
            # - check it's the right M/N to match redeem script
            # - which_key can be empty set, meaning all is already signed

            #print("redeem: %s" % b2a_hex(redeem_script))
            M, N = disassemble_multisig_mn(redeem_script)
            xfp_paths = list(self.subpaths.values())
            xfp_paths.sort()

            # only search wallets with correct script type (aka address format)
            if not psbt.active_multisig:
                # search for multisig wallet
                wal = MultisigWallet.find_match(M, N, xfp_paths, [addr_type])
                if not wal:
                    raise FatalPSBTIssue('Unknown multisig wallet')

                psbt.active_multisig = wal
            else:
                # check consistent w/ already selected wallet
                psbt.active_multisig.assert_matching(M, N, xfp_paths, addr_type)

            # validate redeem script, by disassembling it and checking all pubkeys
            try:
                psbt.active_multisig.validate_script(redeem_script, subpaths=self.subpaths)
                target_spk, _ = chains.current_chain().script_pubkey(addr_type, script=redeem_script)
                assert target_spk == utxo.scriptPubKey, "spk mismatch"
            except BaseException as exc:
                # sys.print_exception(exc)
                raise FatalPSBTIssue('Input #%d: %s' % (my_idx, exc))

        if not which_key and DEBUG:
            print("no key: input #%d: type=%s segwit=%d a_or_pk=%s scriptPubKey=%s" % (
                    my_idx, chains.addr_fmt_str(addr_type), self.is_segwit or 0,
                    b2a_hex(addr_or_pubkey), b2a_hex(utxo.scriptPubKey)))

        self.required_key = which_key

        if self.is_segwit:
            if addr_type in [AF_P2WPKH, AF_P2WPKH_P2SH]:
                # This comment from <https://bitcoincore.org/en/segwit_wallet_dev/>:
                #
                #   Please note that for a P2SH-P2WPKH, the scriptCode is always 26
                #   bytes including the leading size byte, as 0x1976a914{20-byte keyhash}88ac,
                #   NOT the redeemScript nor scriptPubKey
                #
                # Also need this scriptCode for native segwit p2pkh
                #
                assert not self.is_multisig
                self.scriptCode = b'\x19\x76\xa9\x14' + addr + b'\x88\xac'
            elif not self.scriptCode:
                # Segwit P2SH. We need the witness script to be provided.
                if not self.witness_script:
                    raise FatalPSBTIssue('Need witness script for input #%d' % my_idx)

                # "scriptCode is witnessScript preceeded by a
                #  compactSize integer for the size of witnessScript"
                self.scriptCode = ser_string(self.get(self.witness_script))

        # Could probably free self.subpaths and self.redeem_script now, but only if we didn't
        # need to re-serialize as a PSBT.

    def store(self, kt, key, val):
        # Capture what we are interested in.

        if kt == PSBT_IN_NON_WITNESS_UTXO:
            self.utxo = val
        elif kt == PSBT_IN_WITNESS_UTXO:
            self.witness_utxo = val
        elif kt == PSBT_IN_PARTIAL_SIG:
            self.part_sigs[key[1:]] = val
        elif kt == PSBT_IN_BIP32_DERIVATION:
            self.subpaths[key[1:]] = val
        elif kt == PSBT_IN_REDEEM_SCRIPT:
            self.redeem_script = val
        elif kt == PSBT_IN_WITNESS_SCRIPT:
            self.witness_script = val
        elif kt == PSBT_IN_SIGHASH_TYPE:
            self.sighash = unpack('<I', val)[0]
        elif kt == PSBT_IN_PREVIOUS_TXID:
            self.previous_txid = val
        elif kt == PSBT_IN_OUTPUT_INDEX:
            self.prevout_idx = val
        elif kt == PSBT_IN_SEQUENCE:
            self.sequence = unpack("<I", self.get(val))[0]
        elif kt == PSBT_IN_REQUIRED_TIME_LOCKTIME:
            self.req_time_locktime = unpack("<I", self.get(val))[0]
        elif kt == PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
            self.req_height_locktime = unpack("<I", self.get(val))[0]
        else:
            # including: PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS
            self.unknown = self.unknown or {}
            if key in self.unknown:
                raise FatalPSBTIssue("Duplicate key. Key for unknown value already provided in input.")
            self.unknown[key] = val

    def serialize(self, out_fd, is_v2):
        # Output this input's values; might include signatures that weren't there before

        wr = lambda *a: self.write(out_fd, *a)

        if self.utxo:
            wr(PSBT_IN_NON_WITNESS_UTXO, self.utxo)
        if self.witness_utxo:
            wr(PSBT_IN_WITNESS_UTXO, self.witness_utxo)

        if self.part_sigs:
            for pk, sig in self.part_sigs.items():
                wr(PSBT_IN_PARTIAL_SIG, sig, pk)

        if self.added_sigs:
            for pk, sig in self.added_sigs.items():
                wr(PSBT_IN_PARTIAL_SIG, sig, pk)

        if self.sighash is not None:
            wr(PSBT_IN_SIGHASH_TYPE, pack('<I', self.sighash))

        for k in self.subpaths:
            wr(PSBT_IN_BIP32_DERIVATION, self.subpaths[k], k)

        if self.redeem_script:
            wr(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            wr(PSBT_IN_WITNESS_SCRIPT, self.witness_script)

        if is_v2:
            wr(PSBT_IN_PREVIOUS_TXID, self.previous_txid)

            wr(PSBT_IN_OUTPUT_INDEX, self.prevout_idx)

            if self.sequence is not None:
                wr(PSBT_IN_SEQUENCE, pack("<I", self.sequence))

            if self.req_time_locktime is not None:
                wr(PSBT_IN_REQUIRED_TIME_LOCKTIME, pack("<I", self.req_time_locktime))

            if self.req_height_locktime is not None:
                wr(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, pack("<I", self.req_height_locktime))

        if self.unknown:
            for k, v in self.unknown.items():
                wr(k[0], v, k[1:])



class psbtObject(psbtProxy):
    "Just? parse and store"
    short_values = { PSBT_GLOBAL_TX_MODIFIABLE }
    no_keys = { PSBT_GLOBAL_UNSIGNED_TX }

    def __init__(self):
        super().__init__()

        # global objects
        self.version = None
        self.txn = None
        self.xpubs = []         # tuples(xfp_path, xpub)

        self.my_xfp = settings.get('xfp', 0)

        # details that we discover as we go
        self.inputs = None
        self.outputs = None
        self.had_witness = None
        self.num_inputs = None
        self.num_outputs = None
        self.txn_modifiable = None
        self.fallback_locktime = None
        self.vin_start = None
        self.vout_start = None
        self.wit_start = None
        self.txn_version = None
        self._lock_time = None
        self.total_value_out = None
        self.total_value_in = None
        self.presigned_inputs = set()
        # will be tru if number of change outputs equals to total number of outputs
        self.consolidation_tx = False
        # number of change outputs
        self.num_change_outputs = None
        self.total_change_value = None

        # when signing segwit stuff, there is some re-use of hashes
        # only if SIGHASH_ALL
        self.hashPrevouts = None
        self.hashSequence = None
        self.hashOutputs = None

        # this points to a MS wallet, during operation
        # - we are only supporting a single multisig wallet during signing
        self.active_multisig = None

        self.warnings = []
        # not a warning just more info about tx
        # presented in UX on confirm tx screen before warnings
        self.ux_notes = []

        # v1 vs v2 validation
        self.is_v2 = False
        self.has_gic = False  # global input count
        self.has_goc = False  # global output count
        self.has_gtv = False  # global txn version

    @property
    def lock_time(self):
        return (self._lock_time or self.fallback_locktime) or 0

    def store(self, kt, key, val):
        # capture the values we care about

        if kt == PSBT_GLOBAL_UNSIGNED_TX:
            self.txn = val
        elif kt == PSBT_GLOBAL_XPUB:
            # list of tuples(xfp_path, xpub)
            self.xpubs.append( (self.get(val), key[1:]) )
            assert len(self.xpubs) <= MAX_SIGNERS
        elif kt == PSBT_GLOBAL_VERSION:
            self.version = unpack("<I", self.get(val))[0]
        elif kt == PSBT_GLOBAL_TX_VERSION:
            self.txn_version = unpack("<I", self.get(val))[0]
            self.has_gtv = True
        elif kt == PSBT_GLOBAL_FALLBACK_LOCKTIME:
            self.fallback_locktime = unpack("<I", self.get(val))[0]
        elif kt == PSBT_GLOBAL_INPUT_COUNT:
            self.num_inputs = deser_compact_size(BytesIO(self.get(val)))
            self.has_gic = True
        elif kt == PSBT_GLOBAL_OUTPUT_COUNT:
            self.num_outputs = deser_compact_size(BytesIO(self.get(val)))
            self.has_goc = True
        elif kt == PSBT_GLOBAL_TX_MODIFIABLE:
            # bytes of length 1 (tx modifiable in short_values)
            assert len(val) == 1
            self.txn_modifiable = val[0]
        else:
            self.unknown = self.unknown or {}
            if key in self.unknown:
                raise FatalPSBTIssue("Duplicate key. Key for unknown value already provided in global namespace.")
            self.unknown[key] = val

    def output_iter(self, start=0, stop=None):
        # yield the txn's outputs: index, (CTxOut object) for each
        if stop is None:
            stop = self.num_outputs

        if self.is_v2:
            for idx in range(start, stop):
                out = self.outputs[idx]
                amount = unpack("<q", self.get(out.amount))[0]
                spk = self.get(out.script)
                tx_out = CTxOut(nValue=amount, scriptPubKey=spk)
                yield idx, tx_out
        else:
            assert self.vout_start is not None     # must call input_iter/validate first

            fd = self.fd
            fd.seek(self.vout_start)

            if start != 0:
                _skip_n_objs(fd, start, 'CTxOut')

            tx_out = CTxOut()
            for idx in range(start, stop):
                tx_out.deserialize(fd)
                cont = fd.tell()
                yield idx, tx_out

                fd.seek(cont)

    def parse_txn(self):
        # Need to semi-parse in unsigned transaction.
        # - learn number of ins/outs so rest of PSBT can be understood
        # - also captures lots of position details
        # - called right after globals section is read
        fd = self.fd
        old_pos = fd.tell()
        fd.seek(self.txn[0])

        # see serializations.py:CTransaction.deserialize()
        # and BIP-144 ... we expect witness serialization, but
        # don't force that

        self.txn_version, marker, flags = unpack("<iBB", fd.read(6))
        self.had_witness = (marker == 0 and flags != 0x0)

        assert self.txn_version in {1,2,3}, "bad txn version"

        if not self.had_witness:
            # rewind back over marker+flags
            fd.seek(-2, 1)

        num_in = deser_compact_size(fd)
        assert num_in > 0, "no ins?"

        self.num_inputs = num_in

        # all the ins are in sequence starting at this position
        self.vin_start = _skip_n_objs(fd, num_in, 'CTxIn')

        # next is outputs
        self.num_outputs = deser_compact_size(fd)

        self.vout_start = _skip_n_objs(fd, self.num_outputs, 'CTxOut')

        end_pos = sum(self.txn)

        # remainder is the witness data, and then the lock time

        if self.had_witness:
            # we'll need to come back to this pos if we
            # want to read the witness data later.
            self.wit_start = _skip_n_objs(fd, num_in, 'CTxInWitness')

        # we are at end of outputs, and no witness data, so locktime is here
        self._lock_time = unpack("<I", fd.read(4))[0]

        assert fd.tell() == end_pos, 'txn read end wrong'

        fd.seek(old_pos)

    def input_iter(self):
        # Yield each of the txn's inputs, as a tuple:
        #
        #   (index, CTxIn)
        #
        # - we also capture much data about the txn on the first pass thru here
        #
        if self.is_v2:
            for idx in range(self.num_inputs):
                inp = self.inputs[idx]
                prevout = COutPoint(uint256_from_str(self.get(inp.previous_txid)),
                                    unpack("<I", self.get(inp.prevout_idx))[0])
                sequence = inp.sequence if inp.sequence is not None else 0xffffffff
                txin = CTxIn(outpoint=prevout, nSequence=sequence)
                yield idx, txin
        else:
            fd = self.fd

            assert self.vin_start
            # stream out the inputs
            fd.seek(self.vin_start)

            txin = CTxIn()
            for idx in range(self.num_inputs):
                txin.deserialize(fd)

                cont = fd.tell()
                yield idx, txin

                fd.seek(cont)

    def input_witness_iter(self):
        # yield all the witness data, in order by input
        if not self.had_witness:
            # original txn had no witness data, so provide placeholder objs
            for in_idx in range(self.num_inputs):
                yield in_idx, CTxInWitness()
            return

        fd.seek(self.wit_start)
        for idx in range(num_in):

            wit = CTxInWitness()
            wit.deserialize(fd)

            cont = fd.tell()
            yield idx, wit

            fd.seek(cont)

    def guess_M_of_N(self):
        # Peek at the inputs to see if we can guess M/N value. Just takes
        # first one it finds.
        #
        for i in self.inputs:
            # definitely not our if no subpaths
            if not i.subpaths: continue
            ks = i.witness_script or i.redeem_script
            if not ks: continue

            rs = i.get(ks)
            if rs[-1] != OP_CHECKMULTISIG: continue

            M, N = disassemble_multisig_mn(rs)
            # does not match PSBT_XPUBS length
            if N != len(self.xpubs): continue

            assert 1 <= M <= N <= MAX_SIGNERS

            # guess address format also - based on scripts provided by PSBT provider
            if i.witness_script and not i.redeem_script:
                af = AF_P2WSH
            elif i.witness_script and i.redeem_script:
                af = AF_P2WSH_P2SH
            else:
                af = AF_P2SH

            return af, M, N

        return None, None, None

    async def handle_xpubs(self):
        # Lookup correct wallet based on xpubs in globals
        # - only happens if they volunteered this 'extra' data
        # - do not assume multisig
        assert not self.active_multisig

        xfp_paths = []
        has_mine = 0
        for k,_ in self.xpubs:
            h = unpack_from('<%dI' % (len(k)//4), k, 0)
            assert len(h) >= 1
            xfp_paths.append(h)

            if h[0] == self.my_xfp:
                has_mine += 1

        if not has_mine:
            raise FatalPSBTIssue('My XFP not involved')

        candidates = MultisigWallet.find_candidates(xfp_paths)

        if len(candidates) == 1:
            # exact match (by xfp+deriv set) .. normal case
            self.active_multisig = candidates[0]
        else:
            # don't want to guess M if not needed, but we need it
            af, M, N = self.guess_M_of_N()

            if not N:
                # not multisig, but we can still verify:
                # - XFP should be one of ours (checked above).
                # - too slow to re-derive it here, so nothing more to validate at this point
                return

            assert N == len(xfp_paths)

            for c in candidates:
                if c.M == M and c.N == N:
                    self.active_multisig = c
                    break
            # if not active_multisig set in this loop
            # appropriate candidate was not found
            # --> continue to import from psbt prompt

        del candidates

        if not self.active_multisig:
            # Maybe create wallet, for today, forever, or fail, etc.
            proposed, need_approval = MultisigWallet.import_from_psbt(af, M, N, self.xpubs)
            if need_approval:
                # do a complex UX sequence, which lets them save new wallet
                from glob import hsm_active
                if hsm_active:
                    raise FatalPSBTIssue("MS enroll not allowed in HSM mode")

                ch = await proposed.confirm_import()
                if ch != 'y':
                    raise FatalPSBTIssue("Refused to import new wallet")

            self.active_multisig = proposed
        else:
            # Validate good match here. The xpubs must be exactly right, but
            # we're going to use our own values from setup time anyway and not trusting
            # new values without user interaction.
            # Check:
            # - chain codes match what we have stored already
            # - pubkey vs. path will be checked later
            # - xfp+path already checked above when selecting wallet
            # Any issue here is a fraud attempt in some way, not innocent.
            self.active_multisig.validate_psbt_xpubs(self.xpubs)

        if not self.active_multisig:
            # not clear if an error... might be part-way to importing, and
            # the data is optional anyway, etc. If they refuse to import, 
            # we should not reach this point (ie. raise something to abort signing)
            return

    def ux_relative_timelocks(self, tb, bb):
        # visualize 10 largest timelock to user
        # when signing a tx
        MAX_SHOW = 10
        num_tb = len(tb)
        num_bb = len(bb)

        if (num_tb + num_bb) > MAX_SHOW:
            # 10 from each is enough for us to have in memory
            tb = sorted(tb, key=lambda item: item[1], reverse=True)[:10]
            bb = sorted(bb, key=lambda item: item[1], reverse=True)[:10]
            if (num_tb >= 5) and (num_bb >= 5):
                # 5 biggest from each
                tb = tb[:5]
                bb = bb[:5]
            else:
                if num_tb < num_bb:
                    tb = tb[:num_tb]
                    bb = bb[:(MAX_SHOW - num_tb)]
                else:
                    bb = bb[:num_bb]
                    tb = tb[:(MAX_SHOW - num_bb)]

        if num_bb:
            # Block height relative lock-time
            if num_bb == 1:
                idx, val = bb[0]
                msg = "Input %d. has relative block height timelock of %d blocks\n" % (
                        idx, val
                    )
            elif all(bb[0][1] == i[1] for i in bb):
                msg = "%d inputs have relative block height timelock of %d blocks\n" % (
                        num_bb, bb[0][1]
                    )
            else:
                msg = "%d inputs have relative block height timelock." % num_bb
                if num_bb > len(bb):
                    msg += " Showing only %d with highest values." % len(bb)
                msg += "\n\n"
                for idx, num_blocks in bb:
                    msg += " %d.  %d blocks\n" % (idx, num_blocks)

            self.ux_notes.append(("Block height RTL", msg))

        if num_tb:
            # Block height relative lock-time
            if num_tb == 1:
                idx, val = tb[0]
                val = seconds2human_readable(val)
                msg = "Input %d. has relative time-based timelock of:\n %s\n" % (
                    idx, val
                )
            elif all(tb[0][1] == i[1] for i in tb):
                msg = "%d inputs have relative time-based timelock of:\n %s\n" % (
                        num_tb, seconds2human_readable(tb[0][1])
                    )
            else:
                msg = "%d inputs have relative time-based timelock." % num_tb
                if num_tb > len(tb):
                    msg += " Showing only %d with highest values." % len(tb)
                msg += "\n\n"
                for idx, seconds in tb:
                    hr = seconds2human_readable(seconds)
                    msg += " %d.  %s\n" % (idx, hr)

            self.ux_notes.append(("Time-based RTL", msg))

    async def validate(self):
        # Do a first pass over the txn. Raise assertions, be terse tho because
        # these messages are rarely seen. These are syntax/fatal errors.
        #
        if self.version is not None:
            # verision is provided in PSBT - take it as given
            assert self.version in (0,2)
        else:
            # PSBT version is not defined
            # global unsigned tx is only allowed in v0
            self.version = 2 if self.txn is None else 0

        self.is_v2 = self.version is not None and self.version >= 2

        if self.is_v2:
            assert self.has_gic, "v2 requires global input count"
            assert self.has_goc, "v2 requires global output count"
            assert self.has_gtv, "v2 requires global txn version"
            assert self.txn is None, "v2 requires exclusion of global unsigned tx"
        else:
            assert not self.has_gic, "v0 requires exclusion of global input count"
            assert not self.has_goc, "v0 requires exclusion of global output count"
            assert not self.has_gtv, "v0 requires exclusion of global txn version"
            assert self.txn, "v0 requires inclusion of global unsigned tx"
            assert self.txn[1] > 61, 'txn too short'
            assert self.fallback_locktime is None, "v0 requires exclusion of global fallback locktime"
            assert self.txn_modifiable is None, "v0 requires exclusion of global txn modifiable"

        for idx, txo in self.output_iter():
            out = self.outputs[idx]
            if self.is_v2:
                # v2 requires inclusion
                assert out.amount
                assert out.script
            else:
                # v0 requires exclusion
                assert out.amount is None
                assert out.script is None

        # time based relative locks
        tb_rel_locks = []
        # block height based relative locks
        bb_rel_locks = []
        smallest_nsequence = 0xffffffff
        # this parses the input TXN in-place
        for idx, txin in self.input_iter():
            inp = self.inputs[idx]
            if self.is_v2:
                # v2 requires inclusion
                assert inp.prevout_idx is not None
                assert inp.previous_txid
                if inp.req_time_locktime is not None:
                    assert inp.req_time_locktime >= NLOCK_IS_TIME
                if inp.req_height_locktime is not None:
                    assert 0 < inp.req_height_locktime < NLOCK_IS_TIME
            else:
                # v0 requires exclusion
                assert inp.prevout_idx is None
                assert inp.previous_txid is None
                assert inp.sequence is None
                assert inp.req_time_locktime is None
                assert inp.req_height_locktime is None

            self.inputs[idx].validate(idx, txin, self.my_xfp, self)
            if self.txn_version >= 2:
                has_rtl = self.inputs[idx].has_relative_timelock(txin)
                if has_rtl:
                    if has_rtl[0]:
                        tb_rel_locks.append((idx, has_rtl[1]))
                    else:
                        bb_rel_locks.append((idx, has_rtl[1]))

            if txin.nSequence < smallest_nsequence:
                smallest_nsequence = txin.nSequence

        if isinstance(self.lock_time, int) and self.lock_time > 0:
            if smallest_nsequence == 0xffffffff:
                self.warnings.append((
                    "Bad Locktime",
                    "Locktime has no effect! None of the nSequences decremented."
                ))
            else:
                msg = "This tx can only be spent after "
                if self.lock_time < NLOCK_IS_TIME:
                    msg += "block height of %d" % self.lock_time
                else:
                    try:
                        dt = datetime_from_timestamp(self.lock_time)
                        msg += datetime_to_str(dt)
                    except:
                        msg += "%d (unix timestamp)" % self.lock_time

                    msg += " (MTP)"  # median time past
                msg += "\n"
                self.ux_notes.append(("Abs Locktime", msg))

        # create UX for users about tx level relative timelocks (nSequence)
        self.ux_relative_timelocks(tb_rel_locks, bb_rel_locks)

        assert len(self.inputs) == self.num_inputs, 'ni mismatch'

        # if multisig xpub details provided, they better be right and/or offer import
        if self.xpubs:
            await self.handle_xpubs()

        assert self.num_outputs >= 1, 'need outputs'

        if DEBUG:
            our_keys = sum(1 for i in self.inputs if i.num_our_keys)

            print("PSBT: %d inputs, %d output, %d fully-signed, %d ours" % (
                   self.num_inputs, self.num_outputs,
                   sum(1 for i in self.inputs if i and i.fully_signed), our_keys))

    def consider_outputs(self):
        # scan ouputs:
        # - is it a change address, defined by redeem script (p2sh) or key we know is ours
        # - mark change outputs, so perhaps we don't show them to users
        total_out = 0
        total_change = 0
        num_op_return = 0
        num_op_return_size = 0
        num_unknown_scripts = 0
        zero_val_outs = 0  # only those that are not OP_RETURN are considered
        self.num_change_outputs = 0

        for idx, txo in self.output_iter():
            output = self.outputs[idx]
            # perform output validation
            af = output.validate(idx, txo, self.my_xfp, self.active_multisig, self)
            assert txo.nValue >= 0, "negative output value: o%d" % idx
            total_out += txo.nValue

            if (txo.nValue == 0) and (af != OP_RETURN):
                # OP_RETURN outputs have nValue=0 standard
                zero_val_outs += 1

            if output.is_change:
                self.num_change_outputs += 1
                total_change += txo.nValue

            if af == OP_RETURN:
                num_op_return += 1
                if len(txo.scriptPubKey) > 83:
                    num_op_return_size += 1

            elif af is None:
                num_unknown_scripts += 1

        if self.total_value_out is None:
            self.total_value_out = total_out
        else:
            assert self.total_value_out == total_out, \
                '%s != %s' % (self.total_value_out, total_out)

        if self.total_change_value is None:
            self.total_change_value = total_change
        else:
            assert self.total_change_value == total_change, \
                '%s != %s' % (self.total_change_value, total_change)

        # check fee is reasonable
        the_fee = self.calculate_fee()
        if the_fee is None:
            return
        if the_fee < 0:
            raise FatalPSBTIssue("Outputs worth more than inputs!")

        if self.total_value_out:
            per_fee = the_fee * 100 / self.total_value_out
        else:
            per_fee = 100

        fee_limit = settings.get('fee_limit', DEFAULT_MAX_FEE_PERCENTAGE)

        if fee_limit != -1 and per_fee >= fee_limit:
            raise FatalPSBTIssue("Network fee bigger than %d%% of total amount (it is %.0f%%)."
                                % (fee_limit, per_fee))
        if per_fee >= 5:
            self.warnings.append(('Big Fee', 'Network fee is more than '
                                    '5%% of total value (%.1f%%).' % per_fee))

        if (num_op_return > 1) or num_op_return_size:
            mm = ""
            if num_op_return > 1:
                mm += "\nMultiple OP_RETURN outputs: %d" % num_op_return
            if num_op_return_size:
                mm += "\nOP_RETURN > 80 bytes"
            self.warnings.append(
                ("OP_RETURN",
                 "TX may not be relayed by some nodes.%s" % mm))

        if num_unknown_scripts:
            self.warnings.append(
                ('Output?',
                 'Sending to %d not well understood script(s).' % num_unknown_scripts)
            )

        if zero_val_outs:
            self.warnings.append(
                ('Zero Value',
                 'Non-standard zero value output(s).')
            )

        self.consolidation_tx = (self.num_change_outputs == self.num_outputs)

        # Enforce policy related to change outputs
        self.consider_dangerous_change(self.my_xfp)

    def consider_dangerous_sighash(self):
        # Check sighash flags are legal, useful, and safe. Warn about
        # some risks if user has enabled special sighash values.

        sh_unusual = False
        none_sh = False

        for input in self.inputs:
            # only if it is our input - one that will be eventually sign
            if input.num_our_keys:
                if input.sighash is not None:
                    # All inputs MUST have SIGHASH that we are able to sign.
                    if input.sighash not in ALL_SIGHASH_FLAGS:
                        raise FatalPSBTIssue("Unsupported sighash flag 0x%x" % input.sighash)

                    if input.sighash != SIGHASH_ALL:
                        sh_unusual = True

                    if input.sighash in (SIGHASH_NONE, SIGHASH_NONE|SIGHASH_ANYONECANPAY):
                        none_sh = True

        if sh_unusual and not settings.get("sighshchk"):
            if self.consolidation_tx:
                # policy: all inputs must be sighash ALL in purely consolidation txn
                raise FatalPSBTIssue("Only sighash ALL is allowed for pure consolidation transactions.")

            if none_sh:
                # sighash NONE or NONE|ANYONECANPAY is proposed: block
                raise FatalPSBTIssue("Sighash NONE is not allowed as funds could be going anywhere.")

        if none_sh:
            self.warnings.append(
                ("Danger", "Destination address can be changed after signing (sighash NONE).")
            )
        elif sh_unusual:
            self.warnings.append(
                ("Caution", "Some inputs have unusual SIGHASH values not used in typical cases.")
            )

    def consider_dangerous_change(self, my_xfp):
        # Enforce some policy on change outputs:
        # - need to "look like" they are going to same wallet as inputs came from
        # - range limit last two path components (numerically)
        # - same pattern of hard/not hardened components
        # - MAX_PATH_DEPTH already enforced before this point
        #
        in_paths = []
        for inp in self.inputs:
            if inp.fully_signed: continue
            if not inp.required_key: continue
            if not inp.subpaths: continue        # not expected if we're signing it
            for path in inp.subpaths.values():
                if path[0] == my_xfp:
                    in_paths.append(path[1:])

        if not in_paths:
            # We aren't adding any signatures? Can happen but we're going to be 
            # showing a warning about that elsewhere.
            return

        shortest = min(len(i) for i in in_paths)
        longest = max(len(i) for i in in_paths)
        if shortest != longest or shortest <= 2:
            # We aren't seeing shared input path lengths.
            # They are probbably doing weird stuff, so leave them alone.
            return

        # Assumption: hard/not hardened depths will match for all address in wallet
        def hard_bits(p):
            return [bool(i & 0x80000000) for i in p]

        # Assumption: common wallets modulate the last two components only
        # of the path. Typically m/.../change/index where change is {0, 1}
        # and index changes slowly over lifetime of wallet (increasing)
        path_len = shortest
        path_prefix = in_paths[0][0:-2]
        idx_max = max(i[-1]&0x7fffffff for i in in_paths) + 200
        hard_pattern = hard_bits(in_paths[0])

        probs = []
        for nout, out in enumerate(self.outputs):
            if not out.is_change: continue
            # it's a change output, okay if a p2sh change; we're looking at paths
            for path in out.subpaths.values():
                if path[0] != my_xfp: continue          # possible in p2sh case

                path = path[1:]
                if len(path) != path_len:
                    iss = "has wrong path length (%d not %d)" % (len(path), path_len)
                elif hard_bits(path) != hard_pattern:
                    iss = "has different hardening pattern"
                elif path[0:len(path_prefix)] != path_prefix:
                    iss = "goes to diff path prefix"
                elif (path[-2]&0x7fffffff) not in {0, 1}:
                    iss = "2nd last component not 0 or 1"
                elif (path[-1]&0x7fffffff) > idx_max:
                    iss = "last component beyond reasonable gap"
                else:
                    # looks ok
                    continue

                probs.append("Output#%d: %s: %s not %s/{0~1}%s/{0~%d}%s expected" 
                        % (nout, iss, keypath_to_str(path, skip=0),
                            keypath_to_str(path_prefix, skip=0),
                            "'" if hard_pattern[-2] else "",
                            idx_max, "'" if hard_pattern[-1] else "",
                          ))
                break

        for p in probs:
            self.warnings.append(('Troublesome Change Outs', p))

    def consider_inputs(self, cosign_xfp=None):
        # Look at the UTXO's that we are spending. Do we have them? Do the
        # hashes match, and what values are we getting?
        # Important: parse incoming UTXO to build total input value
        foreign = []
        total_in = 0

        for i, txi in self.input_iter():
            inp = self.inputs[i]
            if inp.fully_signed:
                self.presigned_inputs.add(i)

            if not inp.has_utxo():
                if inp.num_our_keys and not inp.fully_signed:
                    # we cannot proceed if the input is ours and there is no UTXO
                    raise FatalPSBTIssue('Missing own UTXO(s). Cannot determine value being signed')
                else:
                    # input clearly not ours
                    foreign.append(i)
                    continue

            # pull out just the CTXOut object (expensive)
            utxo = inp.get_utxo(txi.prevout.n)

            assert utxo.nValue >= 0, "negative input value: i%d" % i
            total_in += utxo.nValue

            # Look at what kind of input this will be, and therefore what
            # type of signing will be required, and which key we need.
            # - also validates redeem_script when present
            # - also finds appropriate multisig wallet to be used
            inp.determine_my_signing_key(i, utxo, self.my_xfp, self, cosign_xfp)

            # iff to UTXO is segwit, then check it's value, and also
            # capture that value, since it's supposed to be immutable
            if inp.is_segwit:
                history.verify_amount(txi.prevout, inp.amount, i)

            del utxo

        # XXX scan witness data provided, and consider those ins signed if not multisig?

        if not foreign:
            # no foreign inputs, we can calculate the total input value
            assert total_in > 0, "zero value txn"
            self.total_value_in = total_in
        else:
            # 1+ inputs don't belong to us, we can't calculate the total input value
            # OK for multi-party transactions (coinjoin etc.)
            self.total_value_in = None
            self.warnings.append(
                ("Unable to calculate fee", "Some input(s) haven't provided UTXO(s): " + seq_to_str(foreign))
            )

        if len(self.presigned_inputs) == self.num_inputs:
            # Maybe wrong for multisig cases? Maybe they want to add their
            # own signature, even tho N of M is satisfied?!
            raise FatalPSBTIssue('Transaction looks completely signed already?')

        # We should know pubkey required for each input now.
        # - but we may not be the signer for those inputs, which is fine.
        # - TODO: but what if not SIGHASH_ALL
        no_keys = set(
            n
            for n,inp in enumerate(self.inputs)
            if (inp.required_key is None) and (not inp.fully_signed)
        )
        if no_keys:
            # This is seen when you re-sign same signed file by accident (multisig)
            # - case of len(no_keys)==num_inputs is handled by consider_keys
            self.warnings.append(('Limited Signing',
                'We are not signing these inputs, because we do not know the key: ' +
                        seq_to_str(no_keys)))

        if self.presigned_inputs:
            # this isn't really even an issue for some complex usage cases
            self.warnings.append(('Partly Signed Already',
                'Some input(s) provided were already completely signed by other parties: ' +
                        seq_to_str(self.presigned_inputs)))

        if MultisigWallet.disable_checks:
            self.warnings.append(('Danger', 'Some multisig checks are disabled.'))

    def calculate_fee(self):
        # what miner's reward is included in txn?
        if self.total_value_in is None:
            return None
        return self.total_value_in - self.total_value_out

    def consider_keys(self):
        # check we posess the right keys for the inputs
        cnt = sum(1 for i in self.inputs if i.num_our_keys)
        if cnt: return

        # collect a list of XFP's given in file that aren't ours
        others = set()
        for inp in self.inputs:
            if not inp.subpaths: continue
            for path in inp.subpaths.values():
                others.add(path[0])

        if not others:
            # Can happen w/ Electrum in watch-mode on XPUB. It doesn't know XFP and
            # so doesn't insert that into PSBT.
            raise FatalPSBTIssue('PSBT does not contain any key path information.')

        others.discard(self.my_xfp)
        msg = ', '.join(xfp2str(i) for i in others)

        raise FatalPSBTIssue('None of the keys involved in this transaction '
                                 'belong to this Coldcard (need %s, found %s).' 
                                    % (xfp2str(self.my_xfp), msg))

    @classmethod
    def read_psbt(cls, fd):
        # read in a PSBT file. Captures fd and keeps it open.
        hdr = fd.read(5)
        if hdr != b'psbt\xff':
            raise ValueError("bad hdr")

        rv = cls()

        # read main body (globals)
        rv.parse(fd)

        if rv.txn:
            # learn about the bitcoin transaction we are signing.
            rv.parse_txn()

        assert rv.num_inputs is not None
        assert rv.num_outputs is not None
        rv.inputs = [psbtInputProxy(fd, idx) for idx in range(rv.num_inputs)]
        rv.outputs = [psbtOutputProxy(fd, idx) for idx in range(rv.num_outputs)]

        return rv

    def serialize(self, out_fd, upgrade_txn=False):
        # Ouput into a file.

        wr = lambda *a: self.write(out_fd, *a)

        out_fd.write(b'psbt\xff')

        if upgrade_txn and self.is_complete():
            # write out the ready-to-transmit txn
            # - means we are also a PSBT combiner in this case
            # - hard tho, due to variable length data.
            # - probably a bad idea, so disabled for now
            out_fd.write(b'\x01\x00')       # keylength=1, key=b'', PSBT_GLOBAL_UNSIGNED_TX

            with SizerFile() as fd:
                self.finalize(fd)
                txn_len = fd.tell()

            out_fd.write(ser_compact_size(txn_len))
            self.finalize(out_fd)
        else:
            if not self.is_v2:  # can be 0 or None
                # provide original txn (unchanged)
                wr(PSBT_GLOBAL_UNSIGNED_TX, self.txn)

        if self.is_v2:
            wr(PSBT_GLOBAL_TX_VERSION, pack('<I', self.txn_version))
            if self.fallback_locktime is not None:
                wr(PSBT_GLOBAL_FALLBACK_LOCKTIME, pack('<I', self.fallback_locktime))
            wr(PSBT_GLOBAL_INPUT_COUNT, ser_compact_size(self.num_inputs))
            wr(PSBT_GLOBAL_OUTPUT_COUNT, ser_compact_size(self.num_outputs))
            if self.txn_modifiable is not None:
                wr(PSBT_GLOBAL_TX_MODIFIABLE, bytes([self.txn_modifiable]))
            wr(PSBT_GLOBAL_VERSION, pack('<I', self.version))

        if self.xpubs:
            for v, k in self.xpubs:
                wr(PSBT_GLOBAL_XPUB, v, k)

        if self.unknown:
            for k, v in self.unknown.items():
                wr(k[0], v, k[1:])

        # sep between globals and inputs
        out_fd.write(b'\0')

        for idx, inp in enumerate(self.inputs):
            inp.serialize(out_fd, self.is_v2)
            out_fd.write(b'\0')

        for idx, outp in enumerate(self.outputs):
            outp.serialize(out_fd, self.is_v2)
            out_fd.write(b'\0')

    @staticmethod
    def check_pubkey_at_path(sv, subpath, target_pk):
        # derive actual pubkey from private
        skp = keypath_to_str(subpath)
        node = sv.derive_path(skp)

        # check the pubkey of this BIP-32 node
        if target_pk == node.pubkey():
            return node
        return None

    @staticmethod
    def ecdsa_grind_sign(sk, digest, sighash):
        # Do the ACTUAL signature ... finally!!!

        # We need to grind sometimes to get a positive R
        # value that will encode (after DER) into a shorter string.
        # - saves on miner's fee (which might be expected/required)
        # - blends in with Bitcoin Core signatures which do this from 0.17.0

        n = 0  # retry num
        while True:
            # time to produce signature on stm32: ~25.1ms
            result = ngu.secp256k1.sign(sk, digest, n).to_bytes()

            if result[1] < 0x80:
                # - no need to check for low S value as those are generated by default
                #   by secp256k1 lib
                # - to produce 71 bytes long signature (both low S low R values),
                #    we need on average 2 retries
                # - worst case ~25 grinding iterations need to be performed total
                break

            n += 1

        # DER serialization after we have low S and low R values in our signature
        r = result[1:33]
        s = result[33:65]
        der_sig = ser_sig_der(r, s, sighash)
        return der_sig

    def sign_it(self, alternate_secret=None, my_xfp=None):
        # txn is approved. sign all inputs we can sign. add signatures
        # - hash the txn first
        # - sign all inputs we have the key for
        # - inputs might be p2sh, p2pkh and/or segwit style
        # - save partial inputs somewhere (append?)
        # - update our state with new partial sigs
        from glob import dis
        from ownership import OWNERSHIP

        if my_xfp is None:
            my_xfp = self.my_xfp

        with stash.SensitiveValues(secret=alternate_secret) as sv:
            # Double-check the change outputs are right. This is slow, but critical because
            # it detects bad actors, not bugs or mistakes.
            # - equivalent check already done for p2sh outputs when we re-built the redeem script
            change_outs = [n for n,o in enumerate(self.outputs) if o.is_change]
            if change_outs:
                dis.fullscreen('Change Check...')

                for count, out_idx in enumerate(change_outs):
                    # only expecting single case, but be general
                    dis.progress_sofar(count, len(change_outs))

                    oup = self.outputs[out_idx]

                    good = 0
                    for pubkey, subpath in oup.subpaths.items():
                        # for multisig, will be N paths, and exactly one will
                        # be our key. For single-signer, should always be my XFP
                        if subpath[0] == my_xfp:
                            # derive actual pubkey from private
                            res = self.check_pubkey_at_path(sv, subpath, pubkey)
                            if res:
                                good += 1
                                # TODO is this needed if output is multisig?
                                OWNERSHIP.note_subpath_used(subpath)

                    if not good:
                        raise FraudulentChangeOutput(out_idx, 
                              "Deception regarding change output. "
                              "BIP-32 path doesn't match actual address.")

            # progress
            dis.fullscreen('Signing...')
            # randomize secp context before each signing session
            ngu.secp256k1.ctx_rnd()
            # Sign individual inputs
            for in_idx, txi in self.input_iter():
                dis.progress_sofar(in_idx, self.num_inputs)

                inp = self.inputs[in_idx]

                if not inp.has_utxo():
                    # maybe they didn't provide the UTXO
                    continue

                if not inp.required_key:
                    # we don't know the key for this input
                    continue

                if inp.fully_signed:
                    # for multisig, it's possible I need to add another sig
                    # but in other cases, no more signatures are possible
                    continue

                txi.scriptSig = inp.scriptSig
                assert txi.scriptSig, "no scriptsig?"

                inp.handle_none_sighash()
                if inp.is_multisig:
                    # need to consider a set of possible keys, since xfp may not be unique
                    for which_key in inp.required_key:
                        # get node required
                        node = self.check_pubkey_at_path(sv, inp.subpaths[which_key], which_key)
                        if node:
                            break
                    else:
                        raise AssertionError("Input #%d needs pubkey I dont have" % in_idx)

                else:
                    # single pubkey <=> single key
                    which_key = inp.required_key

    
                    assert not inp.added_sigs, "already done??"
                    assert which_key in inp.subpaths, 'unk key'

                    if inp.subpaths[which_key][0] != my_xfp:
                        # we don't have the key for this subkey
                        # (redundant, required_key wouldn't be set)
                        continue

                    # get node required
                    skp = keypath_to_str(inp.subpaths[which_key])
                    node = sv.derive_path(skp, register=False)

                    # expensive test, but works... and important
                    pu = node.pubkey()
                    assert pu == which_key, \
                        "Path (%s) led to wrong pubkey for input#%d"%(skp, in_idx)

                    # track wallet usage
                    OWNERSHIP.note_subpath_used(inp.subpaths[which_key])

                if not inp.is_segwit:
                    # Hash by serializing/blanking various subparts of the transaction
                    digest = self.make_txn_sighash(in_idx, txi, inp.sighash)
                else:
                    # Hash the inputs and such in totally new ways, based on BIP-143
                    digest = self.make_txn_segwit_sighash(in_idx, txi,
                                    inp.amount, inp.scriptCode, inp.sighash)

                if sv.deltamode:
                    # Current user is actually a thug with a slightly wrong PIN, so we
                    # do have access to the private keys and could sign txn, but we
                    # are going to silently corrupt our signatures.
                    digest = ngu.hash.sha256d(digest)

                # The precious private key we need
                pk = node.privkey()

                #print("privkey %s" % b2a_hex(pk).decode('ascii'))
                #print(" pubkey %s" % b2a_hex(which_key).decode('ascii'))
                #print(" digest %s" % b2a_hex(digest).decode('ascii'))

                der_sig = self.ecdsa_grind_sign(pk, digest, inp.sighash)

                # private key no longer required
                stash.blank_object(pk)
                stash.blank_object(node)
                del pk, node

                inp.added_sigs[which_key] = der_sig

                # Could remove sighash from input object - it is not required, takes space,
                # and is already in signature or is implicit by not being part of the
                # signature (taproot SIGHASH_DEFAULT)
                ## inp.sighash = None

                if self.is_v2:
                    self.set_modifiable_flag(inp)

                # drop sighash if default (SIGHASH_ALL)
                if inp.sighash == SIGHASH_ALL:
                    inp.sighash = None

                gc.collect()

        # done.
        dis.progress_bar_show(1)

    def set_modifiable_flag(self, inp):
        # only for PSBTv2
        # sighash needs to be properly set on psbtInputProxy object before this runs
        # TODO possible to also cross-check with sighash from signature:
        #    1. witnes/scriptSig in serialized tx in PSBT
        #    2. psbt meta fields partial_sigs, taproot_key_sig and taproot_script_sigs
        if self.txn_modifiable is None:
            # set to inputs/outputs modifiable
            # has SINGLE to false
            self.txn_modifiable = 3

        if not (inp.sighash & SIGHASH_ANYONECANPAY):
            # Bit 0 is the Inputs Modifiable flag - set to 0
            if self.txn_modifiable & 1:
                self.txn_modifiable &= ~1

        out_type = inp.sighash & 0x7f  # regardless of ANYONECANPAY
        if out_type != SIGHASH_NONE:
            # Bit 1 is the Outputs Modifiable flag - set to 0
            if self.txn_modifiable & 2:
                self.txn_modifiable &= ~2

        if out_type == SIGHASH_SINGLE:
            # Bit 2 is the Has SIGHASH_SINGLE flag - set it to 1
            self.txn_modifiable |= 4

    def make_txn_sighash(self, replace_idx, replacement, sighash_type):
        # calculate the hash value for one input of current transaction
        # - blank all script inputs
        # - except one single tx in, which is provided
        # - serialize that without witness data
        # - sha256 over that
        fd = self.fd
        old_pos = fd.tell()

        # sighash regardless of ANYONECANPAY input part
        out_sighash_type = sighash_type & 0x7f

        rv = sha256()

        # version number
        rv.update(pack('<i', self.txn_version))           # nVersion

        # inputs
        num_inputs = 1 if sighash_type & SIGHASH_ANYONECANPAY else self.num_inputs
        rv.update(ser_compact_size(num_inputs))
        for in_idx, txi in self.input_iter():
            if in_idx == replace_idx:
                assert not self.inputs[in_idx].is_segwit
                assert replacement.scriptSig
                rv.update(replacement.serialize())
            elif not (sighash_type & SIGHASH_ANYONECANPAY):
                if out_sighash_type in (SIGHASH_NONE, SIGHASH_SINGLE):
                    # do not include sequence of other inputs (zero them for digest)
                    # which means that they can be replaced
                    txi.nSequence = 0
                txi.scriptSig = b''
                rv.update(txi.serialize())
            # else:
            #    is SIGHASH_ANYONECANPAY so we do not include any other inputs

        # outputs
        if out_sighash_type == SIGHASH_NONE:
            rv.update(ser_compact_size(0))
        elif out_sighash_type == SIGHASH_SINGLE:
            rv.update(ser_compact_size(replace_idx+1))
            assert replace_idx < self.num_outputs, "SINGLE corresponding output (%d) missing" % replace_idx
            for out_idx, txo in self.output_iter():
                if out_idx < replace_idx:
                    rv.update(CTxOut(-1).serialize())
                if out_idx == replace_idx:
                    rv.update(txo.serialize())
        else:
            assert out_sighash_type == SIGHASH_ALL
            rv.update(ser_compact_size(self.num_outputs))
            for out_idx, txo in self.output_iter():
                rv.update(txo.serialize())

        # locktime, sighash_type
        rv.update(pack('<II', self.lock_time, sighash_type))

        fd.seek(old_pos)

        # double SHA256
        return ngu.hash.sha256s(rv.digest())

    def make_txn_segwit_sighash(self, replace_idx, replacement, amount, scriptCode, sighash_type):
        # Implement BIP 143 hashing algo for signature of segwit programs.
        # see <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
        #
        fd = self.fd
        old_pos = fd.tell()

        # sighash regardless of ANYONECANPAY input part
        out_sighash_type = sighash_type & 0x7f

        if self.hashPrevouts and sighash_type == SIGHASH_ALL:
            hashPrevouts = self.hashPrevouts
            hashSequence = self.hashSequence
            hashOutputs = self.hashOutputs
        else:
            # input side
            hashPrevouts = sha256()
            hashSequence = sha256()

            if not (sighash_type & SIGHASH_ANYONECANPAY):
                for in_idx, txi in self.input_iter():
                    hashPrevouts.update(txi.prevout.serialize())
                    if out_sighash_type == SIGHASH_ALL:
                        hashSequence.update(pack("<I", txi.nSequence))

                hashPrevouts = ngu.hash.sha256s(hashPrevouts.digest())
                if out_sighash_type == SIGHASH_ALL:
                    hashSequence = ngu.hash.sha256s(hashSequence.digest())

            # output side
            hashOutputs = sha256()
            if out_sighash_type == SIGHASH_ALL:
                for out_idx, txo in self.output_iter():
                    hashOutputs.update(txo.serialize())

                hashOutputs = ngu.hash.sha256s(hashOutputs.digest())

            elif out_sighash_type == SIGHASH_SINGLE:
                # Even though below case is consensus valid, we block it.
                # If users do not want to sign any outputs, NONE sighash flag
                # should be used instead.
                assert replace_idx < self.num_outputs, \
                            "SINGLE corresponding output (%d) missing" % replace_idx

                for out_idx, txo in self.output_iter():
                    if out_idx == replace_idx:
                        hashOutputs = ngu.hash.sha256d(txo.serialize())
            else:
                assert out_sighash_type == SIGHASH_NONE

            if sighash_type == SIGHASH_ALL:
                # cache this multitude of hashes
                self.hashPrevouts = hashPrevouts
                self.hashSequence = hashSequence
                self.hashOutputs = hashOutputs

            gc.collect()

        rv = sha256()

        # version number
        rv.update(pack('<i', self.txn_version))       # nVersion
        rv.update(hashPrevouts if isinstance(hashPrevouts, bytes) else bytes(32))
        rv.update(hashSequence if isinstance(hashSequence, bytes) else bytes(32))

        rv.update(replacement.prevout.serialize())

        # the "scriptCode" ... not well understood
        assert scriptCode, 'need scriptCode here'
        rv.update(scriptCode)

        rv.update(pack("<q", amount))
        rv.update(pack("<I", replacement.nSequence))

        rv.update(hashOutputs if isinstance(hashOutputs, bytes) else bytes(32))

        # locktime, sighash_type
        rv.update(pack('<II', self.lock_time, sighash_type))

        fd.seek(old_pos)

        # double SHA256
        return ngu.hash.sha256s(rv.digest())

    def multi_input_complete(self, inp):
        # raises if input is not multisig or no active_multisig loaded
        assert inp.is_multisig
        if (len(inp.added_sigs) + len(inp.part_sigs)) >= self.active_multisig.M:
            return True

    def is_complete(self):
        # Are all the inputs (now) signed?

        # some might have been given as signed
        signed = len(self.presigned_inputs)

        # plus we added some signatures
        for inp in self.inputs:
            if inp.is_multisig and self.active_multisig:
                if self.multi_input_complete(inp):
                    signed += 1

            elif inp.added_sigs:
                signed += 1

        return signed == self.num_inputs

    def multisig_signatures(self, inp):
        assert self.active_multisig
        # collect all signatures into one place
        # both we added & those already in part_sigs
        all_sigs = {}
        all_sigs.update(inp.added_sigs)
        for pk, get_data in inp.part_sigs.items():
            all_sigs[pk] = self.get(get_data)

        if self.active_multisig.bip67:
            # BIP-67 easy just sort by public keys
            sigs = [sig for pk, sig in sorted(all_sigs.items())]
        else:
            # need to respect the order of keys in actual descriptor
            sigs = []
            for xfp, _, _ in self.active_multisig.xpubs:
                for pk, pth in inp.subpaths.items():
                    # if xfp matches but pk not in all_sigs -> signer haven't signed
                    # it is ok in threshold multisig - just skip
                    if (xfp == pth[0]) and (pk in all_sigs):
                        sigs.append(all_sigs[pk])
                        break

        # save space and only provide necessary amount of signatures (smaller tx, less fees)
        sigs = sigs[:self.active_multisig.M]
        return sigs

    def singlesig_signature(self, inp):
        # return signature that we added
        # or one signature from partial sigs if input is fully sign
        # (i.e. len(part_sigs)>=len(subpaths))
        ssig = None
        if inp.added_sigs:
            # we have added signature to this single sig input
            assert len(inp.added_sigs) == 1
            ssig = list(inp.added_sigs.items())[0]
        elif inp.part_sigs and inp.fully_signed:
            assert len(inp.part_sigs) == 1
            rv = list(inp.part_sigs.items())[0]
            ssig = rv[0], self.get(rv[1])

        return ssig

    def multisig_xfps_needed(self):
        # provide the set of xfp's that still need to sign PSBT
        # - used to find which multisig-signer needs to go next
        rv = set()
        for inp in self.inputs:
            for pk, pth in inp.subpaths.items():
                if pk in inp.part_sigs:
                    continue
                if pk in inp.added_sigs:
                    continue
                rv.add(pth[0])
        return rv

    def finalize(self, fd):
        # Stream out the finalized transaction, with signatures applied
        # - raise if not complete already
        # - returns the TXID of resulting transaction
        # - but in segwit case, needs to re-read to calculate it
        # - fd must be read/write and seekable to support txid calc

        fd.write(pack('<i', self.txn_version))           # nVersion

        # does this txn require witness data to be included?
        # - yes, if the original txn had some
        # - yes, if we did a segwit signature on any input
        needs_witness = self.had_witness or any(i.is_segwit for i in self.inputs if i)

        if needs_witness:
            # zero marker, and flags=0x01
            fd.write(b'\x00\x01')

        body_start = fd.tell()

        # inputs
        fd.write(ser_compact_size(self.num_inputs))
        for in_idx, txi in self.input_iter():
            inp = self.inputs[in_idx]

            # first check - if no signature(s) - fail soon
            if inp.is_multisig:
                assert self.multi_input_complete(inp), 'Incomplete signature set on input #%d' % in_idx
            else:
                # single signature
                ssig = self.singlesig_signature(inp)
                assert ssig, 'No signature on input #%d' % in_idx

            if inp.is_segwit:
                if inp.is_multisig:
                    if inp.redeem_script:
                        # p2sh-p2wsh
                        txi.scriptSig = ser_string(self.get(inp.redeem_script))

                elif inp.is_p2sh:
                    # singlesig (p2sh) segwit still requires the script here.
                    txi.scriptSig = ser_string(inp.scriptSig)
                else:
                    # major win for segwit (p2pkh): no redeem script bloat anymore
                    txi.scriptSig = b''

                # Actual signature will be in witness data area

            else:
                # insert the new signature(s), assuming fully signed txn.
                if inp.is_multisig:
                    # p2sh multisig (non-segwit)
                    sigs = self.multisig_signatures(inp)
                    ss = b"\x00"
                    for sig in sigs:
                        ss += ser_push_data(sig)
                    ss += ser_push_data(self.get(inp.redeem_script))
                    txi.scriptSig = ss

                else:
                    pubkey, der_sig = ssig
                    txi.scriptSig = ser_push_data(der_sig) + ser_push_data(pubkey)

            fd.write(txi.serialize())

        # outputs
        fd.write(ser_compact_size(self.num_outputs))
        for out_idx, txo in self.output_iter():
            fd.write(txo.serialize())

            # capture change output amounts (if segwit)
            if self.outputs[out_idx].is_change and self.outputs[out_idx].witness_script:
                history.add_segwit_utxos(out_idx, txo.nValue)

        body_end = fd.tell()

        if needs_witness:
            # witness values
            # - preserve any given ones, add ours
            for in_idx, wit in self.input_witness_iter():
                inp = self.inputs[in_idx]

                if inp.is_segwit:
                    # put in new sig: wit is a CTxInWitness
                    assert not wit.scriptWitness.stack, 'replacing non-empty?'
                    if inp.is_multisig:
                        sigs = self.multisig_signatures(inp)
                        wit.scriptWitness.stack = [b""] + sigs + [self.get(inp.witness_script)]
                    else:
                        pubkey, der_sig = self.singlesig_signature(inp)
                        assert pubkey[0] in {0x02, 0x03} and len(pubkey) == 33, "bad v0 pubkey"
                        wit.scriptWitness.stack = [der_sig, pubkey]

                fd.write(wit.serialize())

        # locktime
        fd.write(pack('<I', self.lock_time))

        # calc transaction ID
        if not needs_witness:
            # easy w/o witness data
            txid = ngu.hash.sha256s(fd.checksum.digest())
        else:
            # legacy cost here for segwit: re-read what we just wrote
            txid = calc_txid(fd, (0, fd.tell()), (body_start, body_end-body_start))

        history.add_segwit_utxos_finalize(txid)

        return B2A(bytes(reversed(txid)))

# EOF
