# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# psbt.py - understand PSBT file format: verify and generate them
#
import stash, gc, history, sys, ngu, ckcc, version, chains
from ucollections import OrderedDict
from ustruct import unpack_from, unpack, pack
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, B2A, keypath_to_str, validate_derivation_path_length, problem_file_line
from utils import seconds2human_readable, datetime_from_timestamp, datetime_to_str
from uhashlib import sha256
from uio import BytesIO
from charcodes import KEY_ENTER
from sffile import SizerFile
from chains import taptweak, tapleaf_hash, NLOCK_IS_TIME, AF_TO_STR_AF
from wallet import MiniScriptWallet, TRUST_PSBT, TRUST_VERIFY
from exceptions import FatalPSBTIssue, FraudulentChangeOutput
from serializations import ser_compact_size, deser_compact_size, hash160
from serializations import CTxIn, CTxInWitness, CTxOut, ser_string, COutPoint
from serializations import ser_sig_der, uint256_from_str, ser_push_data
from serializations import SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE, SIGHASH_ANYONECANPAY
from serializations import ALL_SIGHASH_FLAGS, SIGHASH_DEFAULT
from opcodes import OP_CHECKMULTISIG, OP_RETURN
from glob import settings
from precomp_tag_hash import TAP_TWEAK_H, TAP_SIGHASH_H

from public_constants import (
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_XPUB, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT,
    PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_BIP32_DERIVATION, PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_KEY_SIG, PSBT_OUT_TAP_TREE,
    PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_SCRIPT_SIG,
    TAPROOT_LEAF_TAPSCRIPT, TAPROOT_LEAF_MASK,
    PSBT_OUT_SCRIPT, PSBT_OUT_AMOUNT, PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_OUTPUT_COUNT, PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_TX_VERSION, PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX, PSBT_IN_SEQUENCE, PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, MAX_SIGNERS,
    PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL, 
    PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE, PSBT_IN_SP_TWEAK,
    PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE,
    AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH, AF_P2TR, AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH,
    AFC_SEGWIT, AF_BARE_PK
)
from silentpayments import SilentPaymentMixin, compute_silent_payment_spending_privkey

psbt_tmp256 = bytearray(256)

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

def disassemble_multisig_mn(redeem_script):
    # pull out just M and N from script. Simple, faster, no memory.

    if not redeem_script or (redeem_script[-1] != OP_CHECKMULTISIG):
        return None, None

    M = redeem_script[0] - 80
    N = redeem_script[-2] - 80

    return M, N

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

            key_pos = fd.tell() + 1  # first element is ktype

            key = fd.read(ks)
            vs = deser_compact_size(fd)
            assert vs is not None, 'eof'

            kt = key[0]

            if kt in self.no_keys:
                assert len(key) == 1       # not expecting key

            # storing offset and length only! Mostly.
            if kt in self.short_values:
                actual = fd.read(vs)
                self.store(kt, bytes(key), actual)
            else:
                # skip actual data for now
                # TODO: could this be stored more compactly?
                proxy = (fd.tell(), vs)
                fd.seek(vs, 1)
                # store just coords for both key & val
                if kt == PSBT_PROPRIETARY:
                    ident, subtype, _ = decode_prop_key(key[1:])
                    # examine only Coinkite proprietary keys
                    if (ident == PSBT_PROP_CK_ID) and (subtype == PSBT_ATTESTATION_SUBTYPE):
                        # prop key for attestation does not have keydata because the
                        # value is a recoverable signature (already contains pubkey)
                        # just save what we can handle
                        self.attestation = proxy

                self.store(kt, (key_pos, ks-1), proxy)

    def coord_write(self, out_fd, val, ktype=None):
        pos, ll = val
        if ktype is None:
            out_fd.write(ser_compact_size(ll))
        else:
            out_fd.write(ser_compact_size(ll+1))
            out_fd.write(bytes([ktype]))

        self.fd.seek(pos)
        while ll:
            t = self.fd.read(min(64, ll))
            out_fd.write(t)
            ll -= len(t)

    def write(self, out_fd, ktype, val, key=b''):
        # serialize helper: write w/ size and key byte
        if isinstance(key, tuple):
            self.coord_write(out_fd, key, ktype)
        else:
            out_fd.write(ser_compact_size(1 + len(key)))
            out_fd.write(bytes([ktype]) + key)

        if isinstance(val, tuple):
            if ktype in (PSBT_IN_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_BIP32_DERIVATION):
                assert len(val) == 3
                val = val[:-1]  # ignore last element which is just (pos, len) of xfp+pth (after leaf hashes)
            self.coord_write(out_fd, val)
        else:
            out_fd.write(ser_compact_size(len(val)))
            out_fd.write(val)

    def get(self, val):
        # get the raw bytes for a value.
        ## Handle both in-memory values (bytes) and file coordinates (offset, length)
        if isinstance(val, (bytes, bytearray)):
            return val
        pos, ll = val
        self.fd.seek(pos)
        return self.fd.read(ll)

    def parse_xfp_path(self, coords):
        # coords are expected to be value from subpaths or taproot subpaths
        return list(unpack_from('<%dI' % (coords[1] // 4), self.get(coords)))

    def handle_zero_xfp(self, xfp_path, my_xfp, warnings=None):
        # Tricky & Useful: if xfp of zero is observed in file, assume that's a
        # placeholder for my XFP value. Replace on the fly. Great when master
        # XFP is unknown because PSBT built from derived XPUB only. Also privacy.
        if xfp_path[0] == 0:
            xfp_path[0] = my_xfp

            if warnings is not None:
                if not any(True for k, _ in warnings if 'XFP' in k):
                    warnings.append(('Zero XFP',
                                     'Assuming XFP of zero should be replaced by correct XFP'))
        return xfp_path

    def parse_taproot_subpaths(self, my_xfp, warnings, cosign_xfp=None):
        my_sp_idxs = []
        parsed_subpaths = OrderedDict()
        for i in range(len(self.taproot_subpaths)):
            key, val = self.taproot_subpaths[i]
            assert key[1] == 32  # "PSBT_IN_TAP_BIP32_DERIVATION xonly-pubkey length != 32"
            xonly_pk = self.get(key)
            pos, length = val
            end_pos = pos + length
            self.fd.seek(pos)
            leaf_hash_len = deser_compact_size(self.fd)
            if leaf_hash_len:
                self.fd.seek(32*leaf_hash_len, 1)
            else:
                self.ik_idx = i

            curr_pos = self.fd.tell()
            # this position is where actual xfp+path starts
            # save it for faster access
            to_read = end_pos - curr_pos
            self.taproot_subpaths[i] = (key, (val[0], val[1], (curr_pos, to_read)))
            # internal key is allowed to go from master
            # unspendable path can be just a bare xonly pubkey
            allow_master = True if not leaf_hash_len else False
            validate_derivation_path_length(to_read, allow_master=allow_master)
            v = self.fd.read(to_read)
            here = list(unpack_from('<%dI' % (to_read // 4), v))
            here = self.handle_zero_xfp(here, my_xfp, warnings)
            parsed_subpaths[xonly_pk] = [leaf_hash_len] + here
            if (here[0] == my_xfp) or (cosign_xfp and (here[0] == cosign_xfp)):
                my_sp_idxs.append(i)

        if my_sp_idxs:
            self.sp_idxs = my_sp_idxs

        return parsed_subpaths

    def parse_non_taproot_subpaths(self, my_xfp, warnings, cosign_xfp=None):
        parsed_subpaths = OrderedDict()
        my_sp_idxs = []
        for i, (key, val) in enumerate(self.subpaths):
            # len pubkey 33 + 1 byte PSBT keys specifier
            assert key[1] in {33, 65}, "hdpath pubkey len"
            pk = self.get(key)
            if len(pk) == 33:
                assert pk[0] in {0x02, 0x03}, "uncompressed pubkey"

            validate_derivation_path_length(val[1])
            # promote to a list of ints
            here = self.parse_xfp_path(val)
            here = self.handle_zero_xfp(here, my_xfp, warnings)

            parsed_subpaths[pk] = here
            if (here[0] == my_xfp) or (cosign_xfp and (here[0] == cosign_xfp)):
                my_sp_idxs.append(i)

            # else:
            # Address that isn't based on my seed; might be another leg in a p2sh,
            # or an input we're not supposed to be able to sign... and that's okay.

        if my_sp_idxs:
            self.sp_idxs = my_sp_idxs

        return parsed_subpaths

    def parse_subpaths(self, my_xfp, warnings, cosign_xfp=None):
        # - creates dictionary: pubkey => [xfp, *path] (self.subpaths)
        # - creates dictionary: pubkey => [leaf_hash_list, xfp, *path] (self.taproot_subpaths)
        if self.taproot_subpaths:
            return self.parse_taproot_subpaths(my_xfp, warnings, cosign_xfp)
        elif self.subpaths:
            return self.parse_non_taproot_subpaths(my_xfp, warnings, cosign_xfp)
        #return None in/output does not have any key-path info

# Track details of each output of PSBT
#
class psbtOutputProxy(psbtProxy):
    no_keys = { PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE }

    blank_flds = ('unknown', 'subpaths', 'redeem_script', 'witness_script', 'sp_idxs',
                  'is_change', 'amount', 'script', 'attestation', 'proprietary',
                  'taproot_internal_key', 'taproot_subpaths', 'taproot_tree', 'ik_idx',
                  'sp_v0_info', 'sp_v0_label',  # BIP-375 Silent Payments
                  )

    def __init__(self, fd, idx):
        super().__init__()

        # things we track
        #self.subpaths = None          # a dictionary if non-empty
        #self.taproot_subpaths = None  # a dictionary if non-empty
        #self.taproot_internal_key = None
        #self.taproot_tree = None
        #self.ik_idx = None   # index of taproot internal key in taproot_subpaths
        #self.redeem_script = None
        #self.witness_script = None
        #self.script = None
        #self.amount = None

        # this flag is set when we are assuming output will be change (same wallet)
        #self.is_change = False

        self.parse(fd)

    # not needed
    # def parse_taproot_tree(self):
    #     length = self.taproot_tree[1]
    #
    #     res = []
    #     while length:
    #         tree = BytesIO(self.get(self.taproot_tree))
    #         depth = tree.read(1)
    #         leaf_version = tree.read(1)[0]
    #         assert (leaf_version & ~TAPROOT_LEAF_MASK) == 0
    #         script_len, nb = deser_compact_size(tree, ret_num_bytes=True)
    #         script = tree.read(script_len)
    #         res.append((depth, leaf_version, script))
    #         length -= (2 + nb + script_len)
    #
    #     return res

    def store(self, kt, key, val):
        # do not forget that key[0] includes kt (type)
        if kt == PSBT_OUT_BIP32_DERIVATION:
            if not self.subpaths:
                self.subpaths = []
            self.subpaths.append((key,val))
        elif kt == PSBT_OUT_REDEEM_SCRIPT:
            self.redeem_script = val
        elif kt == PSBT_OUT_WITNESS_SCRIPT:
            self.witness_script = val
        elif kt == PSBT_OUT_SCRIPT:
            self.script = val
        elif kt == PSBT_OUT_AMOUNT:
            self.amount = val
        elif kt == PSBT_PROPRIETARY:
            self.proprietary = self.proprietary or []
            self.proprietary.append((key, val))
        elif kt == PSBT_OUT_TAP_INTERNAL_KEY:
            self.taproot_internal_key = val
        elif kt == PSBT_OUT_TAP_BIP32_DERIVATION:
            self.taproot_subpaths = self.taproot_subpaths or []
            self.taproot_subpaths.append((key, val))
        elif kt == PSBT_OUT_TAP_TREE:
            self.taproot_tree = val
        elif kt == PSBT_OUT_SP_V0_INFO:
            # BIP-375: Silent payment address (scan_key + spend_key)
            # val contains 66 bytes: scan_key (33) + spend_key (33)
            self.sp_v0_info = val
        elif kt == PSBT_OUT_SP_V0_LABEL:
            # BIP-375: Optional label for silent payment output
            # val contains 4-byte little-endian integer
            self.sp_v0_label = val
        else:
            self.unknown = self.unknown or []
            pos, length = key
            self.unknown.append(((pos-1, length+1), val))

    def serialize(self, out_fd, is_v2):

        wr = lambda *a: self.write(out_fd, *a)

        if self.subpaths:
            for k, v in self.subpaths:
                wr(PSBT_OUT_BIP32_DERIVATION, v, k)

        if self.redeem_script:
            wr(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            wr(PSBT_OUT_WITNESS_SCRIPT, self.witness_script)

        if self.taproot_internal_key:
            wr(PSBT_OUT_TAP_INTERNAL_KEY, self.taproot_internal_key)

        if self.taproot_subpaths:
            for k, v in self.taproot_subpaths:
                wr(PSBT_OUT_TAP_BIP32_DERIVATION, v, k)

        if self.taproot_tree:
            wr(PSBT_OUT_TAP_TREE, self.taproot_tree)

        if is_v2:
            wr(PSBT_OUT_SCRIPT, self.script)
            wr(PSBT_OUT_AMOUNT, self.amount)

        # BIP-375 Silent Payment fields
        if self.sp_v0_info:
            wr(PSBT_OUT_SP_V0_INFO, self.sp_v0_info)
        
        if self.sp_v0_label:
            wr(PSBT_OUT_SP_V0_LABEL, self.sp_v0_label)

        if self.proprietary:
            for k, v in self.proprietary:
                wr(PSBT_PROPRIETARY, v, k)

        if self.unknown:
            for k, v in self.unknown:
                wr(None, v, k)


    def determine_my_change(self, out_idx, txo, parsed_subpaths, parent):
        # Do things make sense for this output?
    
        # NOTE: We might think it's a change output just because the PSBT
        # creator has given us a key path. However, we must be **very** 
        # careful and fully validate all the details.
        # - no output info is needed, in general, so
        #   any output info provided better be right, or fail as "fraud"
        # - full key derivation and validation is done during signing, and critical.
        # - we raise fraud alarms, since these are not innocent errors

        # - must match expected address for this output, coming from unsigned txn
        af, addr_or_pubkey = txo.get_address()

        if (not self.sp_idxs) or (af in [OP_RETURN, None]):
            # num_ours == 0
            # - not considered fraud because other signers looking at PSBT may have them
            # - user will see them as normal outputs, which they are from our PoV.
            # OP_RETURN
            # - nothing we can do with anchor outputs
            # UNKNOWN
            # - scripts that we do not understand
            return af

        msc = parent.active_miniscript
        if msc and MiniScriptWallet.disable_checks:
            # Without validation, we have to assume all outputs
            # will be taken from us, and are not really change.
            return af

        # certain short-cuts
        if msc:
            if af in [AF_CLASSIC, AF_P2WPKH, AF_BARE_PK]:
                # signing with miniscript wallet - single sig outputs definitely not change
                return af

        elif parent.active_singlesig and (af == AF_P2WSH):
            # we are signing single sig inputs - p2wsh is def not a change
            return af

        def fraud(idx, af, err=""):
            raise FraudulentChangeOutput(idx, "%s change output is fraudulent\n\n%s" % (
                AF_TO_STR_AF[af], err
            ))

        if af == AF_BARE_PK:
            # output is compressed public key (not a hash, much less common)
            # uncompressed public keys not supported!
            assert len(addr_or_pubkey) == 33
            assert len(parsed_subpaths) == 1
            target, = parsed_subpaths.keys()

        elif af in (AF_CLASSIC, AF_P2WPKH):
            # P2PKH & P2WPKH (public key has, whether witness v0 or legacy)
            # input is hash160 of a single public key
            assert len(addr_or_pubkey) == 20
            assert len(parsed_subpaths) == 1
            target, = parsed_subpaths.keys()
            target = hash160(target)

        elif af in (AF_P2SH, AF_P2WSH):  # both p2sh & p2wsh covered here
            if msc:
                # scriptPubkey can be compared against script that we build
                # if exact match change if not - not change
                # no need for redeem/witness script
                # for instance liana & core do not provide witness/redeem
                try:
                    xfp_paths = list(parsed_subpaths.values())
                    # if subpaths do not match, it is not desired wallet - so no change
                    # but also not a fraud
                    if msc.matching_subpaths(xfp_paths):
                        msc.validate_script_pubkey(txo.scriptPubKey, xfp_paths)
                        self.is_change = True
                except AssertionError as e:
                    # sys.print_exception(e)
                    fraud(out_idx, af, e)
                return af

            # we do not have active miniscript - must be single sig otherwise, not a change
            if len(parsed_subpaths) == 1 and (af == AF_P2SH):
                expect_pubkey, = parsed_subpaths.keys()
                target_spk, _ = chains.current_chain().script_pubkey(AF_P2WPKH_P2SH,
                                                                     pubkey=expect_pubkey)
                af = AF_P2WPKH_P2SH
                if txo.scriptPubKey != target_spk:
                    fraud(out_idx, af, "spk mismatch")
                # it's actually segwit p2wpkh inside p2sh
                target = target_spk[2:-1]
            else:
                # done, not a change, subpaths > 1 or p2wsh (and not active miniscript)
                return af

        elif af == AF_P2TR:
            if msc:
                try:
                    xfp_paths = [v[1:] for v in parsed_subpaths.values() if len(v[1:]) > 1]
                    if msc.matching_subpaths(xfp_paths):
                        msc.validate_script_pubkey(txo.scriptPubKey, xfp_paths)
                        self.is_change = True
                except AssertionError as e:
                    fraud(out_idx, af, e)
                return af

            if len(parsed_subpaths) == 1:
                expect_pubkey, = parsed_subpaths.keys()
                target = taptweak(expect_pubkey)
            else:
                # done, not a change, subpaths > 1 (and not active miniscript)
                return af

        # only basic single signature, non-miniscript scripts get here
        assert parent.active_singlesig
        if addr_or_pubkey != target:
            fraud(out_idx, af)

        # We will check pubkey value at the last second, during signing.
        self.is_change = True
        return af


# Track details of each input of PSBT
#
class psbtInputProxy(psbtProxy):

    # just need to store a simple number for these
    short_values = { PSBT_IN_SIGHASH_TYPE }

    # only part-sigs have a key to be stored.
    no_keys = {PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE,
               PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_FINAL_SCRIPTSIG,
               PSBT_IN_FINAL_SCRIPTWITNESS,PSBT_IN_TAP_KEY_SIG,
               PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_MERKLE_ROOT}

    blank_flds = (
        'unknown', 'witness_utxo', 'sighash', 'redeem_script', 'witness_script', 'sp_idxs',
        'fully_signed', 'af', 'is_miniscript', "subpaths", 'utxo', 'utxo_spk',
        'amount', 'previous_txid', 'part_sigs', 'added_sigs',  'prevout_idx', 'sequence',
        'req_time_locktime', 'req_height_locktime',
        'taproot_merkle_root', 'taproot_script_sigs', 'taproot_scripts', 'use_keypath',
        'taproot_subpaths', 'taproot_internal_key', 'taproot_key_sig', 'tr_added_sigs',
        'ik_idx',
        'sp_ecdh_shares', 'sp_dleq_proofs', 'sp_tweak' # BIP-375 Silent Payments
    )

    def __init__(self, fd, idx):
        super().__init__()

        #self.utxo = None
        #self.witness_utxo = None
        #self.part_sigs = []
        #self.added_sigs = []  # signatures that we added (current siging session)
        #self.sighash = None
        #self.subpaths = []          # will be empty if taproot
        #self.redeem_script = None
        #self.witness_script = None

        # Non-zero if one or more of our signing keys involved in input
        #self.sp_idxs = list of indexes leading to our key in self.subpaths

        # things we've learned
        #self.fully_signed = False

        # we can't really learn this until we take apart the UTXO's scriptPubKey
        #self.af = None  # string representation of address format aka. script type

        #self.amount = None
        #self.utxo_spk = None             # scriptPubKey for input utxo

        # === will be empty if non-taproot ===
        # self.taproot_subpaths = {}
        # self.taproot_internal_key = None
        # self.taproot_key_sig = None
        # self.taproot_merkle_root = None
        # self.taproot_script_sigs = None
        # self.taproot_scripts = None
        # self.use_keypath = None   # signing taproot inputs that have script path with internal key
        # self.ik_idx = None   # index of taproot internal key in taproot_subpaths
        # ===

        #self.previous_txid = None
        #self.prevout_idx = None
        #self.sequence = None
        #self.req_time_locktime = None
        #self.req_height_locktime = None

        self.parse(fd)

    @property
    def is_segwit(self):
        return self.af & AFC_SEGWIT

    def get_taproot_script_sigs(self):
        # returns set of (xonly, script) provided via PSBT_IN_TAP_SCRIPT_SIG
        # we do not parse control blocks (k) not needed
        parsed_taproot_script_sigs = set()
        for k, v in self.taproot_script_sigs or []:
            key = self.get(k)
            xonly, script_hash = key[:32], key[32:]
            parsed_taproot_script_sigs.add((xonly, script_hash))

        return parsed_taproot_script_sigs

    def get_taproot_scripts(self):
        # returns set of scripts provided via PSBT_IN_TAP_LEAF_SCRIPT
        # we do not parse control blocks (k) not needed
        t_scr = {}
        for k, v in self.taproot_scripts or []:
            script = self.get(v)
            t_scr[script[:-1]] = script[-1]  # only script, and script version

        return t_scr

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

    def handle_none_sighash(self):
        if self.sighash is None:
            self.sighash = SIGHASH_DEFAULT if self.taproot_subpaths else SIGHASH_ALL

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

    def determine_my_signing_key(self, my_idx, addr_or_pubkey, my_xfp, psbt, parsed_subpaths, utxo):
        # See what it takes to sign this particular input
        # - type of script
        # - which pubkey needed
        # - also validates redeem_script when present
        merkle_root = redeem_script = None

        if self.af == OP_RETURN:
            return

        if self.af is None:
            # If this is reached, we do not understand the output well
            # enough to allow the user to authorize the spend, so fail hard.
            raise FatalPSBTIssue('Unhandled scriptPubKey: ' + b2a_hex(addr_or_pubkey).decode())

        if psbt.active_miniscript or psbt.active_singlesig:
            # we have already set one of these - sow we can use some short-cuts
            if psbt.active_miniscript and (self.af in (AF_CLASSIC, AF_P2WPKH, AF_BARE_PK)):
                # signing with miniscript wallet - ignore single sig utxos
                self.sp_idxs = None
                return
            elif psbt.active_singlesig and (self.af == AF_P2WSH):
                # we are signing single sig inputs - ignore p2wsh utxos
                self.sp_idxs = None
                return

        if self.af == AF_BARE_PK:
            # input is single compressed public key (less common)
            # uncompressed public keys not supported!
            assert len(addr_or_pubkey) == 33

            for i, pubkey in enumerate(parsed_subpaths):
                if pubkey == addr_or_pubkey:
                    assert i == self.sp_idxs[0]
                    break
            else:
                # pubkey provided is just wrong vs. UTXO
                raise FatalPSBTIssue('Input #%d: pubkey wrong' % my_idx)

        elif self.af in (AF_CLASSIC, AF_P2WPKH):
            # P2PKH & P2WPKH
            # input is hash160 of a single public key

            for i, pubkey in enumerate(parsed_subpaths):
                if hash160(pubkey) == addr_or_pubkey:
                    assert i == self.sp_idxs[0]
                    break
            else:
                # none of the pubkeys provided hashes to that address
                raise FatalPSBTIssue('Input #%d: pubkey vs. address wrong' % my_idx)

        elif self.af in (AF_P2WSH, AF_P2SH):
            # we must have the redeem script already (else fail)
            ks = self.witness_script or self.redeem_script
            if not ks:
                raise FatalPSBTIssue("Missing redeem/witness script for input #%d" % my_idx)

            redeem_script = self.get(ks)
            native_v0 = (self.af == AF_P2WSH)

            if not native_v0 and (len(redeem_script) == 22) and \
                    redeem_script[0] == 0 and redeem_script[1] == 20 and \
                    len(parsed_subpaths) == 1:

                for i, pubkey in enumerate(parsed_subpaths):
                    target_spk, _ = chains.current_chain().script_pubkey(AF_P2WPKH_P2SH,
                                                                         pubkey=pubkey)
                    if target_spk == utxo.scriptPubKey:
                        # it's actually segwit p2wpkh inside p2sh
                        self.af = AF_P2WPKH_P2SH
                        assert i == self.sp_idxs[0]

            else:
                # Assume we'll be signing with any key we know
                # - but if partial sig already in place, ignore that one
                self.is_miniscript = True
                # values will always be coords for both pubkey and signature at this point
                done_keys = set()
                if self.part_sigs:
                    done_keys = {self.get(k) for k,_ in self.part_sigs}

                for i, (pubkey, path) in enumerate(parsed_subpaths.items()):
                    if pubkey in done_keys:
                        # pubkey has already signed, so - do not sign again
                        if i in self.sp_idxs:
                            # remove from sp_idxs so we do not attempt to sign again
                            self.sp_idxs.remove(i)

                    elif path[0] == my_xfp:
                        # slight chance of dup xfps, so handle
                        assert i in self.sp_idxs

                if self.witness_script and (not native_v0) and (self.redeem_script[1] == 34):
                    # bugfix
                    self.af = AF_P2WSH_P2SH
                    assert self.redeem_script[1] == 34

                if self.af in (AF_P2WSH, AF_P2WSH_P2SH):
                    # for both P2WSH & P2SH-P2WSH
                    if not self.witness_script:
                        raise FatalPSBTIssue('Need witness script for input #%d' % my_idx)

        elif self.af == AF_P2TR:
            if len(parsed_subpaths) == 1:
                # keyspend without a script path
                assert self.taproot_merkle_root is None, "merkle_root should not be defined for simple keyspend"
                assert self.ik_idx is not None
                xonly_pubkey, lhs_path = list(parsed_subpaths.items())[0]
                lhs, path = lhs_path[0], lhs_path[1:]
                assert not lhs, "LeafHashes have to be empty for internal key"
                assert self.sp_idxs[0] == 0
                # Spending a silent payment output - validation deferred to signing
                if not self.sp_tweak:
                    assert taptweak(xonly_pubkey) == addr_or_pubkey
            else:
                # tapscript (is always miniscript wallet)
                self.is_miniscript = True

                if self.taproot_merkle_root is not None:
                    merkle_root = self.get(self.taproot_merkle_root)

                for i, (xonly_pubkey, lhs_path) in enumerate(parsed_subpaths.items()):
                    if i not in self.sp_idxs:
                        # # ignore keys that does not have correct xfp specified in PSBT
                        continue

                    lhs, path = lhs_path[0], lhs_path[1:]
                    assert path[0] == my_xfp
                    assert merkle_root is not None, "Merkle root not defined"
                    if self.ik_idx == i:
                        assert not lhs
                        output_key = taptweak(xonly_pubkey, merkle_root)
                        if output_key == addr_or_pubkey:
                            # if we find a possibility to spend keypath (internal_key) - we do keypath
                            # even though script path is available
                            self.sp_idxs = [i]
                            self.use_keypath = True
                            break  # done ignoring all other possibilities
                    else:
                        internal_key = self.get(self.taproot_internal_key)
                        output_pubkey = taptweak(internal_key, merkle_root)
                        if addr_or_pubkey == output_pubkey:
                            assert i in self.sp_idxs

        if self.is_miniscript:
            if not self.sp_idxs: return
            if psbt.active_singlesig:
                # if we already considered single signature inputs for signing
                # do not even consider to sign with miniscript wallet(s)
                # maybe we removed
                self.sp_idxs = None
                return  # required key is None

            if self.af == AF_P2TR:
                xfp_paths = [item[1:]
                             for item in parsed_subpaths.values()
                             if len(item[1:]) > 1]
            else:
                xfp_paths = list(parsed_subpaths.values())

            if psbt.active_miniscript:
                if not MiniScriptWallet.disable_checks:
                    if not psbt.active_miniscript.matching_subpaths(xfp_paths):
                        # not input from currently selected wallet
                        self.sp_idxs = None
                        return
            else:
                # if we do have actual script at hand, guess M/N for better matching
                # basic multisig matching
                M, N = disassemble_multisig_mn(redeem_script)
                wal = MiniScriptWallet.find_match(xfp_paths, self.af, M, N)
                if not wal:
                    # not an input from wallet that we have enrolled
                    self.sp_idxs = None
                    return

                psbt.active_miniscript = wal

            try:
                # contains PSBT merkle root verification (if taproot)
                if not MiniScriptWallet.disable_checks:
                    psbt.active_miniscript.validate_script_pubkey(self.utxo_spk,
                                                                  xfp_paths, merkle_root)
            except BaseException as e:
                # sys.print_exception(e)
                raise FatalPSBTIssue('Input #%d: %s\n\n' % (my_idx, e) + problem_file_line(e))

        else:
            # single signature utxo
            if psbt.active_miniscript:
                # complex wallet is active - so this is not for us to sign
                self.sp_idxs = None
                return

            psbt.active_singlesig = True

    def segwit_v0_scriptCode(self):
        # only v0 segwit
        # only needed for sighash
        assert self.is_segwit and (self.af != AF_P2TR)
        if self.af == AF_P2WPKH:
            return b'\x19\x76\xa9\x14' + self.utxo_spk[2:2+20] + b'\x88\xac'
        elif self.af == AF_P2WPKH_P2SH:
            return b'\x19\x76\xa9\x14' + self.get(self.redeem_script)[2:22] + b'\x88\xac'
        elif self.af in (AF_P2WSH, AF_P2WSH_P2SH):
            # "scriptCode is witnessScript preceeded by a
            #  compactSize integer for the size of witnessScript"
            return ser_string(self.get(self.witness_script))

    def get_scriptSig(self):
        if self.af in [AF_BARE_PK, AF_CLASSIC]:
            return self.utxo_spk
        elif self.af in (AF_P2SH, AF_P2WSH_P2SH, AF_P2WPKH_P2SH):
            return self.get(self.redeem_script)
        else:
            return b""

    def store(self, kt, key, val):
        # Capture what we are interested in.
        if kt == PSBT_IN_NON_WITNESS_UTXO:
            self.utxo = val
        elif kt == PSBT_IN_WITNESS_UTXO:
            self.witness_utxo = val
        elif kt == PSBT_IN_PARTIAL_SIG:
            # taproot inputs do not have part sigs
            # only populate the attribute if present
            if not self.part_sigs:
                self.part_sigs = []
            # do not load anything (both key and val are coordinates)
            # actual signatures (71 bytes) we do not need them until finalization
            # public keys are enough for validation we will get them as needed
            self.part_sigs.append((key, val))
        elif kt == PSBT_IN_BIP32_DERIVATION:
            if self.subpaths is None:
                self.subpaths = []
            self.subpaths.append((key, val))
        elif kt == PSBT_IN_REDEEM_SCRIPT:
            self.redeem_script = val
        elif kt == PSBT_IN_WITNESS_SCRIPT:
            self.witness_script = val
        elif kt == PSBT_IN_SIGHASH_TYPE:
            self.sighash = unpack('<I', val)[0]
        elif kt == PSBT_IN_TAP_INTERNAL_KEY:
            self.taproot_internal_key = val
        elif kt == PSBT_IN_TAP_BIP32_DERIVATION:
            if self.taproot_subpaths is None:
                self.taproot_subpaths = []
            self.taproot_subpaths.append((key, val))
        elif kt == PSBT_IN_TAP_KEY_SIG:
            self.taproot_key_sig = val
        elif kt == PSBT_IN_TAP_MERKLE_ROOT:
            self.taproot_merkle_root = val
        elif kt == PSBT_IN_TAP_SCRIPT_SIG:
            self.taproot_script_sigs = self.taproot_script_sigs or []
            self.taproot_script_sigs.append((key, val))
        elif kt == PSBT_IN_TAP_LEAF_SCRIPT:
            self.taproot_scripts = self.taproot_scripts or []
            self.taproot_scripts.append((key, val))
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
        elif kt == PSBT_IN_SP_ECDH_SHARE:
            # BIP-375: Per-input ECDH share
            # key contains scan_key (33 bytes), val contains ECDH share (33 bytes)
            if self.sp_ecdh_shares is None:
                self.sp_ecdh_shares = []
            self.sp_ecdh_shares.append((key, val))
        elif kt == PSBT_IN_SP_DLEQ:
            # BIP-375: Per-input DLEQ proof
            # key contains scan_key (33 bytes), val contains DLEQ proof (64 bytes)
            if self.sp_dleq_proofs is None:
                self.sp_dleq_proofs = []
            self.sp_dleq_proofs.append((key, val))
        elif kt == PSBT_IN_SP_TWEAK:
            self.sp_tweak = val
        else:
            # including: PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS
            self.unknown = self.unknown or []
            pos, length = key
            self.unknown.append(((pos - 1, length + 1), val))

    def serialize(self, out_fd, is_v2):
        # Output this input's values; might include signatures that weren't there before

        wr = lambda *a: self.write(out_fd, *a)

        if self.utxo:
            wr(PSBT_IN_NON_WITNESS_UTXO, self.utxo)
        if self.witness_utxo:
            wr(PSBT_IN_WITNESS_UTXO, self.witness_utxo)

        if self.part_sigs:
            for pk, sig in self.part_sigs:
                wr(PSBT_IN_PARTIAL_SIG, sig, pk)

        if self.added_sigs:
            for pk, sig in self.added_sigs:
                wr(PSBT_IN_PARTIAL_SIG, sig, pk)

        if self.taproot_key_sig:
            wr(PSBT_IN_TAP_KEY_SIG, self.taproot_key_sig)

        if self.sighash is not None:
            wr(PSBT_IN_SIGHASH_TYPE, pack('<I', self.sighash))

        if self.subpaths:
            for k, v in self.subpaths:
                wr(PSBT_IN_BIP32_DERIVATION, v, k)

        if self.redeem_script:
            wr(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            wr(PSBT_IN_WITNESS_SCRIPT, self.witness_script)

        if self.taproot_internal_key:
            wr(PSBT_IN_TAP_INTERNAL_KEY, self.taproot_internal_key)

        if self.taproot_subpaths:
            for k, v in self.taproot_subpaths:
                wr(PSBT_IN_TAP_BIP32_DERIVATION, v, k)

        if self.taproot_merkle_root:
            wr(PSBT_IN_TAP_MERKLE_ROOT, self.taproot_merkle_root)

        if self.taproot_script_sigs:
            for k, v in self.taproot_script_sigs:
                wr(PSBT_IN_TAP_SCRIPT_SIG, v, k)

        if self.tr_added_sigs:
            for (xonly, leaf_hash), sig in self.tr_added_sigs.items():
                wr(PSBT_IN_TAP_SCRIPT_SIG, sig, xonly + leaf_hash)

        if self.taproot_scripts:
            for k, v in self.taproot_scripts:
                wr(PSBT_IN_TAP_LEAF_SCRIPT, v, k)

        if is_v2:
            wr(PSBT_IN_PREVIOUS_TXID, self.previous_txid)

            wr(PSBT_IN_OUTPUT_INDEX, self.prevout_idx)

            if self.sequence is not None:
                wr(PSBT_IN_SEQUENCE, pack("<I", self.sequence))

            if self.req_time_locktime is not None:
                wr(PSBT_IN_REQUIRED_TIME_LOCKTIME, pack("<I", self.req_time_locktime))

            if self.req_height_locktime is not None:
                wr(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, pack("<I", self.req_height_locktime))

        # BIP-375 Silent Payment fields
        if self.sp_ecdh_shares:
            for k, v in self.sp_ecdh_shares:
                wr(PSBT_IN_SP_ECDH_SHARE, v, k)
        
        if self.sp_dleq_proofs:
            for k, v in self.sp_dleq_proofs:
                wr(PSBT_IN_SP_DLEQ, v, k)
        
        if self.sp_tweak:
            wr(PSBT_IN_SP_TWEAK, self.sp_tweak)

        if self.unknown:
            for k, v in self.unknown:
                wr(None, v, k)


class psbtObject(psbtProxy, SilentPaymentMixin):
    "Just? parse and store"
    short_values = { PSBT_GLOBAL_TX_MODIFIABLE }
    no_keys = { PSBT_GLOBAL_UNSIGNED_TX }
    blank_flds = ("hashPrevouts", "hashSequence", "hashOutputs", "hashValues", "hashScriptPubKeys",
                  "my_tr_in", "unknown")

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
        # will be tru if number of change outputs equals to total number of outputs
        self.consolidation_tx = False
        # number of change outputs
        self.num_change_outputs = None
        self.total_change_value = None

        # when signing segwit stuff, there is some re-use of hashes
        # only if SIGHASH_ALL
        # self.hashPrevouts = None
        # self.hashSequence = None
        # self.hashOutputs = None
        # segwit v1
        # self.hashValues = None
        # self.hashScriptPubKeys = None
        # self.my_tr_in = None  # set to true if any taproot input is ours to sign

        # this points to a Miniscript wallet, during operation
        # - we are only supporting a single miniscript wallet during signing
        self.active_miniscript = None
        # - if we plan to sign signle signature inputs
        self.active_singlesig = None

        self.warnings = []
        # not a warning just more info about tx
        # presented in UX on confirm tx screen before warnings
        self.ux_notes = []

        # v1 vs v2 validation
        self.is_v2 = False
        self.has_gic = False  # global input count
        self.has_goc = False  # global output count
        self.has_gtv = False  # global txn version
        
        # BIP-375 Silent Payments: Global ECDH shares and DLEQ proofs
        # Used when single signer owns all inputs
        self.sp_global_ecdh_shares = None  # List of (scan_key, ecdh_share) tuples
        self.sp_global_dleq_proofs = None  # List of (scan_key, dleq_proof) tuples

    @property
    def lock_time(self):
        return (self._lock_time or self.fallback_locktime) or 0

    def store(self, kt, key, val):
        # capture the values we care about

        if kt == PSBT_GLOBAL_UNSIGNED_TX:
            self.txn = val
        elif kt == PSBT_GLOBAL_XPUB:
            # list of tuples(xfp_path, xpub)
            self.xpubs.append((key, val))
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
            self.txn_modifiable = self.get(val)[0]
        elif kt == PSBT_GLOBAL_SP_ECDH_SHARE:
            # BIP-375: Global ECDH share
            # key contains scan_key (33 bytes), val contains ECDH share (33 bytes)
            if self.sp_global_ecdh_shares is None:
                self.sp_global_ecdh_shares = []
            self.sp_global_ecdh_shares.append((key, val))
        elif kt == PSBT_GLOBAL_SP_DLEQ:
            # BIP-375: Global DLEQ proof
            # key contains scan_key (33 bytes), val contains DLEQ proof (64 bytes)
            if self.sp_global_dleq_proofs is None:
                self.sp_global_dleq_proofs = []
            self.sp_global_dleq_proofs.append((key, val))
        else:
            self.unknown = self.unknown or []
            pos, length = key
            self.unknown.append(((pos - 1, length + 1), val))

    def output_iter(self, start=0, stop=None):
        # yield the txn's outputs: index, (CTxOut object) for each
        if stop is None:
            stop = self.num_outputs

        total_out = 0
        if self.is_v2:
            for idx in range(start, stop):
                out = self.outputs[idx]
                amount = unpack("<q", self.get(out.amount))[0]
                tx_out = CTxOut(nValue=amount, scriptPubKey=self.get(out.script))
                total_out += amount
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

                total_out += tx_out.nValue

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

        assert self.txn_version in {1,2}, "bad txn version"

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
        for idx, inp in self.input_iter():
            i = self.inputs[idx]
            ks = i.witness_script or i.redeem_script
            if not ks: continue

            rs = i.get(ks)
            if rs[-1] != OP_CHECKMULTISIG: continue

            if not i.subpaths: continue  # not ours

            for _, val in i.subpaths:
                if self.my_xfp == self.parse_xfp_path(val)[0]:
                    break
            else:
                # does not contain our key (master xfp) in subpaths
                continue

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

        # not multisig, probably
        return None, None, None

    async def handle_xpubs(self):
        # Lookup correct wallet based on xpubs in globals
        # - only happens if they volunteered this 'extra' data
        # - do not assume multisig
        assert not self.active_miniscript

        has_mine = 0
        parsed_xpubs = []
        for k,v in self.xpubs:
            xp = self.get(k)
            h = self.parse_xfp_path(v)
            assert len(h) >= 1
            parsed_xpubs.append((xp, h))

            if h[0] == self.my_xfp:
                has_mine += 1

        if not has_mine:
            raise FatalPSBTIssue('My XFP not involved')

        # don't want to guess M if not needed, but we need it
        af, M, N = self.guess_M_of_N()
        if not N:
            # not multisig, but we can still verify:
            # - miniscript cannot be imported from PSBT (we lack descriptor in PSBT)
            # - XFP should be one of ours (checked above).
            # - too slow to re-derive it here, so nothing more to validate at this point
            return

        assert N == len(self.xpubs)

        # Validate good match here. The xpubs must be exactly right, but
        # we're going to use our own values from setup time anyway and not trusting
        # new values without user interaction.
        # Check:
        # - chain codes match what we have stored already
        # - pubkey vs. path will be checked later
        # - xfp+path already checked above when selecting wallet
        # Any issue here is a fraud attempt in some way, not innocent.
        wal = MiniScriptWallet.find_match([i[1] for i in parsed_xpubs], af, M, N)

        if wal:
            # exact match (by xfp+deriv set) .. normal case
            self.active_miniscript = wal
            # now proper check should follow - matching actual master pubkeys
            # but is it needed?, we just matched the wallet
            # and are going to use our own data for verification anyway
            if not self.active_miniscript.disable_checks:
                self.active_miniscript.validate_psbt_xpubs(parsed_xpubs)

        else:
            trust_mode = MiniScriptWallet.get_trust_policy()
            # already checked for existing import and wasn't found, so fail
            if trust_mode == TRUST_VERIFY:
                raise FatalPSBTIssue("XPUBs in PSBT do not match any existing wallet")

            # Maybe create wallet, for today, forever, or fail, etc.
            proposed = MiniScriptWallet.import_from_psbt(af, M, N, parsed_xpubs)
            if trust_mode != TRUST_PSBT:
                # do a complex UX sequence, which lets them save new wallet
                from glob import hsm_active
                if hsm_active:
                    raise FatalPSBTIssue("MS enroll not allowed in HSM mode")

                approved = await proposed.confirm_import()
                if not approved:
                    raise FatalPSBTIssue("Refused to import new wallet")

            self.active_miniscript = proposed

        # must have wallet at this point
        assert self.active_miniscript

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

    def validate_unkonwn(self, obj, label):
        # find duplicate unknown values in different PSBT parts
        if not obj.unknown:
            return

        if len({self.get(k) for k,_ in obj.unknown}) < len(obj.unknown):
            raise FatalPSBTIssue("Duplicate key. Key for unknown value"
                                 " already provided in %s." % label)

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

        assert len(self.inputs) == self.num_inputs, 'ni mismatch'

        assert self.num_outputs >= 1, 'need outputs'

        self.validate_unkonwn(self, "global namespace")

        inp_have_subpath = False
        for i in self.inputs:
            if i.subpaths or i.taproot_subpaths:
                inp_have_subpath = True

            if self.is_v2:
                # v2 requires inclusion
                assert i.prevout_idx is not None
                assert i.previous_txid
                if i.req_time_locktime is not None:
                    assert i.req_time_locktime >= NLOCK_IS_TIME
                if i.req_height_locktime is not None:
                    assert 0 < i.req_height_locktime < NLOCK_IS_TIME
            else:
                # v0 requires exclusion
                assert i.prevout_idx is None
                assert i.previous_txid is None
                assert i.sequence is None
                assert i.req_time_locktime is None
                assert i.req_height_locktime is None

            if i.witness_script:
                assert i.witness_script[1] >= 30
            if i.redeem_script:
                assert i.redeem_script[1] >= 22

            if i.taproot_internal_key:
                assert i.taproot_internal_key[1] == 32  # "PSBT_IN_TAP_INTERNAL_KEY length != 32"

            if i.taproot_key_sig:
                # "PSBT_IN_TAP_KEY_SIG length != 64 or 65"
                assert i.taproot_key_sig[1] in (64, 65)

            if i.part_sigs:
                for k, v in i.part_sigs:
                    assert k[1] == 33
                    # valid signature can also be 60 bytes or less (needs grinding)
                    # 69 bytes - where both r & s are 31 bytes
                    # 73 -> high-s & high-r
                    assert v[1] <= 73, "DER sig len"

            if i.taproot_script_sigs:
                for k, v in i.taproot_script_sigs:
                    # PSBT_IN_TAP_SCRIPT_SIG + 32 bytes xonly pubkey + leafhash 32 bytes
                    assert k[1] == 64
                    # The 64 or 65 byte Schnorr signature for this pubkey and leaf combination
                    assert v[1] in (64, 65)

            if i.taproot_scripts:
                for k, v in i.taproot_scripts:
                    assert k[1] > 32  # "PSBT_IN_TAP_LEAF_SCRIPT control block is too short"
                    assert (k[1] - 1) % 32 == 0  # "PSBT_IN_TAP_LEAF_SCRIPT control block is not valid"
                    assert v[1] != 0  # "PSBT_IN_TAP_LEAF_SCRIPT cannot be empty"

            if i.sighash and (i.sighash not in ALL_SIGHASH_FLAGS):
                raise FatalPSBTIssue("Unsupported sighash flag 0x%x" % i.sighash)

            self.validate_unkonwn(i, "input")

        for o in self.outputs:
            if self.is_v2:
                # v2 requires inclusion
                assert o.amount
                # BIP-375: Silent payment outputs don't have scripts until ECDH computation
                # Scripts are derived during signing after ECDH shares are computed
                if o.sp_v0_info:
                    o.script = o.sp_v0_info
                else:
                    assert o.script, "PSBTv2 output missing script (not a silent payment)"
            else:
                # v0 requires exclusion
                assert o.amount is None
                assert o.script is None

            if o.taproot_internal_key:
                assert o.taproot_internal_key[1] == 32  # "PSBT_OUT_TAP_INTERNAL_KEY length != 32"

            self.validate_unkonwn(o, "output")

        if not inp_have_subpath:
            # Can happen w/ Electrum in watch-mode on XPUB. It doesn't know XFP and
            # so doesn't insert that into PSBT.
            # or PSBT provider forgot to include subpaths
            raise FatalPSBTIssue('PSBT inputs do not contain any key path information.')

        # if multisig xpub details provided, they better be right and/or offer import
        if self.xpubs:
            await self.handle_xpubs()

        if DEBUG:
            print("PSBT: %d inputs, %d output" % (self.num_inputs, self.num_outputs))

    def consider_outputs(self, len_pths, hard_p, prefix_pths, idx_max, cosign_xfp=None):
        from glob import dis
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

        validate_inp_pths = False
        path_len = None
        max_gap = idx_max + 200

        # We aren't seeing shared input path lengths.
        # They are probably doing weird stuff, so leave them alone
        # and do not validate against inputs paths
        if len(len_pths) == 1:
            path_len = 0
            for pl in len_pths:
                path_len = pl
                break
            if path_len > 2:
                validate_inp_pths = True

        dis.fullscreen("Validating...", line2="Outputs")

        for idx, txo in self.output_iter():
            dis.progress_sofar(idx, self.num_outputs)
            output = self.outputs[idx]

            parsed_subpaths = output.parse_subpaths(self.my_xfp, self.warnings, cosign_xfp)

            # perform output validation
            af = output.determine_my_change(idx, txo, parsed_subpaths, self)
            assert txo.nValue >= 0, "negative output value: o%d" % idx
            total_out += txo.nValue

            if (txo.nValue == 0) and (af != OP_RETURN):
                # OP_RETURN outputs have nValue=0 standard
                zero_val_outs += 1

            if output.is_change:
                self.num_change_outputs += 1
                total_change += txo.nValue

                if validate_inp_pths:
                    # Enforce some policy on change outputs:
                    # - need to "look like" they are going to same wallet as inputs came from
                    # - range limit last two path components (numerically)
                    # - same pattern of hard/not hardened components
                    # - MAX_PATH_DEPTH already enforced before this point
                    # - (single-sig only) check ther is only 0,1 at change index
                    is_cmplx = (len(parsed_subpaths) > 1)
                    for i, xpath in enumerate(parsed_subpaths.values()):
                        if i not in output.sp_idxs: continue
                        p = xpath[2:] if output.taproot_subpaths else xpath[1:]

                        iss = None
                        if len(p) != path_len:
                            iss = "has wrong path length (%d not %d)" % (len(p), path_len)
                        elif tuple(bool(i & 0x80000000) for i in p) not in hard_p:
                            iss = "has different hardening pattern"
                        elif tuple(p[:-2]) not in prefix_pths:
                            iss = "goes to diff path prefix"
                        elif not is_cmplx and ((p[-2] & 0x7fffffff) not in {0,1}):
                            iss = "2nd last component not 0 or 1"
                        elif (p[-1] & 0x7fffffff) > max_gap:
                            iss = "last component beyond reasonable gap"

                        if iss:
                            msg = "Output#%d: %s: %s" % (idx, iss, keypath_to_str(p, skip=0))
                            if len(hard_p) == 1 and len(prefix_pths) == 1:
                                # message can be more verbose
                                # fastest way to get first element from the set
                                # without modifying the set is for-loop
                                for hp in hard_p:
                                    break
                                for pp in prefix_pths:
                                    break
                                msg += " not %s/{0~1}%s/{0~%d}%s expected" % (
                                    keypath_to_str(pp, skip=0),
                                    "'" if hp[-2] else "",
                                    max_gap,
                                    "'" if hp[-1] else ""
                                )
                            self.warnings.append(('Troublesome Change Outs', msg))

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
        dis.progress_bar_show(1)

        if DEBUG:
            print("PSBT change outputs: %d out of %d" % (
                self.num_change_outputs, len(self.outputs)
            ))

    def consider_inputs(self, cosign_xfp=None):
        # Look at the UTXO's that we are spending. Do we have them? Do the
        # hashes match, and what values are we getting?
        # Important: parse incoming UTXO to build total input value
        # check nSequences & nLockTime and warn about TX level locktimes
        from glob import dis

        foreign = []
        total_in = 0
        presigned_inputs = set()
        # time based relative locks
        tb_rel_locks = []
        # block height based relative locks
        bb_rel_locks = []
        smallest_nsequence = 0xffffffff

        # collect some input path data from subapths
        # later used for change outputs path validation
        length_p = set()
        hard_pattern = set()
        prefix_p = set()
        idx_max = 0
        my_cnt = 0

        dis.fullscreen("Validating...", line2="Inputs")

        for i, txi in self.input_iter():
            dis.progress_sofar(i, self.num_inputs)
            inp = self.inputs[i]

            if inp.part_sigs:
                # How complete is the set of signatures so far?
                # - assuming PSBT creator doesn't give us extra data not required
                # - seems harmless if they fool us into thinking already signed; we do nothing
                # - could also look at pubkey needed vs. sig provided
                # - could consider structure of MofN in p2sh cases
                if len(inp.part_sigs) >= len(inp.subpaths):
                    inp.fully_signed = True

            if inp.taproot_key_sig:
                inp.fully_signed = True

            if inp.utxo:
                # Important: they might be trying to trick us with an un-related
                # funding transaction (UTXO) that does not match the input signature we're making
                # (but if it's segwit, the ploy wouldn't work, Segwit FtW)
                # - challenge: it's a straight dsha256() for old serializations, but not for newer
                #   segwit txn's... plus I don't want to deserialize it here.
                try:
                    observed = uint256_from_str(calc_txid(self.fd, inp.utxo))
                except:
                    raise AssertionError("Trouble parsing UTXO given for input #%d" % i)

                assert txi.prevout.hash == observed, "utxo hash mismatch for input #%d" % i

            if self.txn_version >= 2:
                has_rtl = inp.has_relative_timelock(txi)
                if has_rtl:
                    if has_rtl[0]:
                        tb_rel_locks.append((i, has_rtl[1]))
                    else:
                        bb_rel_locks.append((i, has_rtl[1]))

            if txi.nSequence < smallest_nsequence:
                smallest_nsequence = txi.nSequence

            parsed_subpaths = inp.parse_subpaths(self.my_xfp, self.warnings, cosign_xfp)

            if not inp.has_utxo():
                if inp.sp_idxs and not inp.fully_signed:
                    # we cannot proceed if the input is ours and there is no UTXO
                    raise FatalPSBTIssue('Missing own UTXO(s). Cannot determine value being signed')

                # input clearly not ours
                foreign.append(i)
                continue

            # pull out just the CTXOut object
            # very expensive for non-witness utxo (whole tx)
            # less expensive for witness UTXO (just necessary TxOut)
            #
            utxo = inp.get_utxo(txi.prevout.n)
            inp.amount = utxo.nValue
            assert inp.amount >= 0, "negative input value: i%d" % i
            total_in += inp.amount

            inp.af, addr_or_pubkey = utxo.get_address()
            # save scriptPubKey of utxo for later use
            # needed for P2WPKH scriptCode calculation
            # needed for P2PK & P2PKH scriptSig (when finalizing)
            # needed for each input if we sign at least one P2TR input
            inp.utxo_spk = utxo.scriptPubKey

            if inp.sp_idxs:
                my_cnt += 1
            if inp.fully_signed:
                presigned_inputs.add(i)
            if inp.sp_idxs and (not inp.fully_signed):
                # Look at what kind of input this will be, and therefore what
                # type of signing will be required, and which key we need.
                # - also validates redeem_script when present
                # - also finds appropriate miniscript wallet to be used
                inp.determine_my_signing_key(i, addr_or_pubkey, self.my_xfp, self,
                                             parsed_subpaths, utxo)

                # determine_my_signing_key may have removed sp_idxs
                # meaning we're not going to sign this input - other wallet in use
                if not inp.sp_idxs:
                    continue

                # parsed subpaths are OrderedDict - matches sp_idxs
                for ii, xpath in enumerate(parsed_subpaths.values()):
                    if ii not in inp.sp_idxs: continue
                    p = xpath[2:] if inp.taproot_subpaths else xpath[1:]
                    length_p.add(len(p))  # ignore xfp
                    hard_pattern.add(tuple(bool(i & 0x80000000) for i in p))
                    prefix_p.add(tuple(p[:-2]))

                    index = p[-1] & 0x7fffffff
                    if index > idx_max:
                        idx_max = index

                # iff to UTXO is segwit, then check it's value, and also
                # capture that value, since it's supposed to be immutable
                if inp.af and inp.is_segwit:
                    history.verify_amount(txi.prevout, inp.amount, i)

                if inp.af == AF_P2TR:
                    # based on this we know whether we can drop inp.utxo_xpk
                    # attribute after creating sighash
                    self.my_tr_in = True

        if not my_cnt:
            raise FatalPSBTIssue('None of the keys involved in this transaction '
                                 'belong to this Coldcard (need %s).' % xfp2str(self.my_xfp))

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

        if len(presigned_inputs) == self.num_inputs:
            # Maybe wrong f cases? Maybe they want to add their
            # own signature, even tho N of M is satisfied?!
            raise FatalPSBTIssue('Transaction looks completely signed already?')

        # We should know pubkey required for each input now.
        # - but we may not be the signer for those inputs, which is fine.
        # - TODO: but what if not SIGHASH_ALL
        no_keys = set(
            n
            for n,inp in enumerate(self.inputs)
            if (not inp.sp_idxs) and (not inp.fully_signed)
        )
        # HWI blocker
        # if len(no_keys) == self.num_inputs:
        #     # nothing to sign for us
        #     raise FatalPSBTIssue("Nothing to sign here")

        if no_keys:
            # This is seen when you re-sign same signed file by accident (multisig)
            # - case of len(no_keys)==num_inputs is handled by consider_inputs
            self.warnings.append(('Limited Signing',
                "We are not signing these inputs, because we either don't know the key,"
                " inputs belong to different wallet, or we have already signed: " + seq_to_str(no_keys)))

        if presigned_inputs:
            # this isn't really even an issue for some complex usage cases
            self.warnings.append(('Partly Signed Already',
                'Some input(s) provided were already completely signed by other parties: ' +
                        seq_to_str(presigned_inputs)))

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

        if MiniScriptWallet.disable_checks:
            self.warnings.append(('Danger', 'Some miniscript checks are disabled.'))

        if DEBUG:
            print("PSBT inputs: %d inputs contain our key, %d fully-signed" % (
                my_cnt, len(presigned_inputs)))

        dis.progress_bar_show(1)

        # BIP-375: Validate Segwit version restrictions for silent payments
        # Silent payment outputs cannot be mixed with inputs spending Segwit v>1
        if self.has_silent_payment_outputs():
            for i, inp in enumerate(self.inputs):
                if not inp.utxo_spk:
                    continue
                
                # Determine Segwit version from scriptPubKey
                spk = inp.utxo_spk
                if len(spk) >= 2 and spk[0] >= 0x51 and spk[0] <= 0x60:
                    # Witness version is OP_N where N = version
                    witness_version = spk[0] - 0x50
                    
                    if witness_version > 1:
                        raise FatalPSBTIssue(
                            "BIP-375 violation: Input #%d spends Segwit v%d output. "
                            "Silent payment outputs cannot be mixed with Segwit v>1 inputs." %
                            (i, witness_version))

        # useful info from all our parsed paths - will be validated against change outputs
        return length_p, hard_pattern, prefix_p, idx_max


    def consider_dangerous_sighash(self):
        # Check sighash flags are legal, useful, and safe. Warn about
        # some risks if user has enabled special sighash values.
        # can only be run after consider_outputs is done
        sh_unusual = False
        none_sh = False
        for inp in self.inputs:
            if inp.sp_idxs and not inp.fully_signed:
                if inp.sighash:
                    if inp.sighash is not None:
                        if inp.sighash not in (SIGHASH_ALL, SIGHASH_DEFAULT):
                            sh_unusual = True

                        if inp.sighash in (SIGHASH_NONE, SIGHASH_NONE | SIGHASH_ANYONECANPAY):
                            none_sh = True

        if sh_unusual and not settings.get("sighshchk"):
            if self.consolidation_tx:
                # policy: all inputs must be sighash ALL in purely consolidation txn
                raise FatalPSBTIssue("Only sighash ALL/DEFAULT is allowed"
                                     " for pure consolidation transactions.")

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

    def calculate_fee(self):
        # what miner's reward is included in txn?
        if self.total_value_in is None:
            return None
        return self.total_value_in - self.total_value_out

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
            for k, v in self.xpubs:
                wr(PSBT_GLOBAL_XPUB, v, k)

        # BIP-375: Global Silent Payment fields
        if self.sp_global_ecdh_shares:
            for k, v in self.sp_global_ecdh_shares:
                wr(PSBT_GLOBAL_SP_ECDH_SHARE, v, k)
        
        if self.sp_global_dleq_proofs:
            for k, v in self.sp_global_dleq_proofs:
                wr(PSBT_GLOBAL_SP_DLEQ, v, k)

        if self.unknown:
            for k, v in self.unknown:
                wr(None, v, k)

        # sep between globals and inputs
        out_fd.write(b'\0')

        for idx, inp in enumerate(self.inputs):
            inp.serialize(out_fd, self.is_v2)
            out_fd.write(b'\0')

        for idx, outp in enumerate(self.outputs):
            outp.serialize(out_fd, self.is_v2)
            out_fd.write(b'\0')

    @staticmethod
    def check_pubkey_at_path(sv, subpath, target_pk, is_xonly=False):
        # derive actual pubkey from private
        skp = keypath_to_str(subpath)
        node = sv.derive_path(skp)

        # check the pubkey of this BIP-32 node
        our_pk = node.pubkey()
        if is_xonly:
            our_pk = our_pk[1:]
        if target_pk == our_pk:
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
                    for i in oup.sp_idxs:
                        # for multisig, will be N paths, and exactly one will
                        # be our key. For single-signer, should always be my XFP
                        # derive actual pubkey from private
                        if oup.taproot_subpaths:
                            pubk = oup.taproot_subpaths[i][0]
                            sp = oup.taproot_subpaths[i][1][2]
                            ss = len(oup.taproot_subpaths) == 1
                        else:
                            pubk = oup.subpaths[i][0]
                            sp = oup.subpaths[i][1]
                            ss = len(oup.subpaths) == 1

                        # xfp can be zero - substitute with self.my_xfp (not my_xfp as it can be CCC)
                        sp = self.handle_zero_xfp(self.parse_xfp_path(sp), self.my_xfp, None)
                        if sp[0] != my_xfp:
                            # this can happen with CCC, where we have sp_idxs set for both
                            # CCC key and main xfp
                            continue

                        if self.check_pubkey_at_path(sv, sp, self.get(pubk),
                                                     is_xonly=bool(oup.taproot_subpaths)):
                            good += 1
                            if ss:
                                OWNERSHIP.note_subpath_used(sp)

                    if not good:
                        raise FraudulentChangeOutput(out_idx, 
                              "Deception regarding change output. "
                              "BIP-32 path doesn't match actual address.")


            # BIP-375 Silent Payment Processing
            # Process silent payment outputs before signing inputs
            if self.has_silent_payment_outputs():
                ux_note = self.process_silent_payments_for_signing(sv, dis)
                self.ux_notes.append(ux_note)

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

                if not inp.sp_idxs:
                    # we don't know the key for this input
                    continue

                if inp.fully_signed:
                    # for multisig, it's possible I need to add another sig
                    # but in other cases, no more signatures are possible
                    continue

                inp.handle_none_sighash()
                # decide if it is appropriate to drop sighash from PSBT
                if inp.taproot_subpaths:
                    drop_sighash = (inp.sighash == SIGHASH_DEFAULT)
                else:
                    drop_sighash = (inp.sighash == SIGHASH_ALL)

                schnorrsig = False
                tr_sh = []
                to_sign = []
                if inp.is_miniscript:
                    for i in inp.sp_idxs:
                        # get node required
                        if inp.taproot_subpaths:
                            schnorrsig = True
                            pubk = inp.taproot_subpaths[i][0]
                            sp = inp.taproot_subpaths[i][1][2]
                        else:
                            pubk = inp.subpaths[i][0]
                            sp = inp.subpaths[i][1]

                        # xfp can be zero - substitute with self.my_xfp (not my_xfp as it can be CCC)
                        sp = self.handle_zero_xfp(self.parse_xfp_path(sp), self.my_xfp, None)
                        if sp[0] != my_xfp:
                            # this can happen with CCC, where we have sp_idxs set for both
                            # CCC key and main xfp
                            continue

                        which_key = self.get(pubk)
                        is_xonly = len(which_key) == 32

                        # expensive test, but works... and important
                        node = self.check_pubkey_at_path(sv, sp, which_key, is_xonly=is_xonly)

                        if not node:
                            continue

                        to_sign.append((node, pubk))
                        if is_xonly and not inp.use_keypath:
                            # get the script
                            inner_tr_sh = []
                            assert self.active_miniscript
                            xfp_paths = [self.handle_zero_xfp(self.parse_xfp_path(x[2]), self.my_xfp, None)
                                         for _, x in inp.taproot_subpaths]
                            der_d = self.active_miniscript.derive_desc(xfp_paths)

                            # mapping from script to leaf version
                            taproot_scripts = inp.get_taproot_scripts()
                            for leaf in der_d.tapscript.iter_leaves():
                                target_leaf = None
                                # always exact check/match the script, if we would generate such
                                scr = leaf.compile()
                                if scr not in taproot_scripts:
                                    continue

                                # TODO just check if which key is in script bytes, no need to serialize keys
                                # TODO but that may not be true for KeyHash expressions
                                if which_key in [k.key_bytes() for k in leaf.keys]:
                                    inner_tr_sh.append((scr, taproot_scripts[scr]))

                            tr_sh.append(inner_tr_sh)
                            del taproot_scripts

                else:
                    # single pubkey <=> single key
                    assert len(inp.sp_idxs) == 1
                    sp_idx = inp.sp_idxs[0]

                    assert not inp.added_sigs, "already done??"
                    assert not inp.taproot_key_sig, "already done taproot??"

                    if inp.taproot_subpaths:
                        schnorrsig = True
                        pubk = inp.taproot_subpaths[sp_idx][0]
                        sp = inp.taproot_subpaths[sp_idx][1][2]
                    else:
                        pubk = inp.subpaths[sp_idx][0]
                        sp = inp.subpaths[sp_idx][1]

                    int_pth = self.handle_zero_xfp(self.parse_xfp_path(sp), self.my_xfp, None)
                    skp = keypath_to_str(int_pth)
                    # get node required
                    node = sv.derive_path(skp, register=False)
                    # expensive test, but works... and important
                    pu = node.pubkey()
                    if schnorrsig:
                        pu = pu[1:]

                    assert pu == self.get(pubk), \
                        "Path (%s) led to wrong pubkey for input#%d"%(skp, in_idx)

                    to_sign.append((node, pubk))

                    # track wallet usage
                    OWNERSHIP.note_subpath_used(int_pth)

                # normal operation with valid sighash
                if not inp.is_segwit:
                    # Hash by serializing/blanking various subparts of the transaction
                    txi.scriptSig = inp.get_scriptSig()
                    digest = self.make_txn_sighash(in_idx, txi, inp.sighash)
                else:
                    # Hash the inputs and such in totally new ways, based on BIP-143
                    if not inp.taproot_subpaths:
                        digest = self.make_txn_segwit_sighash(in_idx, txi, inp.amount,
                                                              inp.segwit_v0_scriptCode(),
                                                              inp.sighash)
                    elif not tr_sh:
                        # taproot keyspend
                        digest = self.make_txn_taproot_sighash(in_idx, hash_type=inp.sighash)
                    # else:
                        # sighashes for tapscript spend are calculated later

                if sv.deltamode:
                    # Current user is actually a thug with a slightly wrong PIN, so we
                    # do have access to the private keys and could sign txn, but we
                    # are going to silently corrupt our signatures.
                    digest = ngu.hash.sha256d(digest)

                # we no longer need utxo_spk if:
                # - none of the inputs that we're signing is P2TR
                # - this input is not P2PK or P2PKH, otherwise we need utxo_spk for scriptSig
                if not self.my_tr_in and (inp.af not in (AF_BARE_PK, AF_CLASSIC)):
                    try:
                        del inp.utxo_spk
                    except AttributeError: pass  # may not have UTXO

                # The precious private key we need
                for i, (node, pk_coord) in enumerate(to_sign):
                    sk = node.privkey()
                    # Do the ACTUAL signature ... finally!!!
                    if schnorrsig:
                        kp = ngu.secp256k1.keypair(sk)
                        xonly_pk = kp.xonly_pubkey().to_bytes()
                        if tr_sh:
                            # in tapscript keys are not tweaked, just sign with the key in the script
                            taproot_script_sigs = inp.get_taproot_script_sigs()
                            inp.tr_added_sigs = inp.tr_added_sigs or {}

                            for taproot_script, leaf_ver in tr_sh[i]:
                                _key = (xonly_pk, tapleaf_hash(taproot_script, leaf_ver))
                                if _key in taproot_script_sigs:
                                    continue  # already done ?

                                digest = self.make_txn_taproot_sighash(in_idx, hash_type=inp.sighash,
                                                                       scriptpath=True,
                                                                       script=taproot_script, leaf_ver=leaf_ver)

                                if sv.deltamode:
                                    digest = ngu.hash.sha256d(digest)

                                sig = ngu.secp256k1.sign_schnorr(sk, digest, ngu.random.bytes(32))
                                # in the common case of SIGHASH_DEFAULT, encoded as '0x00', a space optimization MUST be made by
                                # 'omitting' the sighash byte, resulting in a 64-byte signature with SIGHASH_DEFAULT assumed
                                if inp.sighash != SIGHASH_DEFAULT:
                                    sig += bytes([inp.sighash])

                                # separate container for PSBT_IN_TAP_SCRIPT_SIG that we added
                                inp.tr_added_sigs[_key] = sig
                        else:
                            # BIP 341 states: "If the spending conditions do not require a script path,
                            # the output key should commit to an unspendable script path instead of having no script path.
                            # This can be achieved by computing the output key point as Q = P + int(hashTapTweak(bytes(P)))G."
                            
                            # For silent payment outputs, sp_tweak already includes the full output key derivation
                            # so we skip the normal taproot tweaking
                            if inp.sp_tweak:
                                sp_tweak_bytes = self.get(inp.sp_tweak)
                                tweaked_sk_int = compute_silent_payment_spending_privkey(sk, sp_tweak_bytes)
                                tweaked_sk = tweaked_sk_int.to_bytes(32, 'big')
                                sig = ngu.secp256k1.sign_schnorr(tweaked_sk, digest, ngu.random.bytes(32))
                            else:
                                tweak = xonly_pk
                                if inp.taproot_merkle_root and inp.use_keypath:
                                    # we have a script path but internal key is spendable by us
                                    # merkle root needs to be added to tweak with internal key
                                    # merkle root was already verified against registered script in determine_my_signing_key
                                    tweak += self.get(inp.taproot_merkle_root)

                                tweak = ngu.hash.sha256t(TAP_TWEAK_H, tweak, True)
                                kpt = kp.xonly_tweak_add(tweak)
                                sig = ngu.secp256k1.sign_schnorr(kpt, digest, ngu.random.bytes(32))
                                del kpt
                            
                            if inp.sighash != SIGHASH_DEFAULT:
                                sig += bytes([inp.sighash])

                            # in the common case of SIGHASH_DEFAULT, encoded as '0x00', a space optimization MUST be made by
                            # 'omitting' the sighash byte, resulting in a 64-byte signature with SIGHASH_DEFAULT assumed
                            inp.taproot_key_sig = sig

                        del kp
                    else:
                        der_sig = self.ecdsa_grind_sign(sk, digest, inp.sighash)
                        inp.added_sigs = inp.added_sigs or []
                        inp.added_sigs.append((pk_coord, der_sig))

                    # private key no longer required
                    stash.blank_object(sk)
                    stash.blank_object(node)
                    del sk, node

                    if self.is_v2:
                        self.set_modifiable_flag(inp)

                if drop_sighash:
                    # only drop after modifiable is set, in case of PSBTv2
                    # SIGHASH_DEFAULT if taproot
                    # SIGHASH_ALL if non-taproot
                    inp.sighash = None

                del to_sign
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

    def make_txn_taproot_sighash(self, input_index, hash_type=SIGHASH_DEFAULT, scriptpath=False, script=None,
                                 codeseparator_pos=-1, annex=None, leaf_ver=TAPROOT_LEAF_TAPSCRIPT):
        # BIP-341
        fd = self.fd
        old_pos = fd.tell()

        out_type = SIGHASH_ALL if (hash_type == SIGHASH_DEFAULT) else (hash_type & 3)
        in_type = hash_type & SIGHASH_ANYONECANPAY

        if not self.hashValues and in_type != SIGHASH_ANYONECANPAY:
            hashPrevouts = sha256()
            hashSequence = sha256()
            hashValues = sha256()
            hashScriptPubKeys = sha256()
            # input side
            for in_idx, txi in self.input_iter():
                hashPrevouts.update(txi.prevout.serialize())
                hashSequence.update(pack("<I", txi.nSequence))
                inp = self.inputs[in_idx]
                hashValues.update(pack("<q", inp.amount))
                hashScriptPubKeys.update(ser_string(inp.utxo_spk))

            self.hashPrevouts = hashPrevouts.digest()
            self.hashSequence = hashSequence.digest()
            self.hashValues = hashValues.digest()
            self.hashScriptPubKeys = hashScriptPubKeys.digest()

            del hashPrevouts, hashSequence, hashValues, hashScriptPubKeys, txi
            gc.collect()

        if not self.hashOutputs and out_type == SIGHASH_ALL:
            # output side
            hashOutputs = sha256()
            for out_idx, txo in self.output_iter():
                hashOutputs.update(txo.serialize())

            self.hashOutputs = hashOutputs.digest()

            del hashOutputs, txo
            gc.collect()

        msg = bytes([0, hash_type])
        msg += pack('<i', self.txn_version)
        msg += pack('<I', self.lock_time)

        if in_type != SIGHASH_ANYONECANPAY:
            # sha_prevouts
            msg += self.hashPrevouts
            # sha_amounts
            msg += self.hashValues
            # sha_scriptpubkeys
            msg += self.hashScriptPubKeys
            # sha_sequences
            msg += self.hashSequence

        if out_type == SIGHASH_ALL:
            # sha_outputs
            msg += self.hashOutputs

        # spend type
        spend_type = 0
        if annex is not None:
            spend_type |= 1
        if scriptpath:
            spend_type |= 2
        msg += bytes([spend_type])

        if in_type == SIGHASH_ANYONECANPAY:
            for in_idx, txi in self.input_iter():
                if input_index == in_idx:
                    inp = self.inputs[in_idx]
                    msg += txi.prevout.serialize()
                    msg += pack("<q", inp.amount)
                    msg += ser_string(inp.utxo_spk)
                    msg += pack("<I", txi.nSequence)
                    break
            else:
                assert False, "ANYONECANPAY inpupt idx"
        else:
            msg += pack('<I', input_index)

        if (spend_type & 1):
            msg += ngu.hash.sha256s(ser_string(annex))
        if out_type == SIGHASH_SINGLE:
            assert input_index < self.num_outputs, "SINGLE corresponding output (%d) missing" % input_index
            for out_idx, txo in self.output_iter():
                if input_index == out_idx:
                    msg += ngu.hash.sha256s(txo.serialize())
                    break

        if scriptpath:
            msg += tapleaf_hash(script, leaf_ver)
            msg += bytes([0])
            msg += pack("<i", codeseparator_pos)

        assert len(msg) == 175 - (in_type == SIGHASH_ANYONECANPAY) * 49 - (
                out_type != SIGHASH_ALL and out_type != SIGHASH_SINGLE) * 32 + (
                       annex is not None) * 32 + scriptpath * 37, "taproot SigMsg length does not make sense"
        fd.seek(old_pos)
        sighash = ngu.hash.sha256t(TAP_SIGHASH_H, msg, True)
        return sighash

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

    def miniscript_input_complete(self, inp):
        desc = self.active_miniscript.to_descriptor()
        if desc.is_basic_multisig:
            # we can only finalize multisig inputs from all miniscript set
            M, N = desc.miniscript.m_n()
            ll = 0
            if inp.part_sigs:
                ll += len(inp.part_sigs)
            if inp.added_sigs:
                ll += len(inp.added_sigs)
            if ll >= M:
                return True
        return False

    def is_complete(self):
        # Are all the inputs (now) signed?

        # plus we added some signatures
        for i, inp in enumerate(self.inputs):
            if inp.fully_signed:
                # was fully signed before (fully signed works with part_sigs only)
                continue
            elif inp.taproot_key_sig:
                continue
            elif inp.is_miniscript and self.active_miniscript:
                if self.miniscript_input_complete(inp):
                    continue
                return False

            ll = len(inp.added_sigs) if inp.added_sigs else 0
            ll += len(inp.part_sigs) if inp.part_sigs else 0
            if inp.subpaths and (len(inp.subpaths) == ll):
                continue

            # input is not signed - and therefore tx is not complete
            return False

        return True

    def multisig_signatures(self, inp):
        assert self.active_miniscript
        desc = self.active_miniscript.to_descriptor()
        assert desc.is_basic_multisig
        M, N = desc.miniscript.m_n()

        # collect all signatures and parse them if some just coords
        full_sigs = {}
        if inp.added_sigs:
            # what we add is always in memory (not coordinates to PSRAM)
            for pk_coord, sig in inp.added_sigs:
                full_sigs[self.get(pk_coord)] = sig

        if inp.part_sigs:
            # what others added is always just coordinates
            for k, v in inp.part_sigs:
                full_sigs[self.get(k)] = self.get(v)
        # ===

        if desc.is_sortedmulti:
            # BIP-67 easy just sort by public keys
            sigs = [sig for pk, sig in sorted(full_sigs.items())]
        else:
            # need to respect the order of keys in actual descriptor
            sigs = []
            for key in desc.keys:
                for k, v in inp.subpaths:
                    pk = self.get(k)
                    xfp = self.handle_zero_xfp(self.parse_xfp_path(v), self.my_xfp, None)[0]
                    # if xfp matches but pk not in all_sigs -> signer haven't signed
                    # it is ok in threshold multisig - just skip
                    if (key.origin.cc_fp == xfp) and (pk in full_sigs):
                        sigs.append(full_sigs[pk])
                        break

        # save space and only provide necessary amount of signatures (smaller tx, less fees)
        return sigs[:M]

    def singlesig_signature(self, inp):
        # return signature that we added
        # or one signature from partial sigs if input is fully sign
        if inp.added_sigs:
            assert len(inp.added_sigs) == 1
            return self.get(inp.added_sigs[0][0]), inp.added_sigs[0][1]

        if inp.part_sigs:
            assert len(inp.part_sigs) == 1
            pk, sig = inp.part_sigs[0]
            return self.get(pk), self.get(sig)

    def miniscript_xfps_needed(self):
        # provide the set of xfp's that still need to sign PSBT
        # - used to find which multisig-signer needs to go next
        rv = set()
        done_keys = set()

        for inp in self.inputs:
            if inp.fully_signed:
                continue

            if inp.taproot_subpaths:
                if inp.taproot_key_sig:
                    # already signed
                    continue

                # only get this once for each input
                if inp.taproot_script_sigs:
                    for xo, _ in inp.get_taproot_script_sigs():
                        done_keys.add(xo)

                if inp.tr_added_sigs:
                    for (xo, _) in inp.tr_added_sigs:
                        done_keys.add(xo)

                for i, (k, v) in enumerate(inp.taproot_subpaths):
                    xpk = self.get(k)
                    if inp.ik_idx == i:
                        # internal key
                        if self.active_miniscript.ik_u:
                            # no way to sign with unspend
                            continue
                    else:
                        if xpk in done_keys:
                            continue

                    # add xfp
                    xfp = self.handle_zero_xfp(self.parse_xfp_path(v[2]), self.my_xfp, None)[0]
                    rv.add(xfp)

            else:
                if inp.part_sigs:
                    for k, _ in inp.part_sigs:
                        done_keys.add(self.get(k))

                if inp.added_sigs:
                    for k, _ in inp.added_sigs:
                        done_keys.add(self.get(k))

                for k, v in inp.subpaths:
                    if self.get(k) not in done_keys:
                        xfp = self.handle_zero_xfp(self.parse_xfp_path(v), self.my_xfp, None)[0]
                        rv.add(xfp)

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
            if inp.is_miniscript and not inp.use_keypath:
                assert self.miniscript_input_complete(inp), 'Incomplete signature set on input #%d' % in_idx
            else:
                # single signature
                if inp.af == AF_P2TR:
                    assert inp.taproot_key_sig, 'No signature on input #%d' % in_idx
                else:
                    ssig = self.singlesig_signature(inp)
                    assert ssig, 'No signature on input #%d' % in_idx

            if inp.is_segwit:
                # p2sh-p2wsh & p2sh-p2wpkh still need redeem here (redeem is witness scriptPubKey)
                txi.scriptSig = inp.get_scriptSig()
                # for p2wpkh & p2wsh inp.scriptSig is b'' (no redeem script bloat anymore) - do not ser_string
                if txi.scriptSig:
                    txi.scriptSig = ser_string(inp.get_scriptSig())

                # Actual signature will be in witness data area
            else:
                # insert the new signature(s), assuming fully signed txn.
                if inp.is_miniscript:
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
                    if inp.taproot_key_sig:
                        # segwit v1 (taproot)
                        w = inp.taproot_key_sig
                        if isinstance(w, tuple):
                            w = self.get(w)
                        # can be 65 bytes if sighash != SIGHASH_DEFAULT (0x00)
                        assert len(w) in (64, 65)
                        wit.scriptWitness.stack = [w]
                    elif inp.is_miniscript:
                        sigs = self.multisig_signatures(inp)
                        wit.scriptWitness.stack = [b""] + sigs + [self.get(inp.witness_script)]
                    else:
                        # segwit v0
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
