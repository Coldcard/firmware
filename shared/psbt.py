# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# psbt.py - understand PSBT file format: verify and generate them
#
from ustruct import unpack_from, unpack, pack
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, B2A, keypath_to_str, problem_file_line
import stash, gc, history, sys, ngu, ckcc
from uhashlib import sha256
from uio import BytesIO
from sffile import SizerFile
from sram2 import psbt_tmp256
from multisig import MultisigWallet, MAX_SIGNERS, disassemble_multisig, disassemble_multisig_mn
from exceptions import FatalPSBTIssue, FraudulentChangeOutput
from serializations import ser_compact_size, deser_compact_size, hash160, hash256
from serializations import CTxIn, CTxInWitness, CTxOut, SIGHASH_ALL, ser_uint256
from serializations import ser_sig_der, uint256_from_str, ser_push_data, uint256_from_str
from serializations import ser_string
from nvstore import settings

from public_constants import (
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_XPUB, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT,
    PSBT_OUT_BIP32_DERIVATION, MAX_PATH_DEPTH
)

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

def read_varint(v):
    # read "compact sized" int from a few bytes.
    assert not isinstance(v, tuple), v
    nit = v[0]
    if nit == 253:
        return unpack_from("<H", v, 1)[0]
    elif nit == 254:
        return unpack_from("<I", v, 1)[0]
    elif nit == 255:
        return unpack_from("<Q", v, 1)[0]
    return nit

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
    pos, ll = poslen
    rv = hasher or sha256()

    fd.seek(pos)
    while ll:
        here = fd.read_into(psbt_tmp256)
        if not here: break
        if here > ll:
            here = ll
        rv.update(memoryview(psbt_tmp256)[0:here])
        ll -= here

    if hasher:
        return

    return ngu.hash.sha256s(rv.digest())


class psbtProxy:
    # store offsets to values, but track the keys in-memory.
    short_values = ()
    no_keys = ()

    # these fields will return None but are not stored unless a value is set
    blank_flds = ('unknown', )

    def __init__(self):
        self.fd = None
        #self.unknown = {}

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
            assert vs != None, 'eof'

            kt = key[0]

            if kt in self.no_keys:
                assert len(key) == 1        # not expectiing key

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

        if self.num_our_keys != None:
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
                    'is_change', 'num_our_keys')

    def __init__(self, fd, idx):
        super().__init__()

        # things we track
        #self.subpaths = None        # a dictionary if non-empty
        #self.redeem_script = None
        #self.witness_script = None

        # this flag is set when we are assuming output will be change (same wallet)
        #self.is_change = False

        self.parse(fd)


    def store(self, kt, key, val):
        if kt == PSBT_OUT_BIP32_DERIVATION:
            if not self.subpaths:
                self.subpaths = {}
            self.subpaths[key[1:]] = val
        elif kt == PSBT_OUT_REDEEM_SCRIPT:
            self.redeem_script = val
        elif kt == PSBT_OUT_WITNESS_SCRIPT:
            self.witness_script = val
        else:
            if not self.unknown:
                self.unknown = {}
            self.unknown[key] = val

    def serialize(self, out_fd, my_idx):

        wr = lambda *a: self.write(out_fd, *a)

        if self.subpaths:
            for k in self.subpaths:
                wr(PSBT_OUT_BIP32_DERIVATION, self.subpaths[k], k)

        if self.redeem_script:
            wr(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            wr(PSBT_OUT_WITNESS_SCRIPT, self.witness_script)

        if self.unknown:
            for k in self.unknown:
                wr(k[0], self.unknown[k], k[1:])

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

        if num_ours == 0:
            # - not considered fraud because other signers looking at PSBT may have them
            # - user will see them as normal outputs, which they are from our PoV.
            return

        # - must match expected address for this output, coming from unsigned txn
        addr_type, addr_or_pubkey, is_segwit = txo.get_address()

        if len(self.subpaths) == 1:
            # p2pk, p2pkh, p2wpkh cases
            expect_pubkey, = self.subpaths.keys()
        else:
            # p2wsh/p2sh cases need full set of pubkeys, and therefore redeem script
            expect_pubkey = None

        if addr_type == 'p2pk':
            # output is public key (not a hash, much less common)
            assert len(addr_or_pubkey) == 33

            if addr_or_pubkey != expect_pubkey:
                raise FraudulentChangeOutput(out_idx, "P2PK change output is fraudulent")

            self.is_change = True
            return

        # Figure out what the hashed addr should be
        pkh = addr_or_pubkey

        if addr_type == 'p2sh':
            # P2SH or Multisig output

            # Can be both, or either one depending on address type
            redeem_script = self.get(self.redeem_script) if self.redeem_script else None
            witness_script = self.get(self.witness_script) if self.witness_script else None

            if not redeem_script and not witness_script:
                # Perhaps an omission, so let's not call fraud on it
                # But definately required, else we don't know what script we're sending to.
                raise FatalPSBTIssue("Missing redeem/witness script for output #%d" % out_idx)

            if not is_segwit and redeem_script and \
                    len(redeem_script) == 22 and \
                    redeem_script[0] == 0 and redeem_script[1] == 20:

                # it's actually segwit p2pkh inside p2sh
                pkh = redeem_script[2:22]
                expect_pkh = hash160(expect_pubkey)

            else:
                # Multisig change output, for wallet we're supposed to be a part of.
                # - our key must be part of it
                # - must look like input side redeem script (same fingerprints)
                # - assert M/N structure of output to match any inputs we have signed in PSBT!
                # - assert all provided pubkeys are in redeem script, not just ours
                # - we get all of that by re-constructing the script from our wallet details

                # it cannot be change if it doesn't precisely match our multisig setup
                if not active_multisig:
                    # - might be a p2sh output for another wallet that isn't us
                    # - not fraud, just an output with more details than we need.
                    self.is_change = False
                    return

                if MultisigWallet.disable_checks:
                    # Without validation, we have to assume all outputs
                    # will be taken from us, and are not really change.
                    self.is_change = False
                    return

                # redeem script must be exactly what we expect
                # - pubkeys will be reconstructed from derived paths here
                # - BIP-45, BIP-67 rules applied
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
                    return

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

        elif addr_type == 'p2pkh':
            # input is hash160 of a single public key
            assert len(addr_or_pubkey) == 20
            expect_pkh = hash160(expect_pubkey)
        else:
            # we don't know how to "solve" this type of input
            return

        if pkh != expect_pkh:
            raise FraudulentChangeOutput(out_idx, "Change output is fraudulent")

        # We will check pubkey value at the last second, during signing.
        self.is_change = True


# Track details of each input of PSBT
#
class psbtInputProxy(psbtProxy):

    # just need to store a simple number for these
    short_values = { PSBT_IN_SIGHASH_TYPE }

    # only part-sigs have a key to be stored.
    no_keys = { PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE,
                     PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_FINAL_SCRIPTSIG,
                     PSBT_IN_FINAL_SCRIPTWITNESS }

    blank_flds = ('unknown',
                    'utxo', 'witness_utxo', 'sighash',
                    'redeem_script', 'witness_script', 'fully_signed',
                    'is_segwit', 'is_multisig', 'is_p2sh', 'num_our_keys',
                    'required_key', 'scriptSig', 'amount', 'scriptCode', 'added_sig')

    def __init__(self, fd, idx):
        super().__init__()

        #self.utxo = None
        #self.witness_utxo = None
        self.part_sig = {}
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
        #self.added_sig = None

        self.parse(fd)

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

        # sighash, but we're probably going to ignore anyway.
        self.sighash = SIGHASH_ALL if self.sighash is None else self.sighash
        if self.sighash != SIGHASH_ALL:
            # - someday we will expand to other types, but not yet
            raise FatalPSBTIssue('Can only do SIGHASH_ALL')

        if self.part_sig:
            # How complete is the set of signatures so far?
            # - assuming PSBT creator doesn't give us extra data not required
            # - seems harmless if they fool us into thinking already signed; we do nothing
            # - could also look at pubkey needed vs. sig provided
            # - could consider structure of MofN in p2sh cases
            self.fully_signed = (len(self.part_sig) >= len(self.subpaths))
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
            self.is_segwit = True

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


    def determine_my_signing_key(self, my_idx, utxo, my_xfp, psbt):
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
        if addr_is_segwit and not self.is_segwit:
            self.is_segwit = True

        if addr_type == 'p2sh':
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
                # - limitation: we cannot be two legs of a multisig
                # - but if partial sig already in place, ignore that one
                for pubkey, path in self.subpaths.items():
                    if self.part_sig and (pubkey in self.part_sig):
                        # pubkey has already signed, so ignore
                        continue

                    if path[0] == my_xfp:
                        # slight chance of dup xfps, so handle
                        if not which_key:
                            which_key = set()

                        which_key.add(pubkey)

            if not addr_is_segwit and \
                    len(redeem_script) == 22 and \
                    redeem_script[0] == 0 and redeem_script[1] == 20:
                # it's actually segwit p2pkh inside p2sh
                addr_type = 'p2sh-p2wpkh'
                addr = redeem_script[2:22]
                self.is_segwit = True
            else:
                # multiple keys involved, we probably can't do the finalize step
                self.is_multisig = True

            if self.witness_script and not self.is_segwit and self.is_multisig:
                # bugfix
                addr_type = 'p2sh-p2wsh'
                self.is_segwit = True

        elif addr_type == 'p2pkh':
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

        elif addr_type == 'p2pk':
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

        if self.is_multisig and which_key:
            # We will be signing this input, so 
            # - find which wallet it is or
            # - check it's the right M/N to match redeem script

            #print("redeem: %s" % b2a_hex(redeem_script))
            M, N = disassemble_multisig_mn(redeem_script)
            xfp_paths = list(self.subpaths.values())
            xfp_paths.sort()

            if not psbt.active_multisig:
                # search for multisig wallet
                wal = MultisigWallet.find_match(M, N, xfp_paths)
                if not wal:
                    raise FatalPSBTIssue('Unknown multisig wallet')

                psbt.active_multisig = wal
            else:
                # check consistent w/ already selected wallet
                psbt.active_multisig.assert_matching(M, N, xfp_paths)

            # validate redeem script, by disassembling it and checking all pubkeys
            try:
                psbt.active_multisig.validate_script(redeem_script, subpaths=self.subpaths)
            except BaseException as exc:
                sys.print_exception(exc)
                raise FatalPSBTIssue('Input #%d: %s' % (my_idx, exc))

        if not which_key and DEBUG:
            print("no key: input #%d: type=%s segwit=%d a_or_pk=%s scriptPubKey=%s" % (
                    my_idx, addr_type, self.is_segwit or 0,
                    b2a_hex(addr_or_pubkey), b2a_hex(utxo.scriptPubKey)))

        self.required_key = which_key

        if self.is_segwit:
            if ('pkh' in addr_type):
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
            self.part_sig[key[1:]] = val
        elif kt == PSBT_IN_BIP32_DERIVATION:
            self.subpaths[key[1:]] = val
        elif kt == PSBT_IN_REDEEM_SCRIPT:
            self.redeem_script = val
        elif kt == PSBT_IN_WITNESS_SCRIPT:
            self.witness_script = val
        elif kt == PSBT_IN_SIGHASH_TYPE:
            self.sighash = unpack('<I', val)[0]
        else:
            # including: PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS
            if not self.unknown:
                self.unknown = {}
            self.unknown[key] = val

    def serialize(self, out_fd, my_idx):
        # Output this input's values; might include signatures that weren't there before

        wr = lambda *a: self.write(out_fd, *a)

        if self.utxo:
            wr(PSBT_IN_NON_WITNESS_UTXO, self.utxo)
        if self.witness_utxo:
            wr(PSBT_IN_WITNESS_UTXO, self.witness_utxo)

        if self.part_sig:
            for pk in self.part_sig:
                wr(PSBT_IN_PARTIAL_SIG, self.part_sig[pk], pk)

        if self.added_sig:
            pubkey, sig = self.added_sig
            wr(PSBT_IN_PARTIAL_SIG, sig, pubkey)

        if self.sighash is not None:
            wr(PSBT_IN_SIGHASH_TYPE, pack('<I', self.sighash))

        for k in self.subpaths:
            wr(PSBT_IN_BIP32_DERIVATION, self.subpaths[k], k)

        if self.redeem_script:
            wr(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            wr(PSBT_IN_WITNESS_SCRIPT, self.witness_script)

        if self.unknown:
            for k in self.unknown:
                wr(k[0], self.unknown[k], k[1:])



class psbtObject(psbtProxy):
    "Just? parse and store"

    no_keys = { PSBT_GLOBAL_UNSIGNED_TX }

    def __init__(self):
        super().__init__()

        # global objects
        self.txn = None
        self.xpubs = []         # tuples(xfp_path, xpub)

        from glob import dis
        self.my_xfp = settings.get('xfp', 0)

        # details that we discover as we go
        self.inputs = None
        self.outputs = None
        self.had_witness = None
        self.num_inputs = None
        self.num_outputs = None
        self.vin_start = None
        self.vout_start = None
        self.wit_start = None
        self.txn_version = None
        self.lock_time = None
        self.total_value_out = None
        self.total_value_in = None
        self.presigned_inputs = set()

        # when signing segwit stuff, there is some re-use of hashes
        self.hashPrevouts = None
        self.hashSequence = None
        self.hashOutputs = None

        # this points to a MS wallet, during operation
        # - we are only supporting a single multisig wallet during signing
        self.active_multisig = None

        self.warnings = []

    def store(self, kt, key, val):
        # capture the values we care about

        if kt == PSBT_GLOBAL_UNSIGNED_TX:
            self.txn = val
        elif kt == PSBT_GLOBAL_XPUB:
            # list of tuples(xfp_path, xpub)
            self.xpubs.append( (self.get(val), key[1:]) )
            assert len(self.xpubs) <= MAX_SIGNERS
        else:
            self.unknowns[key] = val

    def output_iter(self):
        # yield the txn's outputs: index, (CTxOut object) for each
        assert self.vout_start is not None      # must call input_iter/validate first

        fd = self.fd
        fd.seek(self.vout_start)

        total_out = 0
        tx_out = CTxOut()
        for idx in range(self.num_outputs):

            tx_out.deserialize(fd)

            total_out += tx_out.nValue

            cont = fd.tell()
            yield idx, tx_out

            fd.seek(cont)

        if self.total_value_out is None:
            self.total_value_out = total_out
        else:
            assert self.total_value_out == total_out

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
        self.lock_time = unpack("<I", fd.read(4))[0]

        assert fd.tell() == end_pos, 'txn read end wrong'

        fd.seek(old_pos)

    def input_iter(self):
        # Yield each of the txn's inputs, as a tuple:
        #
        #   (index, CTxIn)
        #
        # - we also capture much data about the txn on the first pass thru here
        #
        fd = self.fd

        assert self.vin_start       # call parse_txn() first!

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
        from opcodes import OP_CHECKMULTISIG
        for i in self.inputs:
            ks = i.witness_script or i.redeem_script
            if not ks: continue

            rs = i.get(ks)
            if rs[-1] != OP_CHECKMULTISIG: continue

            M, N = disassemble_multisig_mn(rs)
            assert 1 <= M <= N <= MAX_SIGNERS

            return (M, N)

        # not multisig, probably
        return None, None


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
            M, N = self.guess_M_of_N()

            if not N:
                # not multisig, but we can still verify:
                # - XFP should be one of ours (checked above).
                # - too slow to re-derive it here, so nothing more to validate at this point
                return

            assert N == len(xfp_paths) 

            for c in candidates:
                if c.M == M:
                    assert c.N == N
                    self.active_multisig = c
                    break

        del candidates

        if not self.active_multisig:
            # Maybe create wallet, for today, forever, or fail, etc.
            proposed, need_approval = MultisigWallet.import_from_psbt(M, N, self.xpubs)
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


    async def validate(self):
        # Do a first pass over the txn. Raise assertions, be terse tho because
        # these messages are rarely seen. These are syntax/fatal errors.
        #
        assert self.txn[1] > 63, 'too short'

        # this parses the input TXN in-place
        for idx, txin in self.input_iter():
            self.inputs[idx].validate(idx, txin, self.my_xfp, self)

        assert len(self.inputs) == self.num_inputs, 'ni mismatch'

        # if multisig xpub details provided, they better be right and/or offer import
        if self.xpubs:
            await self.handle_xpubs()

        assert self.num_outputs >= 1, 'need outs'

        if DEBUG:
            our_keys = sum(1 for i in self.inputs if i.num_our_keys)

            print("PSBT: %d inputs, %d output, %d fully-signed, %d ours" % (
                   self.num_inputs, self.num_outputs,
                   sum(1 for i in self.inputs if i and i.fully_signed), our_keys))

    def consider_outputs(self):
        # scan ouputs:
        # - is it a change address, defined by redeem script (p2sh) or key we know is ours
        # - mark change outputs, so perhaps we don't show them to users

        for idx, txo in self.output_iter():
            self.outputs[idx].validate(idx, txo, self.my_xfp, self.active_multisig, self)

        if self.total_value_out is None:
            # this happens, but would expect this to have done already?
            for out_idx, txo in self.output_iter():
                pass


        # check fee is reasonable
        if self.total_value_out == 0:
            per_fee = 100
        else:
            the_fee = self.calculate_fee()
            if the_fee < 0:
                raise FatalPSBTIssue("Outputs worth more than inputs!")

            per_fee = the_fee * 100 / self.total_value_out

        fee_limit = settings.get('fee_limit', DEFAULT_MAX_FEE_PERCENTAGE)

        if fee_limit != -1 and per_fee >= fee_limit:
            raise FatalPSBTIssue("Network fee bigger than %d%% of total amount (it is %.0f%%)."
                                % (fee_limit, per_fee))
        if per_fee >= 5:
            self.warnings.append(('Big Fee', 'Network fee is more than '
                                    '5%% of total value (%.1f%%).' % per_fee))

        # Enforce policy related to change outputs
        self.consider_dangerous_change(self.my_xfp)

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

    def consider_inputs(self):
        # Look an the UTXO's that we are spending. Do we have them? Do the
        # hashes match, and what values are we getting?
        # Important: parse incoming UTXO to build total input value
        missing = 0
        total_in = 0

        for i, txi in self.input_iter():
            inp = self.inputs[i]
            if inp.fully_signed:
                self.presigned_inputs.add(i)

            if not inp.has_utxo():
                # maybe they didn't provide the UTXO
                missing += 1
                continue

            # pull out just the CTXOut object (expensive)
            utxo = inp.get_utxo(txi.prevout.n)

            assert utxo.nValue > 0
            total_in += utxo.nValue

            # Look at what kind of input this will be, and therefore what
            # type of signing will be required, and which key we need.
            # - also validates redeem_script when present
            # - also finds appropriate multisig wallet to be used
            inp.determine_my_signing_key(i, utxo, self.my_xfp, self)

            # iff to UTXO is segwit, then check it's value, and also
            # capture that value, since it's supposed to be immutable
            if inp.is_segwit:
                history.verify_amount(txi.prevout, inp.amount, i)

            del utxo

        # XXX scan witness data provided, and consider those ins signed if not multisig?

        if missing:
            # Should probably be a fatal msg; so risky... but
            # - maybe we aren't expected to sign that input? (coinjoin)
            # - assume for now, probably funny business so we should stop
            raise FatalPSBTIssue('Missing UTXO(s). Cannot determine value being signed')
            # self.warnings.append(('Missing UTXOs',
            #        "We don't know enough about the inputs to this transaction to be sure "
            #        "of their value. This means the network fee could be huge, or resulting "
            #        "transaction's signatures invalid."))
            #self.total_value_in = None
        else:
            assert total_in > 0
            self.total_value_in = total_in

        if len(self.presigned_inputs) == self.num_inputs:
            # Maybe wrong for multisig cases? Maybe they want to add their
            # own signature, even tho N of M is satisfied?!
            raise FatalPSBTIssue('Transaction looks completely signed already?')

        # We should know pubkey required for each input now.
        # - but we may not be the signer for those inputs, which is fine.
        # - TODO: but what if not SIGHASH_ALL
        no_keys = set(n for n,inp in enumerate(self.inputs)
                            if inp.required_key == None and not inp.fully_signed)
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

        assert rv.txn, 'missing reqd section'

        # learn about the bitcoin transaction we are signing.
        rv.parse_txn()

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
            # - XXX probably a bad idea, so disabled for now
            out_fd.write(b'\x01\x00')       # keylength=1, key=b'', PSBT_GLOBAL_UNSIGNED_TX

            with SizerFile() as fd:
                self.finalize(fd)
                txn_len = fd.tell()

            out_fd.write(ser_compact_size(txn_len))
            self.finalize(out_fd)
        else:
            # provide original txn (unchanged)
            wr(PSBT_GLOBAL_UNSIGNED_TX, self.txn)

        if self.xpubs:
            for v, k in self.xpubs:
                wr(PSBT_GLOBAL_XPUB, v, k)

        if self.unknown:
            for k in self.unknown:
                wr(k[0], self.unknown[k], k[1:])

        # sep between globals and inputs
        out_fd.write(b'\0')

        for idx, inp in enumerate(self.inputs):
            inp.serialize(out_fd, idx)
            out_fd.write(b'\0')

        for idx, outp in enumerate(self.outputs):
            outp.serialize(out_fd, idx)
            out_fd.write(b'\0')

    def sign_it(self):
        # txn is approved. sign all inputs we can sign. add signatures
        # - hash the txn first
        # - sign all inputs we have the key for
        # - inputs might be p2sh, p2pkh and/or segwit style
        # - save partial inputs somewhere (append?)
        # - update our state with new partial sigs
        from glob import dis

        with stash.SensitiveValues() as sv:
            # Double check the change outputs are right. This is slow, but critical because
            # it detects bad actors, not bugs or mistakes.
            # - equivilent check already done for p2sh outputs when we re-built the redeem script
            change_outs = [n for n,o in enumerate(self.outputs) if o.is_change]
            if change_outs:
                dis.fullscreen('Change Check...')

                for count, out_idx in enumerate(change_outs):
                    # only expecting single case, but be general
                    dis.progress_bar_show(count / len(change_outs))

                    oup = self.outputs[out_idx]

                    good = 0
                    for pubkey, subpath in oup.subpaths.items():
                        if subpath[0] != self.my_xfp:
                            # for multisig, will be N paths, and exactly one will
                            # be our key. For single-signer, should always be my XFP
                            continue
                            
                        # derive actual pubkey from private
                        skp = keypath_to_str(subpath)
                        node = sv.derive_path(skp)

                        # check the pubkey of this BIP-32 node
                        if pubkey == node.pubkey():
                            good += 1

                    if not good:
                        raise FraudulentChangeOutput(out_idx, 
                              "Deception regarding change output. "
                              "BIP-32 path doesn't match actual address.")

            # progress
            dis.fullscreen('Signing...')

            # Sign individual inputs
            sigs = 0
            success = set()
            for in_idx, txi in self.input_iter():
                dis.progress_bar_show(in_idx / self.num_inputs)

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

                if not inp.is_segwit:
                    # Hash by serializing/blanking various subparts of the transaction
                    digest = self.make_txn_sighash(in_idx, txi, inp.sighash)
                else:
                    # Hash the inputs and such in totally new ways, based on BIP-143
                    digest = self.make_txn_segwit_sighash(in_idx, txi,
                                    inp.amount, inp.scriptCode, inp.sighash)

                if inp.is_multisig:
                    # need to consider a set of possible keys, since xfp may not be unique
                    for which_key in inp.required_key:
                        # get node required
                        skp = keypath_to_str(inp.subpaths[which_key])
                        node = sv.derive_path(skp, register=False)

                        # expensive test, but works... and important
                        pu = node.pubkey()
                        if pu == which_key:
                            break
                    else:
                        raise AssertionError("Input #%d needs pubkey I dont have" % in_idx)

                else:
                    # single pubkey <=> single key
                    which_key = inp.required_key
    
                    assert not inp.added_sig, "already done??"
                    assert which_key in inp.subpaths, 'unk key'

                    if inp.subpaths[which_key][0] != self.my_xfp:
                        # we don't have the key for this subkey
                        # (redundant, required_key wouldn't be set)
                        continue

                    # get node required
                    skp = keypath_to_str(inp.subpaths[which_key])
                    node = sv.derive_path(skp, register=False)

                    # expensive test, but works... and important
                    pu = node.pubkey()
                    assert pu == which_key, "Path (%s) led to wrong pubkey for input#%d"%(skp, in_idx)

                # The precious private key we need
                pk = node.privkey()

                #print("privkey %s" % b2a_hex(pk).decode('ascii'))
                #print(" pubkey %s" % b2a_hex(which_key).decode('ascii'))
                #print(" digest %s" % b2a_hex(digest).decode('ascii'))

                # Do the ACTUAL signature ... finally!!!

                # We need to grind sometimes to get a positive R
                # value that will encode (after DER) into a shorter string.
                # - saves on miner's fee (which might be expected/required)
                # - blends in with Bitcoin Core signatures which do this
                for retry in range(10):
                    result = ngu.secp256k1.sign(pk, digest, retry).to_bytes()

                    # convert signature to DER format
                    #assert len(result) == 65
                    r = result[1:33]
                    s = result[33:65]
                    der_sig = ser_sig_der(r, s, inp.sighash)

                    if len(der_sig) <= 71:
                        # odds of needing retry: just under 50% I think
                        break

                # private key no longer required
                stash.blank_object(pk)
                stash.blank_object(node)
                del pk, node, pu, skp

                inp.added_sig = (which_key, der_sig)

                success.add(in_idx)

                # memory cleanup
                del result, r, s

                gc.collect()

        # done.
        dis.progress_bar_show(1)


    def make_txn_sighash(self, replace_idx, replacement, sighash_type):
        # calculate the hash value for one input of current transaction
        # - blank all script inputs
        # - except one single tx in, which is provided
        # - serialize that without witness data
        # - append SIGHASH_ALL=1 value (LE32)
        # - sha256 over that
        fd = self.fd
        old_pos = fd.tell()
        rv = sha256()

        # version number
        rv.update(pack('<i', self.txn_version))           # nVersion

        # inputs
        rv.update(ser_compact_size(self.num_inputs))
        for in_idx, txi in self.input_iter():

            if in_idx == replace_idx:
                assert not self.inputs[in_idx].witness_utxo
                assert not self.inputs[in_idx].is_segwit
                assert replacement.scriptSig
                rv.update(replacement.serialize())
            else:
                txi.scriptSig = b''
                rv.update(txi.serialize())

        # outputs
        rv.update(ser_compact_size(self.num_outputs))
        for out_idx, txo in self.output_iter():
            rv.update(txo.serialize())

        # locktime
        rv.update(pack('<I', self.lock_time))

        assert sighash_type == SIGHASH_ALL      # "only SIGHASH_ALL supported"
        # SIGHASH_ALL==1 value
        rv.update(b'\x01\x00\x00\x00')

        fd.seek(old_pos)

        # double SHA256
        return ngu.hash.sha256s(rv.digest())

    def make_txn_segwit_sighash(self, replace_idx, replacement, amount, scriptCode, sighash_type):
        # Implement BIP 143 hashing algo for signature of segwit programs.
        # see <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
        #

        fd = self.fd
        old_pos = fd.tell()

        assert sighash_type == SIGHASH_ALL      # add support for others here

        if self.hashPrevouts is None:
            # First time thru, we'll need to hash up this stuff.

            po = sha256()
            sq = sha256()

            # input side
            for in_idx, txi in self.input_iter():
                po.update(txi.prevout.serialize())
                sq.update(pack("<I", txi.nSequence))

            self.hashPrevouts = ngu.hash.sha256s(po.digest())
            self.hashSequence = ngu.hash.sha256s(sq.digest())

            del po, sq, txi

            # output side
            ho = sha256()
            for out_idx, txo in self.output_iter():
                ho.update(txo.serialize())

            self.hashOutputs = ngu.hash.sha256s(ho.digest())

            del ho, txo
            gc.collect()

            #print('hPrev: %s' % str(b2a_hex(self.hashPrevouts), 'ascii'))
            #print('hSeq : %s' % str(b2a_hex(self.hashSequence), 'ascii'))
            #print('hOuts: %s' % str(b2a_hex(self.hashOutputs), 'ascii'))

        rv = sha256()

        # version number
        rv.update(pack('<i', self.txn_version))       # nVersion
        rv.update(self.hashPrevouts)
        rv.update(self.hashSequence)

        rv.update(replacement.prevout.serialize())

        # the "scriptCode" ... not well understood
        assert scriptCode, 'need scriptCode here'
        rv.update(scriptCode)

        rv.update(pack("<q", amount))
        rv.update(pack("<I", replacement.nSequence))

        rv.update(self.hashOutputs)

        # locktime, hashType
        rv.update(pack('<II', self.lock_time, sighash_type))

        fd.seek(old_pos)

        # double SHA256
        return ngu.hash.sha256s(rv.digest())

    def is_complete(self):
        # Are all the inputs (now) signed?

        # some might have been given as signed
        signed = len(self.presigned_inputs)

        # plus we added some signatures
        for inp in self.inputs:
            if inp.is_multisig:
                # but we can't combine/finalize multisig stuff, so will never't be 'final'
                return False

            if inp.added_sig:
                signed += 1

        return signed == self.num_inputs

    def finalize(self, fd):
        # Stream out the finalized transaction, with signatures applied
        # - assumption is it's complete already.
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

            if inp.is_segwit:

                if inp.is_p2sh:
                    # multisig (p2sh) segwit still requires the script here.
                    txi.scriptSig = ser_string(inp.scriptSig)
                else:
                    # major win for segwit (p2pkh): no redeem script bloat anymore
                    txi.scriptSig = b''

                # Actual signature will be in witness data area

            else:
                # insert the new signature(s), assuming fully signed txn.
                assert inp.added_sig, 'No signature on input #%d'%in_idx
                assert not inp.is_multisig, 'Multisig PSBT combine not supported'

                pubkey, der_sig = inp.added_sig

                s = b''
                s += ser_push_data(der_sig)
                s += ser_push_data(pubkey)

                txi.scriptSig = s

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

                if inp.is_segwit and inp.added_sig:
                    # put in new sig: wit is a CTxInWitness
                    assert not wit.scriptWitness.stack, 'replacing non-empty?'
                    assert not inp.is_multisig, 'Multisig PSBT combine not supported'

                    pubkey, der_sig = inp.added_sig
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
