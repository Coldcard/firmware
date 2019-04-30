# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# psbt.py - understand PSBT file format: verify and generate them
#
from serializations import ser_compact_size, deser_compact_size, hash160, hash256
from serializations import CTxIn, CTxInWitness, CTxOut, SIGHASH_ALL, ser_uint256
from serializations import ser_sig_der, uint256_from_str, ser_push_data, uint256_from_str
from serializations import ser_string
from ustruct import unpack_from, unpack, pack
from ubinascii import hexlify as b2a_hex
import tcc, stash, gc
from uio import BytesIO
from sffile import SizerFile
from sram2 import psbt_tmp256

from public_constants import (
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT,
    PSBT_OUT_BIP32_DERIVATION
)

# Max miner's fee, as percentage of output value, that we will allow to be signed.
# Amounts over 1% are warned regardless.
DEFAULT_MAX_FEE_PERCENTAGE = const(10)

B2A = lambda x: str(b2a_hex(x), 'ascii')

class FatalPSBTIssue(RuntimeError):
    pass
class FraudulentChangeOutput(FatalPSBTIssue):
    pass

class HashNDump:
    def __init__(self, d=None):
        self.rv = tcc.sha256()
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

def path_to_str(bin_path):
    return 'm/' + '/'.join(str(i & 0x7fffffff) + ("'" if i & 0x80000000 else "")
                            for i in bin_path[1:])

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
        raise AttributeError

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
                assert len(key) == 1, "no expecto key"

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

    def get_hash256(self, val, hasher=None):
        # return the double-sha256 of a value, without loading it into memory
        pos, ll = val
        rv = hasher or tcc.sha256()

        self.fd.seek(pos)
        while ll:
            here = self.fd.read_into(psbt_tmp256)
            if not here: break
            if here > ll:
                here = ll
            rv.update(memoryview(psbt_tmp256)[0:here])
            ll -= here

        if hasher:
            return

        return tcc.sha256(rv.digest()).digest()

    def parse_subpaths(self, my_xfp, first_known=False):
        # reformat self.subpaths into a more useful form for us; return # of them
        # that are ours.
        # - works in-place, on self.subpaths
        # - just return first result if used for outputs
        our_keys = 0

        for pk in self.subpaths:
            assert len(pk) in {33, 65}, "hdpath pubkey len"
            if len(pk) == 33:
                assert pk[0] in {0x02, 0x03}, "uncompressed pubkey"

            vl = self.subpaths[pk][1]

            # force them to use a derived key, never the master
            assert vl >= 8, 'too short key path'
            assert (vl % 4) == 0, 'corrupt key path'

            # promote to a list of ints
            v = self.get(self.subpaths[pk])
            here = list(unpack_from('<I', v, off)[0] for off in range(0, vl, 4))
            assert len(here) == vl // 4

            if first_known:
                if here[0] == my_xfp:
                    return (pk, here)
                continue

            # update in place
            self.subpaths[pk] = here

            if here[0] == my_xfp:
                our_keys += 1
            else:
                # Address that isn't based on this seed; might be another leg in a p2sh
                #print('here[0]=0x%x != 0x%x  ... %r' % (here[0], self.my_xfp,
                #       [i& 0xfff for i in here[1:]]))
                pass

        return None if first_known else our_keys


# Track details of each output of PSBT
#
class psbtOutputProxy(psbtProxy):
    no_keys = { PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT }
    blank_flds = ('unknown', 'subpaths', 'redeem_script', 'witness_script', 'is_change')

    def __init__(self, fd, idx):
        super().__init__()

        # things we track
        #self.subpaths = None        # a dictionary if non-empty
        #self.redeem_script = None
        #self.witness_script = None

        # this becomes a tuple: (pubkey, subkey path) iff we are a change output
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

        if self.unknown:
            for k in self.unknown:
                wr(k[0], self.unknown[k], k[1:])

    def validate(self, out_idx, txo, my_xfp):
        # Do things make sense for this output?
        # NOTE: We might think it's a change output, because the PSBT
        # creator has given us a key path. However, we must be
        # **very** careful and validate this fully.
        # - no output info is needed, in general, so
        #   any output info provided better be right, or fail
        # - full key derivation and validation is elsewhere, and critical.
        # - we raise a fraud alarm, since these are not innocent errors
        #
        if not self.subpaths:
            return

        ours = self.parse_subpaths(my_xfp, first_known=True)

        # - must be exactly one of our keys here (extras ignored, not-ours ignored)
        # - not considered fraud because other signers looking at PSBT may have them
        # - user will see them as normal outputs, which they are.
        if ours == None:
            return

        expect_pubkey = ours[0]

        # - must match expected address for this output, coming from unsigned txn
        addr_type, addr_or_pubkey, is_segwit = txo.get_address()

        if addr_type == 'p2pk':
            # output is public key (not a hash, much less common)
            assert len(addr_or_pubkey) == 33

            if addr_or_pubkey != expect_pubkey:
                raise FraudulentChangeOutput("Output#%d: P2PK change output is fraudulent" 
                                                            % out_idx)

            self.is_change = ours
            return

        # Figure out what the hashed addr should be
        pkh = None

        if addr_type == 'p2sh':
            # P2SH or Multisig output
            # We must have the witness & redeem script already (else fail)
            if not self.redeem_script:
                # perhaps an omission, so let's not call fraud on it
                raise AssertionError("Missing redeem script for output #%d" % out_idx)

            redeem_script = self.get(self.redeem_script)

            if not is_segwit and \
                    len(redeem_script) == 22 and \
                    redeem_script[0] == 0 and redeem_script[1] == 20:

                # it's actually segwit p2pkh inside p2sh
                pkh = redeem_script[2:22]
            else:
                # Multisig change output, we're supposed to be a part of.
                # - our key must be part of it
                # - must look like input side redeem script
                # - assert M/N structure of output to match any inputs we have signed in PSBT!
                # - assert all provided pubkeys are in redeem script, not just ours
                # - XXX redo this
                if expect_pubkey not in redeem_script:
                    raise FraudulentChangeOutput("Output#%d: P2WSH/P2SH change output missing my pubkey" % out_idx)

            if is_segwit:
                # p2wsh case
                # - need witness script and check it's hash against proposed p2wsh value
                assert len(addr_or_pubkey) == 32
                expect_wsh = tcc.sha256(self.witness_script).digest()
                if expect_wsh != addr_or_pubkey:
                    raise FraudulentChangeOutput("Output#%d: P2WSH witness script has wrong hash" % out_idx)

                self.is_change = ours
                return

            else:
                # old BIP16 style; looks like payment addr
                pkh = hash160(redeem_script)

        elif addr_type == 'p2pkh':
            # input is hash160 of a single public key
            assert len(addr_or_pubkey) == 20
            pkh = addr_or_pubkey
        else:
            # we don't know how to "solve" this type of input
            return

        expect_pkh = hash160(expect_pubkey)
        if pkh != expect_pkh:
            raise FraudulentChangeOutput("Output#%d: P2PKH change output is fraudulent" % out_idx)

        # store pubkey value for later validation
        self.is_change = ours


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
                    'redeem_script', 'witness_script', 'our_keys', 'fully_signed',
                    'is_segwit', 'is_multisig', 'is_p2sh',
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

        #self.our_keys = None

        # things we've learned
        #self.fully_signed = False

        # we can't really learn this until we take apart the UTXO's scriptPubKey
        #self.is_segwit = None
        #self.is_multisig = None
        #self.is_p2sh = False

        #self.required_key = None
        #self.scriptSig = None
        #self.amount = None
        #self.scriptCode = None      # only expected for segwit inputs

        # after signing, we'll have a signature to add to output PSBT
        #self.added_sig = None

        self.parse(fd)

    def validate(self, idx, txin, my_xfp):
        # Validate this txn input: given deserialized CTxIn and maybe witness

        # TODO: tighten these
        if self.witness_script:
            assert self.witness_script[1] >= 30
        if self.redeem_script:
            assert self.redeem_script[1] >= 22

        # require path for each addr, check some are ours

        if self.our_keys is None:        # can only do once
            self.our_keys = self.parse_subpaths(my_xfp)

        # sighash, but we're probably going to ignore anyway.
        self.sighash = SIGHASH_ALL if self.sighash is None else self.sighash

        if self.part_sig:
            # How complete is the set of signatures so far?
            # - assuming PSBT creator doesn't give us extra data not required
            # - seem harmless if they fool us into thinking already signed; we do nothing
            # - could also look at pubkey needed vs. sig provided
            # - could consider structure of MofN in p2sh cases
            self.fully_signed = (len(self.part_sig) >= len(self.subpaths))
        else:
            # No signatures at all yet for this input (typical non multisig)
            self.fully_signed = False

        if not self.fully_signed:
            if not self.subpaths:
                raise FatalPSBTIssue('We require subpaths to be specified in the PSBT')

            if self.sighash != SIGHASH_ALL:
                raise FatalPSBTIssue('Can only do SIGHASH_ALL')

        if self.utxo:
            # Important: they might be trying to trick us with an un-related
            # funding transaction (UTXO) that does not match the input signature we're making
            # (but if it's segwit, the ploy wouldn't work, Segwit FtW)
            # - challenge: it's a straight dsha256() for old serializations, but not for newer
            #   segwit txn's... plus I don't want to deserialize it here.
            observed = uint256_from_str(self.calc_txid(self.utxo))
            assert txin.prevout.hash == observed, "utxo hash mismatch for input #%d" % idx

    def calc_txid(self, poslen):
        # Given the (pos,len) of a transaction, return the txid for that.
        # - doesn't validate data
        # - does detected witness txn vs. old style
        # - simple dsha256() if old style txn, otherwise witness data must be skipped

        # see if witness encoding in effect
        fd = self.fd
        fd.seek(poslen[0])

        txn_version, marker, flags = unpack("<iBB", fd.read(6))
        has_witness = (marker == 0 and flags != 0x0)

        if not has_witness:
            # txn does not have witness data, so txid==wtxix
            return self.get_hash256(poslen)

        rv = tcc.sha256()

        # de/reserialize much of the txn -- but not the witness data
        rv.update(pack("<i", txn_version))

        body_start = fd.tell()

        # determine how long ins + outs are...
        num_in = deser_compact_size(fd)
        _skip_n_objs(fd, num_in, 'CTxIn')
        num_out = deser_compact_size(fd)
        _skip_n_objs(fd, num_out, 'CTxOut')

        body_len = fd.tell() - body_start

        # hash the bulk of txn
        self.get_hash256((body_start, body_len), hasher=rv)

        # assume last 4 bytes are the lock_time
        fd.seek(sum(poslen) - 4)

        rv.update(fd.read(4))

        return tcc.sha256(rv.digest()).digest()

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


    def determine_my_signing_key(self, my_idx, utxo, my_xfp):
        # See what it takes to sign this particular input
        # - type of script
        # - which pubkey needed
        # - scriptSig value
        # - also validates redeem_script when present
        addr_type, addr_or_pubkey, addr_is_segwit = utxo.get_address()

        which_key = None
        self.is_multisig = False
        self.is_p2sh = False
        self.amount = utxo.nValue

        if addr_is_segwit and not self.is_segwit:
            self.is_segwit = True

        if addr_type == 'p2sh':
            # multisig input
            self.is_p2sh = True

            # we must have the redeem script already (else fail)
            if not self.redeem_script:
                raise AssertionError("missing redeem script for in #%d" % my_idx)

            redeem_script = self.get(self.redeem_script)
            self.scriptSig = ser_string(redeem_script)

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
                        # already signed, so ignore
                        continue

                    if path[0] == my_xfp:
                        which_key = pubkey
                        break

            if not addr_is_segwit and \
                    len(redeem_script) == 22 and \
                    redeem_script[0] == 0 and redeem_script[1] == 20:
                # it's actually segwit p2pkh inside p2sh
                addr_type = 'p2wpkh-p2sh'
                addr = redeem_script[2:22]
                self.is_segwit = True
            else:
                # multiple keys involved, we probably can't do the finalize step
                self.is_multisig = True

        elif addr_type == 'p2pkh':
            # input is hash160 of a single public key
            self.scriptSig = utxo.scriptPubKey
            addr = addr_or_pubkey

            for pubkey in self.subpaths:
                if hash160(pubkey) == addr:
                    which_key = pubkey
                    break

        elif addr_type == 'p2pk':
            # input is single public key (less common)
            self.scriptSig = utxo.scriptPubKey
            assert len(addr_or_pubkey) == 33

            if addr_or_pubkey in self.subpaths:
                which_key = addr_or_pubkey

        else:
            # we don't know how to "solve" this type of input
            pass

        if not which_key:
            print("no key: input #%d: type=%s segwit=%d a_or_pk=%s scriptPubKey=%s" % (
                    my_idx, addr_type, self.is_segwit,
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
                # Segwit P2SH segwit. We need the script!
                if not self.witness_script:
                    raise AssertionError('Need witness script for input #%d' % my_idx)

                self.scriptCode = self.get(self.witness_script)

        # Could probably free self.subpaths and self.redeem_script now, but only if we don't
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

        self.txn = None


        # some don't need/want key (just a single value)

        from main import settings, dis
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

        self.warnings = []

    def store(self, kt, key, val):
        # capture the values we care about

        if kt == PSBT_GLOBAL_UNSIGNED_TX:
            self.txn = val
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


    def validate(self):
        # Do a first pass over the txn. Raise assertions, be terse tho because
        # these messages are rarely seen. These are syntax/fatal errors.
        #
        assert self.txn[1] > 63, 'too short'

        # this parses the input TXN in-place
        for idx, txin in self.input_iter():
            self.inputs[idx].validate(idx, txin, self.my_xfp)

        assert len(self.inputs) == self.num_inputs, 'ni mismatch'

        assert self.num_outputs >= 1, 'need outs'

        for idx, txo in self.output_iter():
            self.outputs[idx].validate(idx, txo, self.my_xfp)

        our_keys = sum(i.our_keys for i in self.inputs)

        print("PSBT: %d inputs, %d output, %d fully-signed, %d ours" % (
                   self.num_inputs, self.num_outputs,
                   sum(1 for i in self.inputs if i and i.fully_signed), our_keys))

    def consider_outputs(self):
        # scan ouputs:
        # - is it a change address, defined by redeem script (p2sh) or key we know is ours
        # - mark change outputs, so perhaps we don't show them to users

        if self.total_value_out is None:
            # this happens, but would expect this to have done already?
            for out_idx, txo in self.output_iter():
                pass

        # check fee is reasonable
        if self.total_value_out == 0:
            per_fee = 100
        else:
            per_fee = self.calculate_fee() * 100 / self.total_value_out

        from main import settings
        fee_limit = settings.get('fee_limit', DEFAULT_MAX_FEE_PERCENTAGE)

        if fee_limit != -1 and per_fee >= fee_limit:
            raise FatalPSBTIssue("Network fee bigger than %d%% of total amount (it is %.0f%%)."
                                % (fee_limit, per_fee))
        if per_fee >= 5:
            self.warnings.append(('Big Fee', 'Network fee is more than '
                                    '5%% of total value (%.1f%%).' % per_fee))

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
            inp.determine_my_signing_key(i, utxo, self.my_xfp)

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
            self.warnings.append(('Missing Keys',
                'We do not know the keypair for some inputs: %r' % list(no_keys)))

        if self.presigned_inputs:
            # this isn't really even an issue for some complex usage cases
            self.warnings.append(('Partly Signed Already',
                'Some input(s) provided were already signed by another party: %r'
                                % list(self.presigned_inputs)))

    def calculate_fee(self):
        # what miner's reward is included in txn?
        if self.total_value_in is None:
            return None
        return self.total_value_in - self.total_value_out

    def consider_keys(self):
        # check we process the right keys for the inputs
        # - check our derivation leads to same pubkey?
        cnt = sum(i.our_keys for i in self.inputs)
        if not cnt:
            raise FatalPSBTIssue('None of the keys involved in this transaction '
                                        'belong to this Coldcard (expect 0x%08x).' % self.my_xfp)

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
            # - means we are also a combiner in this case
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

        if self.unknown:
            for k in self.unknown:
                wr(k[0], self.unknown[k], k[1:])

        # sep between globals in inputs
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
        from main import dis

        with stash.SensitiveValues() as sv:
            # Double check the change outputs are right. This is slow, but critical because
            # it detects bad actors, not bugs or mistakes.
            change_paths = [(n, o.is_change) for n,o in enumerate(self.outputs) if o.is_change]
            if change_paths:
                dis.fullscreen('Change Check...')

                for out_idx, (pubkey, subpath) in change_paths:
                    dis.progress_bar_show(out_idx / len(change_paths))

                    skp = path_to_str(subpath)
                    node = sv.derive_path(skp)

                    # check the pubkey of this BIP32 node
                    pu = node.public_key()
                    if pu != pubkey:
                        raise FraudulentChangeOutput(
                                  "Deception regarding change output #%d. "
                                  "BIP32 path doesn't match actual address." % out_idx)

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

                which_key = inp.required_key
                assert not inp.added_sig, "already done??"
                assert which_key in inp.subpaths, 'unk key'

                if inp.subpaths[which_key][0] != self.my_xfp:
                    # we don't have the key for this subkey
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

                # Do the ACTUAL signature ... finally!!!
                skp = path_to_str(inp.subpaths[which_key])
                node = sv.derive_path(skp, register=False)

                pk = node.private_key()

                # expensive test, but works... and important
                pu = node.public_key()
                assert pu == which_key, "Path (%s) led to wrong pubkey for input#%d"%(skp, in_idx)

                #print("privkey %s" % b2a_hex(pk).decode('ascii'))
                #print(" pubkey %s" % b2a_hex(which_key).decode('ascii'))
                #print(" digest %s" % b2a_hex(digest).decode('ascii'))

                result = tcc.secp256k1.sign(pk, digest)

                # private key no longer required
                stash.blank_object(pk)
                stash.blank_object(node)
                del pk, node, pu, skp

                #print("result %s" % b2a_hex(result).decode('ascii'))

                # convert signature to DER format
                assert len(result) == 65
                r = result[1:33]
                s = result[33:65]

                inp.added_sig = (which_key, ser_sig_der(r, s, inp.sighash))

                success.add(in_idx)

                # memory cleanup
                del result, r, s

                gc.collect()

        if len(success) != self.num_inputs:
            print("Wasn't able to sign input(s): %s" %
                            ', '.join('#'+str(i) for i in set(range(self.num_inputs)) - success))

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
        rv = tcc.sha256()

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

        assert sighash_type == SIGHASH_ALL, "only SIGHASH_ALL supported"
        # SIGHASH_ALL==1 value
        rv.update(b'\x01\x00\x00\x00')

        fd.seek(old_pos)

        # double SHA256
        return tcc.sha256(rv.digest()).digest()

    def make_txn_segwit_sighash(self, replace_idx, replacement, amount, scriptCode, sighash_type):
        # Implement BIP 143 hashing algo for signature of segwit programs.
        # see <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
        #

        fd = self.fd
        old_pos = fd.tell()

        assert sighash_type == SIGHASH_ALL, "only SIGHASH_ALL supported"

        if self.hashPrevouts is None:
            # First time thru, we'll need to hash up this stuff.

            po = tcc.sha256()
            sq = tcc.sha256()

            # input side
            for in_idx, txi in self.input_iter():
                po.update(txi.prevout.serialize())
                sq.update(pack("<I", txi.nSequence))

            self.hashPrevouts = tcc.sha256(po.digest()).digest()
            self.hashSequence = tcc.sha256(sq.digest()).digest()

            del po, sq, txi

            # output side
            ho = tcc.sha256()
            for out_idx, txo in self.output_iter():
                ho.update(txo.serialize())

            self.hashOutputs = tcc.sha256(ho.digest()).digest()

            del ho, txo
            gc.collect()

            #print('hPrev: %s' % str(b2a_hex(self.hashPrevouts), 'ascii'))
            #print('hSeq : %s' % str(b2a_hex(self.hashSequence), 'ascii'))
            #print('hOuts: %s' % str(b2a_hex(self.hashOutputs), 'ascii'))

        rv = tcc.sha256()

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
        return tcc.sha256(rv.digest()).digest()

    def is_complete(self):
        # Are all the inputs (now) signed?

        # some might have been given as signed
        signed = set(self.presigned_inputs)

        # plus we added some signatures
        for i in range(self.num_inputs):
            if self.inputs[i] and self.inputs[i].added_sig:
                signed.add(i)

        return len(signed) == self.num_inputs

    def finalize(self, fd):
        # Stream out the finalized transaction, with signatures applied
        # - assumption is it's complete already.

        fd.write(pack('<i', self.txn_version))           # nVersion

        # does this txn require witness data to be included?
        # - yes, if the original txn had some
        # - yes, if we did a segwit signature on any input
        needs_witness = self.had_witness or any(i.is_segwit for i in self.inputs if i)

        if needs_witness:
            # zero marker, and flags=0x01
            fd.write(b'\x00\x01')

        # inputs
        fd.write(ser_compact_size(self.num_inputs))
        for in_idx, txi in self.input_iter():
            inp = self.inputs[in_idx]

            if inp.is_segwit:

                if inp.is_p2sh:
                    # multisig (p2sh) segwit still requires the script here.
                    txi.scriptSig = inp.scriptSig
                else:
                    # major win for segwit (p2pkh): no redeem script bloat anymore
                    txi.scriptSig = b''

                # NOTE: Actual signature will be in witness data area

            elif inp.added_sig:
                # insert the new signature(s)

                pubkey, der_sig = inp.added_sig

                s = b''
                if not inp.is_multisig:
                    s += ser_push_data(der_sig)
                    s += ser_push_data(pubkey)
                else:
                    assert False, 'Multisig PSBT combine not supported'

                txi.scriptSig = s

            fd.write(txi.serialize())

        # outputs
        fd.write(ser_compact_size(self.num_outputs))
        for out_idx, txo in self.output_iter():
            fd.write(txo.serialize())

        if needs_witness:
            # witness values
            # - preserve any given ones, add ours
            for in_idx, wit in self.input_witness_iter():
                inp = self.inputs[in_idx]

                if inp.is_segwit and inp.added_sig:
                    # put in new sig: wit is a CTxInWitness
                    assert not wit.scriptWitness.stack, 'replacing non-empty?'

                    pubkey, der_sig = inp.added_sig
                    if not inp.is_multisig:
                        assert pubkey[0] in {0x02, 0x03} and len(pubkey) == 33, "bad v0 pubkey"
                        wit.scriptWitness.stack = [der_sig, pubkey]
                    else:
                        assert False, 'Multisig PSBT combine not supported'

                fd.write(wit.serialize())

        # locktime
        fd.write(pack('<I', self.lock_time))


# EOF
