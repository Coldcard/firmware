# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# multisig.py - support code for multisig signing and p2sh in general.
#
import stash, chains, ustruct, ure, uio, sys
#from ubinascii import hexlify as b2a_hex
from utils import xfp2str, str2xfp, swab32, cleanup_deriv_path
from ux import ux_show_story, ux_confirm, ux_dramatic_pause, ux_clear_keys
from files import CardSlot, CardMissingError
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AFC_SCRIPT, MAX_PATH_DEPTH
from menu import MenuSystem, MenuItem
from opcodes import OP_CHECKMULTISIG
from actions import needs_microsd

# Bitcoin limitation: max number of signatures in CHECK_MULTISIG
# - 520 byte redeem script limit <= 15*34 bytes per pubkey == 510 bytes 
MAX_SIGNERS = const(15)

# PSBT Xpub trust policies
TRUST_VERIFY = const(0)
TRUST_OFFER = const(1)
TRUST_PSBT = const(2)

class MultisigOutOfSpace(RuntimeError):
    pass

def disassemble_multisig_mn(redeem_script):
    # pull out just M and N from script. Simple, faster, no memory.

    assert MAX_SIGNERS == 15
    assert redeem_script[-1] == OP_CHECKMULTISIG, 'need CHECKMULTISIG'

    M = redeem_script[0] - 80
    N = redeem_script[-2] - 80

    return M, N

def disassemble_multisig(redeem_script):
    # Take apart a standard multisig's redeem/witness script, and return M/N and public keys
    # - only for multisig scripts, not general purpose
    # - expect OP_1 (pk1) (pk2) (pk3) OP_3 OP_CHECKMULTISIG for 1 of 3 case
    # - returns M, N, (list of pubkeys)
    # - for very unlikely/impossible asserts, dont document reason; otherwise do.
    from serializations import disassemble

    M, N = disassemble_multisig_mn(redeem_script)
    assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
    assert len(redeem_script) == 1 + (N * 34) + 1 + 1, 'bad len'

    # generator function
    dis = disassemble(redeem_script)

    # expect M value first
    ex_M, opcode =  next(dis)
    assert ex_M == M and opcode == None, 'bad M'

    # need N pubkeys
    pubkeys = []
    for idx in range(N):
        data, opcode = next(dis)
        assert opcode == None and len(data) == 33, 'data'
        assert data[0] == 0x02 or data[0] == 0x03, 'Y val'
        pubkeys.append(data)

    assert len(pubkeys) == N

    # next is N value
    ex_N, opcode = next(dis)
    assert ex_N == N and opcode == None

    # finally, the opcode: CHECKMULTISIG
    data, opcode = next(dis)
    assert opcode == OP_CHECKMULTISIG

    # must have reached end of script at this point
    try:
        next(dis)
        raise AssertionError("too long")
    except StopIteration:
        # expected, since we're reading past end
        pass

    return M, N, pubkeys

class MultisigWallet:
    # Capture the info we need to store long-term in order to participate in a
    # multisig wallet as a co-signer.
    # - can be saved to nvram
    # - can be imported from a simple text file
    # - can be displayed to user in a menu (and deleted)
    # - required during signing to verify change outputs
    # - can reconstruct any redeem script from this
    # Challenges:
    # - can be big, taking big % of 4k storage in nvram
    # - complex object, want to have flexibility going forward
    FORMAT_NAMES = [
        (AF_P2SH, 'p2sh'),
        (AF_P2WSH, 'p2wsh'),
        (AF_P2WSH_P2SH, 'p2wsh-p2sh'),
    ]
    # regexes for parsing multisig descriptors
    DESCRIPTOR_REGEXES = [
        (AF_P2SH, r"^sh\(sortedmulti\((\d+),(\S+)\)\)$"),
        (AF_P2WSH_P2SH, r"^sh\(wsh\(sortedmulti\((\d+),(\S+)\)\)\)$"),
        (AF_P2WSH, r"^wsh\(sortedmulti\((\d+),(\S+)\)\)$")
    ]

    def __init__(self, name, m_of_n, xpubs, addr_fmt=AF_P2SH, common_prefix=None, chain_type='BTC'):
        self.storage_idx = -1

        self.name = name
        assert len(m_of_n) == 2
        self.M, self.N = m_of_n
        self.chain_type = chain_type or 'BTC'
        self.xpubs = xpubs                  # list of (xfp(int), xpub(str))
        self.common_prefix = common_prefix  # example: "45'" for BIP45 .. no m/ prefix
        self.addr_fmt = addr_fmt            # not clear how useful that is.

        # useful cache value
        self.xfps = sorted(k for k,v in self.xpubs)

    @classmethod
    def render_addr_fmt(cls, addr_fmt):
        for k, v in cls.FORMAT_NAMES:
            if k == addr_fmt:
                return v.upper()
        return '?'

    def serialize(self):
        # return a JSON-able object

        opts = dict()
        if self.addr_fmt != AF_P2SH:
            opts['ft'] = self.addr_fmt
        if self.chain_type != 'BTC':
            opts['ch'] = self.chain_type
        if self.common_prefix:
            opts['pp'] = self.common_prefix

        return (self.name, (self.M, self.N), self.xpubs, opts)

    @property
    def chain(self):
        return chains.get_chain(self.chain_type)

    @classmethod
    def get_trust_policy(cls):
        from main import settings

        which = settings.get('pms', None)

        if which is None:
            which = TRUST_VERIFY if cls.exists() else TRUST_OFFER

        return which

    @classmethod
    def deserialize(cls, vals, idx=-1):
        # take json object, make instance.
        name, m_of_n, xpubs, opts = vals

        rv = cls(name, m_of_n, xpubs, addr_fmt=opts.get('ft', AF_P2SH),
                                    common_prefix=opts.get('pp', None),
                                    chain_type=opts.get('ch', 'BTC'))
        rv.storage_idx = idx

        return rv

    @classmethod
    def find_match(cls, M, N, fingerprints):
        # Find index of matching wallet. Don't de-serialize everything.
        # - returns index, or -1 if not found
        # - fingerprints are iterable of uint32's: may not be unique!
        # - M, N must be known.
        from main import settings
        lst = settings.get('multisig', [])

        fingerprints = sorted(fingerprints)
        assert N == len(fingerprints)
        
        for idx, rec in enumerate(lst):
            name, m_of_n, xpubs, opts = rec
            if tuple(m_of_n) != (M, N): continue
            if sorted(f for f,_ in xpubs) != fingerprints: continue
            return idx

        return -1

    @classmethod
    def find_candidates(cls, fingerprints):
        # Find index of matching wallet and M value. Don't de-serialize everything.
        # - returns set of matches, each with M value
        # - fingerprints are iterable of uint32's
        from main import settings
        lst = settings.get('multisig', [])

        fingerprints = sorted(fingerprints)
        N = len(fingerprints)
        rv = []
        
        for idx, rec in enumerate(lst):
            name, m_of_n, xpubs, opts = rec
            if m_of_n[1] != N: continue
            if sorted(f for f,_ in xpubs) != fingerprints: continue

            rv.append(idx)

        return rv

    def assert_matching(self, M, N, fingerprints):
        # compare in-memory wallet with details recovered from PSBT
        assert (self.M, self.N) == (M, N), "M/N mismatch"
        assert len(fingerprints) == N, "XFP count"
        assert sorted(fingerprints) == self.xfps, "wrong XFPs"

    @classmethod
    def quick_check(cls, M, N, xfp_xor):
        # quicker USB method.
        from main import settings
        lst = settings.get('multisig', [])

        rv = []
        for rec in lst:
            name, m_of_n, xpubs, opts = rec
            if m_of_n[0] != M: continue
            if m_of_n[1] != N: continue

            x = 0
            for xfp, _ in xpubs:
                x ^= xfp
            if x != xfp_xor: continue

            return True

        return False

    @classmethod
    def get_all(cls):
        # return them all, as a generator
        from main import settings

        lst = settings.get('multisig', [])

        for idx, v in enumerate(lst):
            yield cls.deserialize(v, idx)

    @classmethod
    def exists(cls):
        # are there any wallets defined?
        from main import settings
        return bool(settings.get('multisig', False))

    @classmethod
    def get_by_idx(cls, nth):
        # instance from index number
        from main import settings
        lst = settings.get('multisig', [])
        try:
            obj = lst[nth]
        except IndexError:
            return None

        return cls.deserialize(obj, nth)

    def commit(self):
        # data to save
        # - important that this fails immediately when nvram overflows
        from main import settings

        obj = self.serialize()

        v = settings.get('multisig', [])
        orig = v.copy()
        if not v or self.storage_idx == -1:
            # create
            self.storage_idx = len(v)
            v.append(obj)
        else:
            # update: no provision for changing fingerprints
            assert sorted(k for k,v in v[self.storage_idx][2]) == self.xfps
            v[self.storage_idx] = obj

        settings.set('multisig', v)

        # save now, rather than in background, so we can recover
        # from out-of-space situation
        try:
            settings.save()
        except:
            # back out change; no longer sure of NVRAM state
            try:
                settings.set('multisig', orig)
                settings.save()
            except: pass        # give up on recovery

            raise MultisigOutOfSpace


    def has_dup(self):
        # check if we already have a saved duplicate to this proposed wallet
        # - also, flag if it's a dangerous/fraudulent attempt to replace it.

        idx = MultisigWallet.find_match(self.M, self.N, self.xfps)
        if idx == -1:
            # no matches
            return False, 0

        # See if the xpubs are changing, which is risky... other differences like
        # name are okay.
        o = self.get_by_idx(idx)

        # Calc apx. number of xpub changes.
        diffs = 0
        a = sorted(self.xpubs)
        b = sorted(o.xpubs)
        assert len(a) == len(b)         # because same N
        for idx in range(self.N):
            if a[idx] != b[idx]:
                diffs += 1

        return o, diffs

    def delete(self):
        # remove saved entry
        # - important: not expecting more than one instance of this class in memory
        from main import settings

        assert self.storage_idx >= 0

        # safety check
        expect_idx = self.find_match(self.M, self.N, self.xfps)
        assert expect_idx == self.storage_idx

        lst = settings.get('multisig', [])
        del lst[self.storage_idx]
        settings.set('multisig', lst)
        settings.save()

        self.storage_idx = -1

    def xpubs_with_xfp(self, xfp):
        # return set of indexes of xpubs with indicated xfp
        return set(xp_idx for xp_idx, (wxfp, _) in enumerate(self.xpubs)
                        if wxfp == xfp)

    def validate_script(self, redeem_script, subpaths=None, xfp_paths=None):
        # Check we can generate all pubkeys in the redeem script, raise on errors.
        # - working from pubkeys in the script, because duplicate XFP can happen
        #
        # redeem_script: what we expect and we were given
        # subpaths: pubkey => (xfp, *path)
        # xfp_paths: (xfp, *path) in same order as pubkeys in redeem script
        from psbt import path_to_str

        subpath_help = []
        used = set()
        ch = self.chain

        M, N, pubkeys = disassemble_multisig(redeem_script)
        assert M==self.M and N == self.N, 'wrong M/N in script'

        for pk_order, pubkey in enumerate(pubkeys):
            check_these = []

            if subpaths:
                # in PSBT, we are given a map from pubkey to xfp/path, use it
                # while remembering it's potentially one-2-many
                assert pubkey in subpaths, "unexpected pubkey"
                xfp, *path = subpaths[pubkey]

                for xp_idx, (wxfp, xpub) in enumerate(self.xpubs):
                    if wxfp != xfp: continue
                    if xp_idx in used: continue      # only allow once
                    check_these.append((xp_idx, path))
            else:
                # Without PSBT, USB caller must provide xfp+path
                # in same order as they occur inside redeem script.
                # Working solely from the redeem script's pubkeys, we
                # wouldn't know which xpub to use, nor correct path for it.
                xfp, *path = xfp_paths[pk_order]

                for xp_idx in self.xpubs_with_xfp(xfp):
                    if xp_idx in used: continue      # only allow once
                    check_these.append((xp_idx, path))

            here = None
            too_shallow = False
            for xp_idx, path in check_these:
                # matched fingerprint, try to make pubkey that needs to match
                xpub = self.xpubs[xp_idx][1]

                node = ch.deserialize_node(xpub, AF_P2SH); assert node
                dp = node.depth()

                if not (0 <= dp <= len(path)):
                    # obscure case: xpub isn't deep enough to represent
                    # indicated path... not wrong really.
                    too_shallow = True
                    continue

                for sp in path[dp:]:
                    assert not (sp & 0x80000000), 'hard deriv'
                    node.derive(sp)     # works in-place

                found_pk = node.public_key()

                # Document path(s) used. Not sure this is useful info to user tho.
                # - Do not show what we can't verify: we don't really know the hardeneded
                #   part of the path from fingerprint to here.
                here = '(m=%s)\n' % xfp2str(xfp)
                if dp != len(path):
                    here += 'm' + ('/_'*dp) + path_to_str(path[dp:], '/', 0)

                if found_pk != pubkey:
                    # Not a match but not an error by itself, since might be 
                    # another dup xfp to look at still.

                    #print('pk mismatch: %s => %s != %s' % (
                    #                here, b2a_hex(found_pk), b2a_hex(pubkey)))
                    continue

                subpath_help.append(here)

                used.add(xp_idx)
                break
            else:
                msg = 'pk#%d wrong' % (pk_order+1)
                if not check_these:
                    msg += ', unknown XFP'
                elif here:
                    msg += ', tried: ' + here
                if too_shallow:
                    msg += ', too shallow'
                raise AssertionError(msg)

            if pk_order:
                # verify sorted order
                assert bytes(pubkey) > bytes(pubkeys[pk_order-1]), 'BIP67 violation'

        assert len(used) == self.N, 'not all keys used: %d of %d' % (len(used), self.N)

        return subpath_help

    @classmethod
    def from_descriptor(cls, desc_str, expected_chain, name=None):
        from main import settings
        d = cls.parse_descriptor(desc_str, expected_chain)
        xpubs = []
        common_prefix = None
        has_mine = False
        my_xfp = settings.get('xfp')
        for ko in d["key_origins"]:
            xfp = str2xfp(ko["xfp"])
            xpubs.append( (xfp, ko["xpub"]) )
            if xfp == my_xfp:
                has_mine = True
                common_prefix = ko["derivation"]
        if has_mine == False:
            raise Exception("Descriptor doesn't include our fingerprint.")
        if name is None:
            # provide a default name
            name = '%s Descriptor %d-of-%d' % (d["addr_fmt"], d["M"], d["N"])
        return cls(name, (d["M"], d["N"]), xpubs, addr_fmt=d["addr_fmt"],
                   chain_type=expected_chain, common_prefix=common_prefix)
                                
    
    @classmethod
    def from_file(cls, config, name=None):
        # Given a simple text file, parse contents and create instance (unsaved).
        # format is:         label: value
        # where label is:
        #       name: nameforwallet
        #       policy: M of N
        #       (8digithex): xpub of cosigner
        # 
        # quick checks:
        # - name: 1-20 ascii chars
        # - M of N line (assume N of N if not spec'd)
        # - xpub: any bip32 serialization we understand, but be consistent
        #
        from main import settings

        my_xfp = settings.get('xfp')
        common_prefix = None
        xpubs = []
        path_tops = set()
        M, N = -1, -1
        has_mine = False
        addr_fmt = AF_P2SH
        expect_chain = chains.current_chain().ctype
        descriptor = None

        lines = config.split('\n')

        for ln in lines:
            # remove comments
            comm = ln.find('#')
            if comm != -1:
                ln = ln[0:comm]

            ln = ln.strip()

            if ':' not in ln:
                if 'pub' in ln:
                    # optimization: allow bare xpub if we can calc xfp
                    label = '0'*8
                    value = ln
                else:
                    # complain?
                    if ln: print("no colon: " + ln)
                    continue
            else:
                label, value = ln.split(':')
                label = label.lower()

            value = value.strip()

            if label == 'name':
                name = value
            elif label == 'policy':
                try:
                    # accepts: 2 of 3    2/3    2,3    2 3   etc
                    mat = ure.search(r'(\d+)\D*(\d+)', value)
                    assert mat
                    M = int(mat.group(1))
                    N = int(mat.group(2))
                    assert 1 <= M <= N <= MAX_SIGNERS
                except:
                    raise AssertionError('bad policy line')

            elif label == 'derivation':
                # reveal the **common** path derivation for all keys
                try:
                    cp = cleanup_deriv_path(value)
                    # - not storing "m/" prefix, nor 'm' case which doesn't add any info
                    common_prefix = None if cp == 'm' else cp[2:]
                except BaseException as exc:
                    raise AssertionError('bad derivation line: ' + str(exc))

            elif label == 'format':
                # pick segwit vs. classic vs. wrapped version
                value = value.lower()
                for fmt_code, fmt_label in cls.FORMAT_NAMES:
                    if value == fmt_label:
                        addr_fmt = fmt_code
                        break
                else:
                    raise AssertionError('bad format line')
            elif len(label) == 8:
                try:
                    xfp = str2xfp(label)
                except:
                    # complain?
                    #print("Bad xfp: " + ln)
                    continue

                # deserialize, update list and lots of checks
                xfp = cls.check_xpub(xfp, value, expect_chain, xpubs, path_tops)

                if xfp == my_xfp:
                    # not conclusive, but enough for error catching.
                    has_mine = True
            elif label == 'descriptor':
                # pass
                descriptor = value

        if descriptor:
            return cls.from_descriptor(descriptor, expect_chain, name)

        assert len(xpubs), 'need xpubs'

        if M == N == -1:
            # default policy: all keys
            N = M = len(xpubs)

        if not name:
            # provide a default name
            name = '%d-of-%d' % (M, N)

        try:
            name = str(name, 'ascii')
            assert 1 <= len(name) <= 20
        except:
            raise AssertionError('name must be ascii, 1..20 long')

        assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
        assert N == len(xpubs), 'wrong # of xpubs, expect %d' % N
        assert addr_fmt & AFC_SCRIPT, 'script style addr fmt'

        # check we're included... do not insert ourselves, even tho we
        # have enough info, simply because other signers need to know my xpubkey anyway
        assert has_mine, 'my key not included'

        if not common_prefix and len(path_tops) == 1:
            # fill in the common prefix iff we can deduce it from xpubs
            common_prefix = path_tops.pop()

        # done. have all the parts
        return cls(name, (M, N), xpubs, addr_fmt=addr_fmt,
                        chain_type=expect_chain, common_prefix=common_prefix)

    @classmethod
    def check_xpub(cls, xfp, xpub, expect_chain, xpubs, path_tops):
        # Shared code: consider an xpub for inclusion into a wallet, if ok, append
        # to list: xpubs, and path_tops

        try:
            # Note: addr fmt detected here via SLIP-132 isn't useful
            node, chain, _ = import_xpub(xpub)
        except:
            print(xpub)
            raise AssertionError('unable to parse xpub')

        assert node.private_key() == None, 'no privkeys plz'
        assert chain.ctype == expect_chain, 'wrong chain'

        # NOTE: could enforce all same depth, and/or all depth >= 1, but
        # seems like more restrictive than needed.
        if node.depth() == 1:
            if not xfp:
                # allow a shortcut: zero/omit xfp => use observed parent value
                xfp = swab32(node.fingerprint())
            else:
                # generally cannot check fingerprint values, but if we can, do.
                assert swab32(node.fingerprint()) == xfp, 'xfp depth=1 wrong'

        assert xfp, 'need fingerprint'

        # detect, when possible, if it follows BIP45 ... find the path
        path_top = None
        if node.depth() == 1:
            cn = node.child_num()
            path_top = str(cn & 0x7fffffff)
            if cn & 0x80000000:
                path_top += "'"

        path_tops.add(path_top)

        # serialize xpub w/ BIP32 standard now.
        # - this has effect of stripping SLIP-132 confusion away
        xpubs.append((xfp, chain.serialize_public(node, AF_P2SH)))

        return xfp

    @classmethod
    def parse_descriptor(cls, desc, expected_chain):
        # try matching each type of descriptor
        print("Descriptor to parse: " + desc)
        match = None
        address_fmt = None
        for addr_fmt, pat in DESCRIPTOR_REGEXES:
            match = ure.search(pat, desc)
            if match is not None:
                address_fmt = addr_fmt
                break
        if match is None:
            raise Exception("Invalid or unsupported descriptor type.")
        M = int(match.group(1))
        key_origins_str = match.group(2)
        key_origins = []
        for ko in key_origins_str.split(","):
            key_origins.append(
                cls.parse_key_origin(ko, expected_chain)
            )
        N = len(key_origins)
        if N < M:
            raise Exception("Invalid descriptor: M must be greater than N")
    
        return {
            "addr_fmt": address_fmt,
            "M": M,
            "N": N,
            "key_origins": key_origins
        }

    @classmethod
    def parse_key_origin(cls, ko, expected_chain):
        print("Parsing key origin: " + ko)
        r = { "derivation": None }
        arr = ko.strip().split("]")
        if len(arr) <= 1:
            raise Exception("Invalid key origin")
        derivation = arr[0].replace("h","'").lower()
        xpub = arr[1]
        if derivation[0] != "[":
            raise Exception("Origin missing leading [")
        arr = derivation[1:].split("/")
        pat = r"^[a-fA-F0-9]*$"
        match = ure.search(pat, arr[0])
        if match is None:
            raise Exception("Fingerprint is not hex")
        if len(arr[0]) != 8:
            raise Exception("Incorrect fingerprint length")
        r["xfp"] = arr[0].upper()
        global_hardened = True
        for der in arr[1:]:
            if der[-1] == "'":
                if global_hardened == False:
                    raise Exception("Invalid key origin: cannot derive hardened child from non-hardened parent")
                der = der[:-1]
            else:
                global_hardened = False
            try:
                i = int(der)
            except:
                raise Exception("Bad index in key origin derivation.")
        r["derivation"] = "/".join(arr[1:])
        # check xpub
        xpubs = []
        print(xpub, expected_chain)
        print(r["xfp"], xpub)
        cls.check_xpub(r["xfp"], xpub, expected_chain, xpubs, set())
        _, xpub = xpubs.pop()
        r["xpub"] = xpub
        r["string"] = ko
        return r

    def make_fname(self, prefix, suffix='txt'):
        rv = '%s-%s.%s' % (prefix, self.name, suffix)
        return rv.replace(' ', '_')

    async def export_electrum(self):
        # Generate and save an Electrum JSON file.
        from export import make_json_wallet

        def doit():
            rv = dict(seed_version=17, use_encryption=False,
                        wallet_type='%dof%d' % (self.M, self.N))

            ch = self.chain

            # the important stuff.
            for idx, (xfp, xpub) in enumerate(self.xpubs): 

                if self.addr_fmt != AF_P2SH:
                    # CHALLENGE: we must do slip-132 format [yz]pubs here when not p2sh mode.
                    node = ch.deserialize_node(xpub, AF_P2SH); assert node
                    xp = ch.serialize_public(node, self.addr_fmt)
                else:
                    xp = xpub

                rv['x%d/' % (idx+1)] = dict(
                                hw_type='coldcard', type='hardware',
                                ckcc_xfp=xfp,
                                label='Coldcard %s' % xfp2str(xfp),
                                derivation='m/'+self.common_prefix, xpub=xp)

            return rv
            
        await make_json_wallet('Electrum multisig wallet', doit,
                                    fname_pattern=self.make_fname('el', 'json'))

    async def export_wallet_file(self, mode="exported from", extra_msg=None):
        # create a text file with the details; ready for import to next Coldcard
        from main import settings
        my_xfp = xfp2str(settings.get('xfp'))

        fname_pattern = self.make_fname('export')

        try:
            with CardSlot() as card:
                fname, nice = card.pick_filename(fname_pattern)

                # do actual write
                with open(fname, 'wt') as fp:
                    print("# Coldcard Multisig setup file (%s %s)\n#" % (mode, my_xfp), file=fp)
                    self.render_export(fp)

            msg = '''Coldcard multisig setup file written:\n\n%s''' % nice
            if extra_msg:
                msg += extra_msg

            await ux_show_story(msg)

        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story('Failed to write!\n\n\n'+str(e))
            return

    def render_export(self, fp):
        print("Name: %s\nPolicy: %d of %d" % (self.name, self.M, self.N), file=fp)

        if self.common_prefix:
            print("Derivation: m/%s" % self.common_prefix, file=fp)

        if self.addr_fmt != AF_P2SH:
            print("Format: " + self.render_addr_fmt(self.addr_fmt), file=fp)

        print("", file=fp)

        for xfp, val in self.xpubs:
            print('%s: %s' % (xfp2str(xfp), val), file=fp)

    @classmethod
    def import_from_psbt(cls, M, N, xpubs_list):
        # given the raw data fro PSBT global header, offer the user
        # the details, and/or bypass that all and just trust the data.
        # - xpubs_list is a list of (xfp+path, binary BIP32 xpub)
        # - already know not in our records.
        from main import settings
        import tcc

        trust_mode = cls.get_trust_policy()

        if trust_mode == TRUST_VERIFY:
            # already checked for existing import and wasn't found, so fail
            raise AssertionError("XPUBs in PSBT do not match any existing wallet")

        # build up an in-memory version of the wallet.

        assert N == len(xpubs_list)
        assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
        my_xfp = settings.get('xfp')

        expect_chain = chains.current_chain().ctype
        xpubs = []
        has_mine = False
        path_tops = set()

        for k, v in xpubs_list:
            xfp, *path = ustruct.unpack_from('<%dI' % (len(k)/4), k, 0)
            xpub = tcc.codecs.b58_encode(v)
            xfp = cls.check_xpub(xfp, xpub, expect_chain, xpubs, path_tops)
            if xfp == my_xfp:
                has_mine = True

        assert has_mine, 'my key not included'

        name = 'PSBT-%d-of-%d' % (M, N)

        prefix = path_tops.pop() if len(path_tops) == 1 else None

        ms = cls(name, (M, N), xpubs, chain_type=expect_chain, common_prefix=prefix)

        # may just keep just in-memory version, no approval required, if we are
        # trusting PSBT's today, otherwise caller will need to handle UX w.r.t new wallet
        return ms, (trust_mode != TRUST_PSBT)

    async def confirm_import(self):
        # prompt them about a new wallet, let them see details and then commit change.
        M, N = self.M, self.N

        if M == N == 1:
            exp = 'The one signer must approve spends.'
        if M == N:
            exp = 'All %d co-signers must approve spends.' % N
        elif M == 1:
            exp = 'Any signature from %d co-signers will approve spends.' % N
        else:
            exp = '{M} signatures, from {N} possible co-signers, will be required to approve spends.'.format(M=M, N=N)

        # Look for duplicate case.
        is_dup, diff_count = self.has_dup()

        if not is_dup:
            story = 'Create new multisig wallet?'
        elif diff_count:
            story = '''\
CAUTION: This updated wallet has %d different XPUB values, but matching fingerprints \
and same M of N. Perhaps the derivation path has changed legitimately, otherwise, much \
DANGER!''' % diff_count
        else:
            story = 'Update existing multisig wallet?'
        story += '''\n
Wallet Name:
  {name}

Policy: {M} of {N}

{exp}

Derivation:
  m/{deriv}

Press (1) to see extended public keys, \
OK to approve, X to cancel.'''.format(M=M, N=N, name=self.name, exp=exp,
                                        deriv=self.common_prefix or 'unknown')

        ux_clear_keys(True)
        while 1:
            ch = await ux_show_story(story, escape='1')

            if ch == '1':
                # Show the xpubs; might be 2k or more rendered.
                msg = uio.StringIO()

                for idx, (xfp, xpub) in enumerate(self.xpubs):
                    if idx:
                        msg.write('\n\n')

                    # Not showing index numbers here because order
                    # is non-deterministic both here, our storage, and in usage.
                    msg.write('%s:\n%s' % (xfp2str(xfp), xpub))

                await ux_show_story(msg, title='%d of %d' % (self.M, self.N))

                continue

            if ch == 'y':
                # save to nvram, may raise MultisigOutOfSpace
                if is_dup:
                    is_dup.delete()
                self.commit()
                await ux_dramatic_pause("Saved.", 2)
            break

        return ch

async def no_ms_yet(*a):
    # action for 'no wallets yet' menu item
    await ux_show_story("You don't have any multisig wallets yet.")

def psbt_xpubs_policy_chooser():
    # Chooser for trust policy
    ch = [ 'Verify Only', 'Offer Import', 'Trust PSBT']

    def xset(idx, text):
        from main import settings
        settings.set('pms', idx)

    return MultisigWallet.get_trust_policy(), ch, xset

async def trust_psbt_menu(*a):
    # show a story then go into chooser
    from menu import start_chooser

    ch = await ux_show_story('''\
This setting controls what the Coldcard does \
with the co-signer public keys (XPUB) that may \
be provided inside a PSBT file. Three choices:

- Verify Only. Do not import the xpubs found, but do \
verify the correct wallet already exists on the Coldcard.

- Offer Import. If it's a new multisig wallet, offer to import \
the details and store them as a new wallet in the Coldcard.

- Trust PSBT. Use the wallet data in the PSBT as a temporary,
multisig wallet, and do not import it. This permits some \
deniability and additional privacy.

When the XPUB data is not provided in the PSBT, regardless of the above, \
we require the appropriate multisig wallet to already exist \
on the Coldcard. Default is to 'Offer' unless a multisig wallet already \
exists, otherwise 'Verify'.''')

    if ch == 'x': return
    start_chooser(psbt_xpubs_policy_chooser)

class MultisigMenu(MenuSystem):

    @classmethod
    def construct(cls):
        # Dynamic menu with user-defined names of wallets shown
        #from menu import MenuSystem, MenuItem
        from actions import import_multisig

        if not MultisigWallet.exists():
            rv = [MenuItem('(none setup yet)', f=no_ms_yet)]
        else:
            rv = []
            for ms in MultisigWallet.get_all():
                rv.append(MenuItem('%d/%d: %s' % (ms.M, ms.N, ms.name),
                            menu=make_ms_wallet_menu, arg=ms.storage_idx))

        rv.append(MenuItem('Import from SD', f=import_multisig))
        rv.append(MenuItem('Export XPUB', f=export_multisig_xpubs))
        rv.append(MenuItem('Create Airgapped', f=create_ms_step1))
        rv.append(MenuItem('Trust PSBT?', f=trust_psbt_menu))

        return rv

    def update_contents(self):
        # Reconstruct the list of wallets on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)


async def make_multisig_menu(*a):
    # list of all multisig wallets, and high-level settings/actions
    from main import pa

    if pa.is_secret_blank():
        await ux_show_story("You must have wallet seed before creating multisig wallets.")
        return

    rv = MultisigMenu.construct()
    return MultisigMenu(rv)

async def make_ms_wallet_menu(menu, label, item):
    # details, actions on single multisig wallet
    ms = MultisigWallet.get_by_idx(item.arg)
    if not ms: return

    rv = [
        MenuItem('"%s"' % ms.name, f=ms_wallet_detail, arg=ms),
        MenuItem('View Details', f=ms_wallet_detail, arg=ms),

        MenuItem('Delete', f=ms_wallet_delete, arg=ms),
        MenuItem('Coldcard Export', f=ms_wallet_ckcc_export, arg=ms),
        MenuItem('Electrum Wallet', f=ms_wallet_electrum_export, arg=ms),
    ]

    return rv

async def ms_wallet_delete(menu, label, item):
    ms = item.arg

    # delete
    if not await ux_confirm("Delete this multisig wallet (%s)?\n\nFunds may be impacted."
                                                 % ms.name):
        await ux_dramatic_pause('Aborted.', 3)
        return

    ms.delete()
    await ux_dramatic_pause('Deleted.', 3)

    # update/hide from menu
    #menu.update_contents()

    from ux import the_ux
    # pop stack
    the_ux.pop()

    m = the_ux.top_of_stack()
    m.update_contents()

async def ms_wallet_ckcc_export(menu, label, item):
    # create a text file with the details; ready for import to next Coldcard
    ms = item.arg
    await ms.export_wallet_file()

async def ms_wallet_electrum_export(menu, label, item):
    # create a JSON file that Electrum can use. Challenges:
    # - file contains a derivation path that we don't really know.
    # - electrum is using BIP43 with purpose=48 (purpose48_derivation) to make paths like:
    #       m/48'/1'/0'/2'
    # - other signers might not be coldcards (we don't know)
    # solution: 
    # - (much earlier) when exporting, include all the paths needed.
    # - when building air-gap, pick address type at that point, and matching path to suit
    # - require a common prefix path here
    # - could check path prefix and addr_fmt make sense together, but meh.
    ms = item.arg
    from actions import electrum_export_story

    prefix = ms.common_prefix 
    if not prefix :
        return await ux_show_story("We don't know the common derivation path for "
                                        "these keys, so cannot create Electrum wallet.")

    msg = 'The new wallet will have derivation path:\n  %s\n and use %s addresses.\n' % (
            prefix, MultisigWallet.render_addr_fmt(ms.addr_fmt) )

    if await ux_show_story(electrum_export_story(msg)) != 'y':
        return

    await ms.export_electrum()


async def ms_wallet_detail(menu, label, item):
    # show details of single multisig wallet, offer to delete
    import chains

    ms = item.arg
    msg = uio.StringIO()

    msg.write('''
Policy: {M} of {N}
Blockchain: {ctype}
Addresses:
  {at}
'''.format(M=ms.M, N=ms.N, ctype=ms.chain_type,
            at=MultisigWallet.render_addr_fmt(ms.addr_fmt)))

    if ms.common_prefix:
        msg.write('''\
Derivation:
  m/{der}
'''.format(der=ms.common_prefix))

    msg.write('\n')

    # concern: the order of keys here is non-deterministic
    for idx, (xfp, xpub) in enumerate(ms.xpubs):
        if idx:
            msg.write('\n')
        msg.write('%s:\n%s\n' % (xfp2str(xfp), xpub))

    await ux_show_story(msg, title=ms.name)


async def export_multisig_xpubs(*a):
    # WAS: Create a single text file with lots of docs, and all possible useful xpub values.
    # THEN: Just create the one-liner xpub export value they need/want to support BIP45
    # NOW: Export JSON with one xpub per useful address type and semi-standard derivation path
    #
    # Consumer for this file is supposed to be ourselves, when we build on-device multisig.
    #
    from main import settings
    xfp = xfp2str(settings.get('xfp', 0))
    chain = chains.current_chain()
    
    fname_pattern = 'ccxp-%s.json' % xfp

    msg = '''\
This feature creates a small file containing \
the extended public keys (XPUB) you would need to join \
a multisig wallet using the 'Create Airgapped' feature.

The public keys exported are:

BIP45:
   m/45'
P2WSH-P2SH:
   m/48'/{coin}'/0'/1'
P2WSH:
   m/48'/{coin}'/0'/2'

OK to continue. X to abort.
'''.format(coin = chain.b44_cointype)

    resp = await ux_show_story(msg)
    if resp != 'y': return

    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)
            # do actual write: manual JSON here so more human-readable.
            with open(fname, 'wt') as fp:
                fp.write('{\n')
                with stash.SensitiveValues() as sv:
                    for deriv, name, fmt in [
                        ( "m/45'", 'p2sh', AF_P2SH), 
                        ( "m/48'/{coin}'/0'/1'", 'p2wsh_p2sh', AF_P2WSH_P2SH),
                        ( "m/48'/{coin}'/0'/2'", 'p2wsh', AF_P2WSH)
                    ]:

                        dd = deriv.format(coin = chain.b44_cointype)
                        node = sv.derive_path(dd)
                        xp = chain.serialize_public(node, fmt)
                        fp.write('  "%s_deriv": "%s",\n' % (name, dd))
                        fp.write('  "%s": "%s",\n' % (name, xp))

                fp.write('  "xfp": "%s"\n}\n' % xfp)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''BIP45 multisig xpub file written:\n\n%s''' % nice
    await ux_show_story(msg)

def import_xpub(ln):
    # read an xpub/ypub/etc and return BIP32 node and what chain it's on.
    # - can handle any garbage line
    # - returns (node, chain, addr_fmt)
    # - people are using SLIP132 so we need this
    import tcc, chains, ure

    pat = ure.compile(r'.pub[A-Za-z0-9]+')

    found = pat.search(ln)
    if not found:
        return None

    found = found.group(0)

    for ch in chains.AllChains:
        for kk in ch.slip132:
            if found[0] == ch.slip132[kk].hint:
                try:
                    node = tcc.bip32.deserialize(found, ch.slip132[kk].pub, ch.slip132[kk].priv)
                    chain = ch
                    addr_fmt = kk
                    return (node, ch, kk)
                except ValueError:
                    pass

    # looked like one, but fail.
    return None

async def ondevice_multisig_create(mode='p2wsh', addr_fmt=AF_P2WSH):
    # collect all xpub- exports on current SD card (must be > 1)
    # - ask for M value 
    # - create wallet, save and also export 
    # - also create electrum skel to go with that
    # - only expected to work with our ccxp-foo.json export files.
    from actions import file_picker
    import uos, ujson
    from utils import get_filesize
    from main import settings

    chain = chains.current_chain()
    my_xfp = settings.get('xfp')

    xpubs = []
    files = []
    has_mine = False
    deriv = None
    try:
        with CardSlot() as card:
            for path in card.get_paths():
                for fn, ftype, *var in uos.ilistdir(path):
                    if ftype == 0x4000:
                        # ignore subdirs
                        continue

                    if not fn.startswith('ccxp-') or not fn.endswith('.json'):
                        # wrong prefix/suffix: ignore
                        continue

                    full_fname = path + '/' + fn

                    # Conside file size
                    # sigh, OS/filesystem variations
                    file_size = var[1] if len(var) == 2 else get_filesize(full_fname)

                    if not (0 <= file_size <= 1000):
                        # out of range size
                        continue

                    try:
                        with open(full_fname, 'rt') as fp:
                            vals = ujson.load(fp)

                        ln = vals.get(mode)

                        # value in file is BE32, but we want LE32 internally
                        xfp = str2xfp(vals['xfp'])
                        if not deriv:
                            deriv = vals[mode+'_deriv']
                        else:
                            assert deriv == vals[mode+'_deriv'], "wrong derivation"

                        node, _, _ = import_xpub(ln)

                        if xfp == my_xfp:
                            has_mine = True

                        xpubs.append( (xfp, chain.serialize_public(node, AF_P2SH)) )
                        files.append(fn)

                    except CardMissingError:
                        raise

                    except Exception as exc:
                        # show something for coders, but no user feedback
                        sys.print_exception(exc)
                        continue

    except CardMissingError:
        await needs_microsd()
        return

    # remove dups; easy to happen if you double-tap the export
    delme = set()
    for i in range(len(xpubs)):
        for j in range(len(xpubs)):
            if j in delme: continue
            if i == j: continue
            if xpubs[i] == xpubs[j]:
                delme.add(j)
    if delme:
        xpubs = [x for idx,x in enumerate(xpubs) if idx not in delme]

    if not xpubs or len(xpubs) == 1 and has_mine:
        await ux_show_story("Unable to find any Coldcard exported keys on this card. Must have filename: ccxp-....json")
        return
    
    # add myself if not included already
    if not has_mine:
        with stash.SensitiveValues() as sv:
            node = sv.derive_path(deriv)
            xpubs.append( (my_xfp, chain.serialize_public(node, AF_P2SH)) )

    N = len(xpubs)

    if N > MAX_SIGNERS:
        await ux_show_story("Too many signers, max is %d." % MAX_SIGNERS)
        return

    # pick useful M value to start
    assert N >= 2
    M = (N - 1) if N < 4 else ((N//2)+1)

    while 1:
        msg = '''How many need to sign?\n      %d of %d

Press (7 or 9) to change M value, or OK \
to continue.

If you expected more or less keys (N=%d #files=%d), \
then check card and file contents.

Coldcard multisig setup file and an Electrum wallet file will be created automatically.\
''' % (M, N, N, len(files))

        ch = await ux_show_story(msg, escape='123479')

        if ch in '1234':
            M = min(N, int(ch))     # undocumented shortcut
        elif ch == '9':
            M = min(N, M+1)
        elif ch == '7':
            M = max(1, M-1)
        elif ch == 'x':
            await ux_dramatic_pause('Aborted.', 2)
            return
        elif ch == 'y':
            break
        
    # create appropriate object
    assert 1 <= M <= N <= MAX_SIGNERS

    name = 'CC-%d-of-%d' % (M, N)
    ms = MultisigWallet(name, (M, N), xpubs, chain_type=chain.ctype,
                            common_prefix=deriv[2:], addr_fmt=addr_fmt)

    from auth import NewEnrollRequest, UserAuthorizedAction

    UserAuthorizedAction.active_request = NewEnrollRequest(ms, auto_export=True)

    # menu item case: add to stack
    from ux import the_ux
    the_ux.push(UserAuthorizedAction.active_request)

async def create_ms_step1(*a):
    # Show story, have them pick address format.

    ch = await ux_show_story('''\
Insert SD card with exported XPUB files from at least one other \
Coldcard. A multisig wallet will be constructed using those keys and \
this device.

Default is P2WSH addresses (segwit), but press (1) for P2WSH-P2SH or (2) for P2SH (legacy) instead.
''', escape='12')

    if ch == 'y':
        n, f = 'p2wsh', AF_P2WSH
    elif ch == '1':
        n, f = 'p2wsh_p2sh', AF_P2WSH_P2SH
    elif ch == '2':
        n, f = 'p2sh', AF_P2SH
    else:
        return

    return await ondevice_multisig_create(n, f)


# EOF
