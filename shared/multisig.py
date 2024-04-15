# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# multisig.py - support code for multisig signing and p2sh in general.
#
import stash, chains, ustruct, ure, uio, sys, ngu, uos, ujson, version
from utils import xfp2str, str2xfp, swab32, cleanup_deriv_path, keypath_to_str, to_ascii_printable
from utils import str_to_keypath, problem_file_line, parse_extended_key
from ux import ux_show_story, ux_confirm, ux_dramatic_pause, ux_clear_keys, ux_enter_bip32_index
from files import CardSlot, CardMissingError, needs_microsd
from descriptor import MultisigDescriptor, multisig_descriptor_template
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AFC_SCRIPT, MAX_SIGNERS
from menu import MenuSystem, MenuItem
from opcodes import OP_CHECKMULTISIG
from exceptions import FatalPSBTIssue
from glob import settings
from charcodes import KEY_NFC, KEY_CANCEL, KEY_QR
from wallet import WalletABC, MAX_BIP32_IDX

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

def make_redeem_script(M, nodes, subkey_idx):
    # take a list of BIP-32 nodes, and derive Nth subkey (subkey_idx) and make
    # a standard M-of-N redeem script for that. Always applies BIP-67 sorting.
    N = len(nodes)
    assert 1 <= M <= N <= MAX_SIGNERS

    pubkeys = []
    for n in nodes:
        copy = n.copy()
        copy.derive(subkey_idx, False)
        # 0x21 = 33 = len(pubkey) = OP_PUSHDATA(33)
        pubkeys.append(b'\x21' + copy.pubkey())
        del copy

    pubkeys.sort()

    # serialize redeem script
    pubkeys.insert(0, bytes([80 + M]))
    pubkeys.append(bytes([80 + N, OP_CHECKMULTISIG]))

    return b''.join(pubkeys)

class MultisigWallet(WalletABC):
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
        (AF_P2WSH_P2SH, 'p2sh-p2wsh'),      # preferred
        (AF_P2WSH_P2SH, 'p2wsh-p2sh'),      # obsolete (now an alias)
    ]

    # optional: user can short-circuit many checks (system wide, one power-cycle only)
    disable_checks = False

    def __init__(self, name, m_of_n, xpubs, addr_fmt=AF_P2SH, chain_type='BTC'):
        self.storage_idx = -1

        self.name = name
        assert len(m_of_n) == 2
        self.M, self.N = m_of_n
        self.chain_type = chain_type or 'BTC'
        assert len(xpubs[0]) == 3
        self.xpubs = xpubs                  # list of (xfp(int), deriv, xpub(str))
        self.addr_fmt = addr_fmt            # address format for wallet

        # calc useful cache value: numeric xfp+subpath, with lookup
        self.xfp_paths = {}
        for xfp, deriv, xpub in self.xpubs:
            self.xfp_paths[xfp] = str_to_keypath(xfp, deriv)

        assert len(self.xfp_paths) == self.N, 'dup XFP'         # not supported

    @classmethod
    def render_addr_fmt(cls, addr_fmt):
        for k, v in cls.FORMAT_NAMES:
            if k == addr_fmt:
                return v.upper()
        return '?'

    def render_path(self, change_idx, idx):
        # assuming shared derivations for all cosigners. Wrongish.
        derivs, _ = self.get_deriv_paths()
        if len(derivs) > 1:
            deriv = '(various)'
        else:
            deriv = derivs[0]
        return deriv + '/%d/%d' % (change_idx, idx)

    @property
    def chain(self):
        return chains.get_chain(self.chain_type)

    @classmethod
    def get_trust_policy(cls):

        which = settings.get('pms', None)

        if which is None:
            which = TRUST_VERIFY if cls.exists() else TRUST_OFFER

        return which

    def serialize(self):
        # return a JSON-able object

        opts = dict()
        if self.addr_fmt != AF_P2SH:
            opts['ft'] = self.addr_fmt
        if self.chain_type != 'BTC':
            opts['ch'] = self.chain_type

        # Data compression: most legs will all use same derivation.
        # put a int(0) in place and set option 'pp' to be derivation
        # (used to be common_prefix assumption)
        pp = list(sorted(set(d for _,d,_ in self.xpubs)))
        if len(pp) == 1:
            # generate old-format data, to preserve firmware downgrade path
            xp = [(a, c) for a,deriv,c in self.xpubs]
            opts['pp'] = pp[0]
        else:
            # allow for distinct deriv paths on each leg
            opts['d'] = pp
            xp = [(a, pp.index(deriv),c) for a,deriv,c in self.xpubs]

        return (self.name, (self.M, self.N), xp, opts)

    @classmethod
    def deserialize(cls, vals, idx=-1):
        # take json object, make instance.
        name, m_of_n, xpubs, opts = vals

        if len(xpubs[0]) == 2:
            # promote from old format to new: assume common prefix is the derivation
            # for all of them
            # PROBLEM: we don't have enough info if no common prefix can be assumed
            common_prefix = opts.get('pp', None)
            if not common_prefix:
                # TODO: this should raise a warning, not supported anymore
                common_prefix = 'm'
            xpubs = [(a, common_prefix, b) for a,b in xpubs]
        else:
            # new format decompression
            if 'd' in opts:
                derivs = opts.get('d', None)
                xpubs = [(a, derivs[b], c) for a,b,c in xpubs]

        rv = cls(name, m_of_n, xpubs, addr_fmt=opts.get('ft', AF_P2SH),
                 chain_type=opts.get('ch', 'BTC'))
        rv.storage_idx = idx

        return rv

    @classmethod
    def iter_wallets(cls, M=None, N=None, not_idx=None, addr_fmt=None):
        # yield MS wallets we know about, that match at least right M,N if known.
        # - this is only place we should be searching this list, please!!
        lst = settings.get('multisig', [])

        for idx, rec in enumerate(lst):
            if idx == not_idx:
                # ignore one by index
                continue

            if M or N:
                # peek at M/N
                has_m, has_n = tuple(rec[1])
                if M is not None and has_m != M: continue
                if N is not None and has_n != N: continue

            if addr_fmt is not None:
                opts = rec[3]
                af = opts.get('ft', AF_P2SH)
                if af != addr_fmt: continue
                
            yield cls.deserialize(rec, idx)

    def get_xfp_paths(self):
        # return list of lists [xfp, *deriv]
        return list(self.xfp_paths.values())

    @classmethod
    def find_match(cls, M, N, xfp_paths, addr_fmt=None):
        # Find index of matching wallet
        # - xfp_paths is list of lists: [xfp, *path] like in psbt files
        # - M and N must be known
        # - returns instance, or None if not found
        for rv in cls.iter_wallets(M, N, addr_fmt=addr_fmt):
            if rv.matching_subpaths(xfp_paths):
                return rv

        return None

    @classmethod
    def find_candidates(cls, xfp_paths, addr_fmt=None, M=None):
        # Return a list of matching wallets for various M values.
        # - xpfs_paths should already be sorted
        # - returns set of matches, of any M value

        # we know N, but not M at this point.
        N = len(xfp_paths)
        
        matches = []
        for rv in cls.iter_wallets(M=M, addr_fmt=addr_fmt):
            if rv.matching_subpaths(xfp_paths):
                matches.append(rv)

        return matches

    def matching_subpaths(self, xfp_paths):
        # Does this wallet use same set of xfp values, and 
        # the same prefix path per-each xfp, as indicated 
        # xfp_paths (unordered)?
        # - could also check non-prefix part is all non-hardened
        if len(xfp_paths) != len(self.xfp_paths):
            # cannot be the same if  len(w0.N) != len(w1.N)
            # maybe check duplicates first?
            return False
        for x in xfp_paths:
            if x[0] not in self.xfp_paths:
                return False
            prefix = self.xfp_paths[x[0]]

            if len(x) < len(prefix):
                # PSBT specs a path shorter than wallet's xpub
                #print('path len: %d vs %d' % (len(prefix), len(x)))
                return False

            comm = len(prefix)
            if tuple(prefix[:comm]) != tuple(x[:comm]):
                # xfp => maps to wrong path
                #print('path mismatch:\n%r\n%r\ncomm=%d' % (prefix[:comm], x[:comm], comm))
                return False

        return True

    def assert_matching(self, M, N, xfp_paths):
        # compare in-memory wallet with details recovered from PSBT
        # - xfp_paths must be sorted already
        assert (self.M, self.N) == (M, N), "M/N mismatch"
        assert len(xfp_paths) == N, "XFP count"
        if self.disable_checks: return
        assert self.matching_subpaths(xfp_paths), "wrong XFP/derivs"

    @classmethod
    def quick_check(cls, M, N, xfp_xor):
        # quicker? USB method.
        rv = []
        for ms in cls.iter_wallets(M, N):
            x = 0
            for xfp in ms.xfp_paths.keys():
                x ^= xfp
            if x != xfp_xor: continue

            return True

        return False

    @classmethod
    def get_all(cls):
        # return them all, as a generator
        return cls.iter_wallets()

    @classmethod
    def exists(cls):
        # are there any wallets defined?
        return bool(settings.get('multisig', False))

    @classmethod
    def get_by_idx(cls, nth):
        # instance from index number (used in menu)
        lst = settings.get('multisig', [])
        try:
            obj = lst[nth]
        except IndexError:
            return None

        return cls.deserialize(obj, nth)

    def commit(self):
        # data to save
        # - important that this fails immediately when nvram overflows
        obj = self.serialize()

        v = settings.get('multisig', [])
        orig = v.copy()
        if not v or self.storage_idx == -1:
            # create
            self.storage_idx = len(v)
            v.append(obj)
        else:
            # update in place
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

    def has_similar(self):
        # check if we already have a saved duplicate to this proposed wallet
        # - return (name_change, diff_items, count_similar) where:
        #   - name_change is existing wallet that has exact match, different name
        #   - diff_items: text list of similarity/differences
        #   - count_similar: same N, same xfp+paths

        lst = self.get_xfp_paths()
        c = self.find_match(self.M, self.N, lst, addr_fmt=self.addr_fmt)
        if c:
            # All details are same: M/N, paths, addr fmt
            if self.xpubs != c.xpubs:
                return None, ['xpubs'], 0
            elif self.name == c.name:
                return None, [], 1
            else:
                return c, ['name'], 0

        similar = MultisigWallet.find_candidates(lst)
        if not similar:
            # no matches, good.
            return None, [], 0

        # See if the xpubs are changing, which is risky... other differences like
        # name are okay.
        diffs = set()
        name_diff = None
        for c in similar:
            if c.M != self.M:
                diffs.add('M differs')
            if c.addr_fmt != self.addr_fmt:
                diffs.add('address type')
            if c.name != self.name:
                diffs.add('name')
            if c.xpubs != self.xpubs:
                diffs.add('xpubs')

        return None, diffs, len(similar)

    def delete(self):
        # remove saved entry
        # - important: not expecting more than one instance of this class in memory
        assert self.storage_idx >= 0

        # safety check
        for existing in self.iter_wallets(M=self.M, N=self.N, addr_fmt=self.addr_fmt):
            if existing.storage_idx != self.storage_idx: continue
            break
        else:
            raise IndexError        # consistency bug

        lst = settings.get('multisig', [])
        del lst[self.storage_idx]
        settings.set('multisig', lst)
        settings.save()

        self.storage_idx = -1

    def xpubs_with_xfp(self, xfp):
        # return set of indexes of xpubs with indicated xfp
        return set(xp_idx for xp_idx, (wxfp, _, _) in enumerate(self.xpubs)
                        if wxfp == xfp)

    def yield_addresses(self, start_idx, count, change_idx=0):
        # Assuming a suffix of /0/0 on the defined prefix's, yield
        # possible deposit addresses for this wallet.
        ch = self.chain

        assert self.addr_fmt, 'no addr fmt known'

        # setup
        nodes = []
        paths = []
        for xfp, deriv, xpub in self.xpubs:
            # load bip32 node for each cosigner
            node = ch.deserialize_node(xpub, AF_P2SH)
            node.derive(change_idx, False)
            # indicate path used (for UX)
            path = "[%s/%s/%d/{idx}]" % (xfp2str(xfp), deriv[2:], change_idx)
            nodes.append(node)
            paths.append(path)

        idx = start_idx
        while count:
            if idx > MAX_BIP32_IDX:
                break
            # make the redeem script, convert into address
            script = make_redeem_script(self.M, nodes, idx)
            addr = ch.p2sh_address(self.addr_fmt, script)

            yield idx, addr, [p.format(idx=idx) for p in paths], script

            idx += 1
            count -= 1

    def validate_script(self, redeem_script, subpaths=None, xfp_paths=None):
        # Check we can generate all pubkeys in the redeem script, raise on errors.
        # - working from pubkeys in the script, because duplicate XFP can happen
        # - if disable_checks is set better to handle in caller, but we're also neutered
        #
        # redeem_script: what we expect and we were given
        # subpaths: pubkey => (xfp, *path)
        # xfp_paths: (xfp, *path) in same order as pubkeys in redeem script

        subpath_help = []
        used = set()
        ch = self.chain

        M, N, pubkeys = disassemble_multisig(redeem_script)
        assert M==self.M and N == self.N, 'wrong M/N in script'

        if self.disable_checks: return ['UNVERIFIED']

        for pk_order, pubkey in enumerate(pubkeys):
            check_these = []

            # TODO: this could be simpler now that XFP is unique per co-signer
            if subpaths:
                # in PSBT, we are given a map from pubkey to xfp/path, use it
                # while remembering it's potentially one-2-many
                assert pubkey in subpaths, "unexpected pubkey"
                xfp, *path = subpaths[pubkey]

                for xp_idx, (wxfp, _, xpub) in enumerate(self.xpubs):
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
                xpub = self.xpubs[xp_idx][-1]

                node = ch.deserialize_node(xpub, AF_P2SH); assert node
                dp = node.depth()

                #print("%s => deriv=%s dp=%d len(path)=%d path=%s" %
                #        (xfp2str(xfp), self.xpubs[xp_idx][1], dp, len(path), path))

                if not (0 <= dp <= len(path)):
                    # obscure case: xpub isn't deep enough to represent
                    # indicated path... not wrong really.
                    too_shallow = True
                    continue

                for sp in path[dp:]:
                    assert not (sp & 0x80000000), 'hard deriv'
                    node.derive(sp, False)     # works in-place

                found_pk = node.pubkey()

                # Document path(s) used. Not sure this is useful info to user tho.
                # - Do not show what we can't verify: we don't really know the hardeneded
                #   part of the path from fingerprint to here.
                here = '[%s]' % xfp2str(xfp)
                if dp != len(path):
                    here = here[:-1] + ('/_'*dp) + keypath_to_str(path[dp:], '/', 0) + "]"

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
                assert bytes(pubkey) > bytes(pubkeys[pk_order-1]), 'BIP-67 violation'

        assert len(used) == self.N, 'not all keys used: %d of %d' % (len(used), self.N)

        return subpath_help

    @classmethod
    def from_simple_text(cls, lines):
        # standard multisig file format - more than one line
        has_mine = 0
        M, N = -1, -1
        deriv = None
        name = None
        xpubs = []
        addr_fmt = AF_P2SH
        my_xfp = settings.get('xfp')
        for ln in lines:
            # remove comments
            comm = ln.find('#')
            if comm == 0:
                continue
            if comm != -1:
                if not ln[comm + 1:comm + 2].isdigit():
                    ln = ln[0:comm]

            ln = ln.strip()

            if ':' not in ln:
                if 'pub' in ln:
                    # pointless optimization: allow bare xpub if we can calc xfp
                    label = '00000000'
                    value = ln
                else:
                    # complain?
                    # if ln: print("no colon: " + ln)
                    continue
            else:
                label, value = ln.split(':', 1)
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
                # reveal the path derivation for following key(s)
                try:
                    assert value, 'blank'
                    deriv = cleanup_deriv_path(value)
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
                    # print("Bad xfp: " + ln)
                    continue

                # deserialize, update list and lots of checks
                is_mine = cls.check_xpub(xfp, value, deriv, chains.current_chain().ctype, my_xfp, xpubs)
                if is_mine:
                    has_mine += 1
        return name, addr_fmt, xpubs, has_mine, M, N

    @classmethod
    def from_descriptor(cls, descriptor: str):
        # excpect descriptor here if only one line, normal multisig file requires more lines
        has_mine = 0
        my_xfp = settings.get('xfp')
        xpubs = []

        desc = MultisigDescriptor.parse(descriptor)
        for xfp, deriv, xpub in desc.keys:
            deriv = cleanup_deriv_path(deriv)
            is_mine = cls.check_xpub(xfp, xpub, deriv, chains.current_chain().ctype, my_xfp, xpubs)
            if is_mine:
                has_mine += 1
        return None, desc.addr_fmt, xpubs, has_mine, desc.M, desc.N

    def to_descriptor(self):
        return MultisigDescriptor(
            M=self.M, N=self.N,
            keys=self.xpubs,
            addr_fmt=self.addr_fmt,
        )

    @classmethod
    def from_file(cls, config, name=None):
        # Given a simple text file, parse contents and create instance (unsaved).
        # format is:         label: value
        # where label is:
        #       name: nameforwallet
        #       policy: M of N
        #       format: p2sh  (+etc)
        #       derivation: m/45h/0     (common prefix)
        #       (8digithex): xpub of cosigner
        #
        # Descriptor support
        #    * text file containing multisig descriptor
        #
        # quick checks:
        # - name: 1-20 ascii chars
        # - M of N line (assume N of N if not spec'd)
        # - xpub: any bip32 serialization we understand, but be consistent
        #
        expect_chain = chains.current_chain().ctype
        if "sortedmulti(" in config or MultisigDescriptor.is_descriptor(config):
            # assume descriptor, classic config should not contain sortedmulti( and check for checksum separator
            # ignore name
            _, addr_fmt, xpubs, has_mine, M, N = cls.from_descriptor(config)
        else:
            # oldschool
            lines = [line for line in config.split('\n') if line]  # remove empty lines
            parsed_name, addr_fmt, xpubs, has_mine, M, N = cls.from_simple_text(lines)
            if parsed_name:
                # if name provided in file, use that instead of name inferred from filename
                name = parsed_name

        assert len(xpubs), 'need xpubs'

        if M == N == -1:
            # default policy: all keys
            N = M = len(xpubs)

        if not name:
            # provide a default name
            name = '%d-of-%d' % (M, N)

        try:
            name = to_ascii_printable(name)
            assert 1 <= len(name) <= 20
        except:
            raise AssertionError('name must be ascii, 1..20 long')

        assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
        assert N == len(xpubs), 'wrong # of xpubs, expect %d' % N
        assert addr_fmt & AFC_SCRIPT, 'script style addr fmt'

        # check we're included... do not insert ourselves, even tho we
        # have enough info, simply because other signers need to know my xpubkey anyway
        assert has_mine != 0, 'my key not included'
        assert has_mine == 1, 'my key included more than once'

        # done. have all the parts
        return cls(name, (M, N), xpubs, addr_fmt=addr_fmt, chain_type=expect_chain)

    @classmethod
    def check_xpub(cls, xfp, xpub, deriv, expect_chain, my_xfp, xpubs):
        # Shared code: consider an xpub for inclusion into a wallet, if ok, append
        # to list: xpubs with a tuple: (xfp, deriv, xpub)
        # return T if it's our own key
        # - deriv can be None, and in very limited cases can recover derivation path
        # - could enforce all same depth, and/or all depth >= 1, but
        #   seems like more restrictive than needed, so "m" is allowed

        try:
            # Note: addr fmt detected here via SLIP-132 isn't useful
            node, chain, _ = parse_extended_key(xpub)
        except:
            raise AssertionError('unable to parse xpub')

        try:
            assert node.privkey() == None       # 'no privkeys plz'
        except ValueError:
            pass

        if expect_chain == "XRT":
            # HACK but there is no difference extended_keys - just bech32 hrp
            assert chain.ctype == "XTN"
        else:
            assert chain.ctype == expect_chain, 'wrong chain'

        depth = node.depth()

        if depth == 1:
            if not xfp:
                # allow a shortcut: zero/omit xfp => use observed parent value
                xfp = swab32(node.parent_fp())
            else:
                # generally cannot check fingerprint values, but if we can, do so.
                if not cls.disable_checks:
                    assert swab32(node.parent_fp()) == xfp, 'xfp depth=1 wrong'

        assert xfp, 'need fingerprint'          # happens if bare xpub given

        # In most cases, we cannot verify the derivation path because it's hardened
        # and we know none of the private keys involved.
        if depth == 1:
            # but derivation is implied at depth==1
            kn, is_hard = node.child_number()
            if is_hard: kn |= 0x80000000
            guess = keypath_to_str([kn], skip=0)

            if deriv:
                if not cls.disable_checks:
                    assert guess == deriv, '%s != %s' % (guess, deriv)
            else:
                deriv = guess           # reachable? doubt it

        assert deriv, 'empty deriv'         # or force to be 'm'?
        assert deriv[0] == 'm'

        # path length of derivation given needs to match xpub's depth
        if not cls.disable_checks:
            p_len = deriv.count('/')
            assert p_len == depth, 'deriv %d != %d xpub depth (xfp=%s)' % (
                                        p_len, depth, xfp2str(xfp))

            if xfp == my_xfp:
                # its supposed to be my key, so I should be able to generate pubkey
                # - might indicate collision on xfp value between co-signers,
                #   and that's not supported
                with stash.SensitiveValues() as sv:
                    chk_node = sv.derive_path(deriv)
                    assert node.pubkey() == chk_node.pubkey(), \
                                "[%s/%s] wrong pubkey" % (xfp2str(xfp), deriv[2:])

        # serialize xpub w/ BIP-32 standard now.
        # - this has effect of stripping SLIP-132 confusion away
        xpubs.append((xfp, deriv, chain.serialize_public(node, AF_P2SH)))

        return (xfp == my_xfp)

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
            for idx, (xfp, deriv, xpub) in enumerate(self.xpubs): 

                node = None
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
                                derivation=deriv, xpub=xp)

            # sign export with first p2pkh key
            return ujson.dumps(rv), False, False
            
        await make_json_wallet('Electrum multisig wallet', doit,
                                    fname_pattern=self.make_fname('el', 'json'))

    async def export_wallet_file(self, mode="exported from", extra_msg=None, descriptor=False,
                                 core=False, desc_pretty=True):
        # create a text file with the details; ready for import to next Coldcard
        from glob import NFC
        from ux import import_export_prompt, show_qr_code

        my_xfp = xfp2str(settings.get('xfp'))
        if core:
            name = "Bitcoin Core"
            fname_pattern = self.make_fname('bitcoin-core')
        elif descriptor:
            name = "Descriptor"
            fname_pattern = self.make_fname('desc')
        else:
            name = "Coldcard"
            fname_pattern = self.make_fname('export')

        hdr = '%s %s' % (mode, my_xfp)
        label = "%s multisig setup" % name

        choice = await import_export_prompt("%s file" % label, is_import=False)
        if choice == KEY_CANCEL:
            return
        elif choice in (KEY_NFC, KEY_QR):
            with uio.StringIO() as fp:
                self.render_export(fp, hdr_comment=hdr, descriptor=descriptor,
                                   core=core, desc_pretty=desc_pretty)
                if choice == KEY_NFC:
                    await NFC.share_text(fp.getvalue())
                else:
                    try:
                        await show_qr_code(fp.getvalue())
                    except (ValueError, RuntimeError):
                        if version.has_qwerty:
                            # do BBQr on Q
                            from ux_q1 import show_bbqr_codes
                            await show_bbqr_codes('U', fp.getvalue(), label)
            return

        try:
            with CardSlot(**choice) as card:
                fname, nice = card.pick_filename(fname_pattern)

                # do actual write
                with open(fname, 'w+') as fp:
                    self.render_export(fp, hdr_comment=hdr, descriptor=descriptor,
                                       core=core, desc_pretty=desc_pretty)
                #     fp.seek(0)
                #     contents = fp.read()
                # TODO re-enable once we know how to proceed with regards to with which key to sign
                # from auth import write_sig_file
                # h = ngu.hash.sha256s(contents.encode())
                # sig_nice = write_sig_file([(h, fname)])

            msg = '%s file written:\n\n%s' % (label, nice)
            # msg += '\n\nColdcard multisig signature file written:\n\n%s' % sig_nice
            if extra_msg:
                msg += extra_msg

            await ux_show_story(msg)

        except CardMissingError:
            await needs_microsd()
            return
        except Exception as e:
            await ux_show_story('Failed to write!\n\n\n'+str(e))
            return

    def render_export(self, fp, hdr_comment=None, descriptor=False, core=False, desc_pretty=True):
        if descriptor:
            # serialize descriptor
            desc_obj = self.to_descriptor()
            if core:
                core_obj = desc_obj.bitcoin_core_serialize()
                core_str = ujson.dumps(core_obj)
                print("importdescriptors '%s'\n" % core_str, file=fp)
            else:
                if desc_pretty:
                    desc = desc_obj.pretty_serialize()
                else:
                    desc = desc_obj.serialize()
                print("%s\n" % desc, file=fp)
        else:
            if hdr_comment:
                print("# Coldcard Multisig setup file (%s)\n#" % hdr_comment, file=fp)

            print("Name: %s\nPolicy: %d of %d" % (self.name, self.M, self.N), file=fp)

            if self.addr_fmt != AF_P2SH:
                print("Format: " + self.render_addr_fmt(self.addr_fmt), file=fp)

            last_deriv = None
            for xfp, deriv, val in self.xpubs:
                if last_deriv != deriv:
                    print("\nDerivation: %s\n" % deriv, file=fp)
                    last_deriv = deriv

                print('%s: %s' % (xfp2str(xfp), val), file=fp)

    @classmethod
    def guess_addr_fmt(cls, npath):
        # Assuming  the bips are being respected, what address format will be used,
        # based on indicated numeric subkey path observed.
        # - return None if unsure, no errors
        #
        #( "m/45h", 'p2sh', AF_P2SH), 
        #( "m/48h/{coin}h/0h/1h", 'p2sh_p2wsh', AF_P2WSH_P2SH),
        #( "m/48h/{coin}h/0h/2h", 'p2wsh', AF_P2WSH)

        top = npath[0] & 0x7fffffff
        if top == npath[0]:
            # non-hardened top? rare/bad
            return

        if top == 45:
            return AF_P2SH

        if top == 48:
            if len(npath) < 4: return

            last = npath[3] & 0x7fffffff
            if last == 1:
                return AF_P2WSH_P2SH
            if last == 2:
                return AF_P2WSH

    @classmethod
    def import_from_psbt(cls, M, N, xpubs_list):
        # given the raw data from PSBT global header, offer the user
        # the details, and/or bypass that all and just trust the data.
        # - xpubs_list is a list of (xfp+path, binary BIP-32 xpub)
        # - already know not in our records.
        trust_mode = cls.get_trust_policy()

        if trust_mode == TRUST_VERIFY:
            # already checked for existing import and wasn't found, so fail
            raise FatalPSBTIssue("XPUBs in PSBT do not match any existing wallet")

        # build up an in-memory version of the wallet.
        #  - capture address format based on path used for my leg (if standards compliant)

        assert N == len(xpubs_list)
        assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
        my_xfp = settings.get('xfp')

        expect_chain = chains.current_chain().ctype
        xpubs = []
        has_mine = 0

        for k, v in xpubs_list:
            xfp, *path = ustruct.unpack_from('<%dI' % (len(k)//4), k, 0)
            xpub = ngu.codecs.b58_encode(v)
            is_mine = cls.check_xpub(xfp, xpub, keypath_to_str(path, skip=0),
                                                        expect_chain, my_xfp, xpubs)
            if is_mine:
                has_mine += 1
                addr_fmt = cls.guess_addr_fmt(path)

        assert has_mine == 1         # 'my key not included'

        name = 'PSBT-%d-of-%d' % (M, N)
        ms = cls(name, (M, N), xpubs, chain_type=expect_chain, addr_fmt=addr_fmt or AF_P2SH)

        # may just keep just in-memory version, no approval required, if we are
        # trusting PSBT's today, otherwise caller will need to handle UX w.r.t new wallet
        return ms, (trust_mode != TRUST_PSBT)

    def validate_psbt_xpubs(self, xpubs_list):
        # The xpubs provided in PSBT must be exactly right, compared to our record.
        # But we're going to use our own values from setup time anyway.
        # Check:
        # - chain codes match what we have stored already
        # - pubkey vs. path will be checked later
        # - xfp+path already checked when selecting this wallet
        # - some cases we cannot check, so count those for a warning
        # Any issue here is a fraud attempt in some way, not innocent.
        # But it would not have tricked us and so the attack targets some other signer.
        assert len(xpubs_list) == self.N

        for k, v in xpubs_list:
            xfp, *path = ustruct.unpack_from('<%dI' % (len(k)//4), k, 0)
            xpub = ngu.codecs.b58_encode(v)

            # cleanup and normalize xpub
            tmp = []
            self.check_xpub(xfp, xpub, keypath_to_str(path, skip=0), self.chain_type, 0, tmp)
            (_, deriv, xpub_reserialized) = tmp[0]
            assert deriv            # because given as arg

            if self.disable_checks:
                # allow wrong derivation paths in PSBT; but also allows usage when
                # old pre-3.2.1 MS wallet lacks derivation details for all legs
                continue

            # find in our records.
            for (x_xfp, x_deriv, x_xpub) in self.xpubs: 
                if x_xfp != xfp: continue
                # found matching XFP
                assert deriv == x_deriv

                assert xpub_reserialized == x_xpub, 'xpub wrong (xfp=%s)' % xfp2str(xfp)
                break
            else:
                assert False            # not reachable, since we picked wallet based on xfps

    def get_deriv_paths(self):
        # List of unique derivation paths being used. Often length one.
        # - also a rendered single-value summary
        derivs =  sorted(set(d for _,d,_ in self.xpubs))

        if len(derivs) == 1:
            dsum = derivs[0]
        else:
            dsum = 'Varies (%d)' % len(derivs)

        return derivs, dsum

    async def confirm_import(self):
        # prompt them about a new wallet, let them see details and then commit change.
        M, N = self.M, self.N

        if M == N == 1:
            exp = 'The one signer must approve spends.'
        elif M == N:
            exp = 'All %d co-signers must approve spends.' % N
        elif M == 1:
            exp = 'Any signature from %d co-signers will approve spends.' % N
        else:
            exp = '{M} signatures, from {N} possible co-signers, will be required to approve spends.'.format(M=M, N=N)

        # Look for duplicate stuff
        name_change, diff_items, num_dups = self.has_similar()

        is_dup = False
        if name_change:
            story = 'Update NAME only of existing multisig wallet?'
        elif diff_items:
            # Concern here is overwrite when similar, but we don't overwrite anymore, so 
            # more of a warning about funny business.
            story = '''\
WARNING: This new wallet is similar to an existing wallet, but will NOT replace it. Consider deleting previous wallet first. Differences: \
''' + ', '.join(diff_items)
        elif num_dups:
            story = 'Duplicate wallet. All details are the same as existing!'
            is_dup = True
        else:
            story = 'Create new multisig wallet?'

        derivs, dsum = self.get_deriv_paths()

        story += '''\n
Wallet Name:
  {name}

Policy: {M} of {N}

{exp}

Addresses:
  {at}

Derivation:
  {dsum}

Press (1) to see extended public keys, '''.format(M=M, N=N, name=self.name, exp=exp, dsum=dsum, 
                                        at=self.render_addr_fmt(self.addr_fmt))

        story += 'OK to approve, X to cancel.' if not is_dup else 'X to cancel'

        ux_clear_keys(True)
        while 1:
            ch = await ux_show_story(story, escape='1')

            if ch == '1':
                await self.show_detail(verbose=False)
                continue

            if ch == 'y' and not is_dup:
                # save to nvram, may raise MultisigOutOfSpace
                if name_change:
                    name_change.delete()

                assert self.storage_idx == -1
                self.commit()
                await ux_dramatic_pause("Saved.", 2)
            break

        return ch

    async def show_detail(self, verbose=True):
        # Show the xpubs; might be 2k or more rendered.
        msg = uio.StringIO()

        if verbose:
            msg.write('''
Policy: {M} of {N}
Blockchain: {ctype}
Addresses:
  {at}\n\n'''.format(M=self.M, N=self.N, ctype=self.chain_type,
            at=self.render_addr_fmt(self.addr_fmt)))

        # concern: the order of keys here is non-deterministic
        for idx, (xfp, deriv, xpub) in enumerate(self.xpubs):
            if idx:
                msg.write('\n---===---\n\n')

            msg.write('%s:\n  %s\n\n%s\n' % (xfp2str(xfp), deriv, xpub))

            if self.addr_fmt != AF_P2SH:
                # SLIP-132 format [yz]pubs here when not p2sh mode.
                # - has same info as proper bitcoin serialization, but looks much different
                node = self.chain.deserialize_node(xpub, AF_P2SH)
                xp = self.chain.serialize_public(node, self.addr_fmt)

                msg.write('\nSLIP-132 equiv:\n%s\n' % xp)

        return await ux_show_story(msg, title=self.name)

async def no_ms_yet(*a):
    # action for 'no wallets yet' menu item
    await ux_show_story("You don't have any multisig wallets yet.")

def disable_checks_chooser():
    ch = [ 'Normal', 'Skip Checks']

    def xset(idx, text):
        MultisigWallet.disable_checks = bool(idx)

    return int(MultisigWallet.disable_checks), ch, xset

async def disable_checks_menu(*a):
    from menu import start_chooser

    if not MultisigWallet.disable_checks:
        ch = await ux_show_story('''\
With many different wallet vendors and implementors involved, it can \
be hard to create a PSBT consistent with the many keys involved. \
With this setting, you can \
disable the more stringent verification checks your Coldcard normally provides.

USE AT YOUR OWN RISK. These checks exist for good reason! Signed txn may \
not be accepted by network.

This settings lasts only until power down.

Press (4) to confirm entering this DANGEROUS mode.
''', escape='4')

        if ch != '4': return

    start_chooser(disable_checks_chooser)


def psbt_xpubs_policy_chooser():
    # Chooser for trust policy
    ch = [ 'Verify Only', 'Offer Import', 'Trust PSBT']

    def xset(idx, text):
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

        if not MultisigWallet.exists():
            rv = [MenuItem('(none setup yet)', f=no_ms_yet)]
        else:
            rv = []
            for ms in MultisigWallet.get_all():
                rv.append(MenuItem('%d/%d: %s' % (ms.M, ms.N, ms.name),
                            menu=make_ms_wallet_menu, arg=ms.storage_idx))
        from glob import NFC
        rv.append(MenuItem('Import from File', f=import_multisig))
        rv.append(MenuItem('Import via NFC', f=import_multisig_nfc,
                           predicate=bool(NFC)))
        rv.append(MenuItem('Export XPUB', f=export_multisig_xpubs))
        rv.append(MenuItem('Create Airgapped', f=create_ms_step1))
        rv.append(MenuItem('Trust PSBT?', f=trust_psbt_menu))
        rv.append(MenuItem('Skip Checks?', f=disable_checks_menu))

        return rv

    def update_contents(self):
        # Reconstruct the list of wallets on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)


async def make_multisig_menu(*a):
    # list of all multisig wallets, and high-level settings/actions
    from pincodes import pa

    if not pa.has_secrets():
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
        MenuItem('Coldcard Export', f=ms_wallet_ckcc_export, arg=(ms, {})),
        MenuItem('Descriptors', menu=make_ms_wallet_descriptor_menu, arg=ms),
        MenuItem('Electrum Wallet', f=ms_wallet_electrum_export, arg=ms),
    ]
    return rv

async def make_ms_wallet_descriptor_menu(menu, label, item):
    # descriptor menu
    ms = item.arg
    if not ms:
        return

    rv = [
        MenuItem('View Descriptor', f=ms_wallet_show_descriptor, arg=ms),
        MenuItem('Export', f=ms_wallet_ckcc_export, arg=(ms, {"descriptor": True, "desc_pretty": False})),
        MenuItem('Bitcoin Core', f=ms_wallet_ckcc_export, arg=(ms, {"descriptor": True, "core": True})),
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
    ms = item.arg[0]
    kwargs = item.arg[1]
    await ms.export_wallet_file(**kwargs)

async def ms_wallet_show_descriptor(menu, label, item):
    from glob import dis
    dis.fullscreen("Wait...")
    ms = item.arg
    desc = ms.to_descriptor()
    desc_str = desc.serialize()
    ch = await ux_show_story("Press (1) to export in pretty human readable format.\n\n" + desc_str, escape="1")
    if ch == "1":
        await ms.export_wallet_file(descriptor=True, desc_pretty=True)

async def ms_wallet_electrum_export(menu, label, item):
    # create a JSON file that Electrum can use. Challenges:
    # - file contains derivation paths for each co-signer to use
    # - electrum is using BIP-43 with purpose=48 (purpose48_derivation) to make paths like:
    #       m/48h/1h/0h/2h
    # - above is now called BIP-48
    # - other signers might not be coldcards (we don't know)
    # solution: 
    # - when building air-gap, pick address type at that point, and matching path to suit
    # - could check path prefix and addr_fmt make sense together, but meh.
    ms = item.arg
    from actions import electrum_export_story

    derivs, dsum = ms.get_deriv_paths()

    msg = 'The new wallet will have derivation path:\n  %s\n and use %s addresses.\n' % (
            dsum, MultisigWallet.render_addr_fmt(ms.addr_fmt) )

    if await ux_show_story(electrum_export_story(msg)) != 'y':
        return

    await ms.export_electrum()


async def ms_wallet_detail(menu, label, item):
    # show details of single multisig wallet

    ms = item.arg

    return await ms.show_detail()


async def export_multisig_xpubs(*a):
    # WAS: Create a single text file with lots of docs, and all possible useful xpub values.
    # THEN: Just create the one-liner xpub export value they need/want to support BIP-45
    # NOW: Export JSON with one xpub per useful address type and semi-standard derivation path
    #
    # Consumer for this file is supposed to be ourselves, when we build on-device multisig.
    # - however some 3rd parties are making use of it as well.
    #
    from glob import NFC, dis
    from ux import import_export_prompt

    xfp = xfp2str(settings.get('xfp', 0))
    chain = chains.current_chain()
    
    fname_pattern = 'ccxp-%s.json' % xfp
    label = "Multisig XPUB"

    msg = '''\
This feature creates a small file containing \
the extended public keys (XPUB) you would need to join \
a multisig wallet using the 'Create Airgapped' feature.

Public keys for BIP-48 conformant paths are used:

P2SH-P2WSH:
   m/48h/{coin}h/{{acct}}h/1h
P2WSH:
   m/48h/{coin}h/{{acct}}h/2h

OK to continue. X to abort.'''.format(coin=chain.b44_cointype)

    ch = await ux_show_story(msg)
    if ch != "y":
        return

    acct_num = await ux_enter_bip32_index('Account Number:') or 0

    choice = await import_export_prompt("%s file" % label, is_import=False, no_qr=True)

    if choice == KEY_CANCEL:
        return

    dis.fullscreen('Generating...')

    todo = [
        ( "m/45h", 'p2sh', AF_P2SH),       # iff acct_num == 0
        ( "m/48h/{coin}h/{acct_num}h/1h", 'p2sh_p2wsh', AF_P2WSH_P2SH ),
        ( "m/48h/{coin}h/{acct_num}h/2h", 'p2wsh', AF_P2WSH ),
    ]

    def render(fp):
        fp.write('{\n')
        with stash.SensitiveValues() as sv:
            for deriv, name, fmt in todo:
                if fmt == AF_P2SH and acct_num:
                    continue
                dd = deriv.format(coin=chain.b44_cointype, acct_num=acct_num)
                node = sv.derive_path(dd)
                xp = chain.serialize_public(node, fmt)
                fp.write('  "%s_deriv": "%s",\n' % (name, dd))
                fp.write('  "%s": "%s",\n' % (name, xp))
                xpub = chain.serialize_public(node)
                descriptor_template = multisig_descriptor_template(xpub, dd, xfp, fmt)
                if descriptor_template is None:
                    continue
                fp.write('  "%s_desc": "%s",\n' % (name, descriptor_template))

        fp.write('  "account": "%d",\n' % acct_num)
        fp.write('  "xfp": "%s"\n}\n' % xfp)

    if choice == KEY_NFC:
        with uio.StringIO() as fp:
            render(fp)
            await NFC.share_json(fp.getvalue())
        return

    try:
        with CardSlot(**choice) as card:
            fname, nice = card.pick_filename(fname_pattern)
            # do actual write: manual JSON here so more human-readable.
            with open(fname, 'w+') as fp:
                render(fp)
            #     fp.seek(0)
            #     contents = fp.read()
            # TODO re-enable once we know how to proceed with regards to with which key to sign
            # from auth import write_sig_file
            # h = ngu.hash.sha256s(contents.encode())
            # sig_nice = write_sig_file([(h, fname)])

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '%s file written:\n\n%s' % (label, nice)
    # msg += '\n\nMultisig XPUB signature file written:\n\n%s' % sig_nice
    await ux_show_story(msg)

async def ondevice_multisig_create(mode='p2wsh', addr_fmt=AF_P2WSH, force_vdisk=False):
    # collect all xpub- exports on current SD card (must be >= 1) to make "air gapped" wallet
    # - ask for M value 
    # - create wallet, save and also export 
    # - also create electrum skel to go with that
    # - only expected to work with our ccxp-foo.json export files.
    from utils import get_filesize

    chain = chains.current_chain()
    my_xfp = settings.get('xfp')

    xpubs = []
    files = []
    has_mine = 0
    deriv = None
    try:
        with CardSlot(force_vdisk=force_vdisk) as card:
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

                    if not (0 <= file_size <= 1100):
                        # out of range size
                        continue

                    try:
                        with open(full_fname, 'rt') as fp:
                            vals = ujson.load(fp)

                        ln = vals.get(mode)

                        # value in file is BE32, but we want LE32 internally
                        xfp = str2xfp(vals['xfp'])
                        if not deriv:
                            deriv = cleanup_deriv_path(vals[mode+'_deriv'])
                        else:
                            assert deriv == vals[mode+'_deriv'], "wrong derivation: %s != %s"%(
                                            deriv, vals[mode+'_deriv'])

                        is_mine = MultisigWallet.check_xpub(xfp, ln, deriv,
                                                    chain.ctype, my_xfp, xpubs)
                        if is_mine:
                            has_mine += 1

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
            xpubs.append( (my_xfp, deriv, chain.serialize_public(node, AF_P2SH)) )
    else:
        assert has_mine == 1, "same coldcard included"

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
    ms = MultisigWallet(name, (M, N), xpubs, chain_type=chain.ctype, addr_fmt=addr_fmt)

    from auth import NewEnrollRequest, UserAuthorizedAction

    UserAuthorizedAction.active_request = NewEnrollRequest(ms, auto_export=True)

    # menu item case: add to stack
    from ux import the_ux
    the_ux.push(UserAuthorizedAction.active_request)

async def create_ms_step1(*a):
    # Show story, have them pick address format.

    ch = await ux_show_story('''\
Insert SD card (or eject SD card to use Virtual Disk) with exported XPUB files from at least one other \
Coldcard. A multisig wallet will be constructed using those keys and \
this device.

Default is P2WSH addresses (segwit) or press (1) for P2SH-P2WSH.''', escape='1')

    if ch == 'y':
        n, f = 'p2wsh', AF_P2WSH
    elif ch == '1':
        n, f = 'p2sh_p2wsh', AF_P2WSH_P2SH
    else:
        return

    return await ondevice_multisig_create(n, f)


async def import_multisig_nfc(*a):
    from glob import NFC
    # this menu option should not be available if NFC is disabled
    try:
        return await NFC.import_multisig_nfc()
    except Exception as e:
        await ux_show_story(title="ERROR", msg="Failed to import multisig. %s" % str(e))

async def import_multisig(*a):
    # pick text file from SD card, import as multisig setup file
    from actions import file_picker
    from glob import VD

    force_vdisk = False
    if VD:
        prompt = "Press (1) to import multisig wallet file from SD Card"
        escape = "1"
        if VD is not None:
            prompt += ", press (2) to import from Virtual Disk"
            escape += "2"
        prompt += "."
        ch = await ux_show_story(prompt, escape=escape)
        if ch == "1":
            force_vdisk=False
        elif ch == "2":
            force_vdisk = True
        else:
            return

    def possible(filename):
        with open(filename, 'rt') as fd:
            for ln in fd:
                if "sh(" in ln or "wsh(" in ln:
                    # descriptor import
                    return True
                if 'pub' in ln:
                    return True

    fn = await file_picker(suffix='.txt', min_size=100, max_size=20*200,
                           taster=possible, force_vdisk=force_vdisk)
    if not fn: return

    try:
        with CardSlot(force_vdisk=force_vdisk) as card:
            with open(fn, 'rt') as fp:
                data = fp.read()
    except CardMissingError:
        await needs_microsd()
        return

    from auth import maybe_enroll_xpub
    try:
        possible_name = (fn.split('/')[-1].split('.'))[0]
        maybe_enroll_xpub(config=data, name=possible_name)
    except Exception as e:
        #import sys; sys.print_exception(e)
        await ux_show_story('Failed to import.\n\n%s\n%s' % (e, problem_file_line(e)))

# EOF
