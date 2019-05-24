# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# multisig.py - support code for multisig signing and p2sh in general.
#
import stash, chains, ustruct, ure, uio
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, swab32
from ux import ux_show_story, ux_confirm, ux_dramatic_pause
from files import CardSlot, CardMissingError
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AFC_SCRIPT
from menu import MenuSystem, MenuItem
from opcodes import OP_CHECKMULTISIG

# Bitcoin limitation: max number of signatures in CHECK_MULTISIG
# - 520 byte redeem script limit <= 15*34 bytes per pubkey == 510 bytes 
MAX_SIGNERS = const(15)

# PSBT Xpub trust policies
TRUST_VERIFY = const(0)
TRUST_OFFER = const(1)
TRUST_PSBT = const(2)

class MultisigOutOfSpace(RuntimeError):
    pass

def disassemble_multisig(redeem_script):
    # take apart a standard multisig's redeem/witness script, and return M/N and offset of
    # one pubkey (if provided) involved
    # - can only for multisig
    # - expect OP_1 (pk1) (pk2) (pk3) OP_3 OP_CHECKMULTISIG for 1 of 3 case
    # - returns M, N, (list of pubkeys)
    from serializations import disassemble

    M, N = -1, -1

    # generator
    dis = disassemble(redeem_script)

    # expect M value first
    M, opcode =  next(dis)
    assert opcode == None and isinstance(M, int), 'garbage at start'

    pubkeys = []
    for offset, (data, opcode) in enumerate(dis):
        if opcode == OP_CHECKMULTISIG:
            # should be last byte
            break
        if isinstance(data, int):
            N = data
        else:
            pubkeys.append(data)
    else:
        raise AssertionError("end fall")

    assert len(pubkeys) == N
    assert 1 <= M <= N <= 20, 'M/N range'      # will also happen if N not encoded.

    return M, N, pubkeys

def disassemble_multisig_mn(redeem_script):
    # pull out just M and N from script. Simple, faster, no memory.

    assert MAX_SIGNERS == 15
    assert redeem_script[-1] == OP_CHECKMULTISIG

    M = redeem_script[0] - 80
    N = redeem_script[-2] - 80

    return M, N

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

    def __init__(self, name, m_of_n, xpubs, addr_fmt=AF_P2SH, path_prefix=None, chain_type='BTC'):
        self.storage_idx = -1

        self.name = name
        assert len(m_of_n) == 2
        self.M, self.N = m_of_n
        self.chain_type = chain_type or 'BTC'
        self.xpubs = xpubs                  # list of (xfp(int), xpub(str))
        self.path_prefix = path_prefix      # half implemented? XXX kill me
        self.addr_fmt = addr_fmt            # not clear how useful that is.

        # useful cache value
        self.xfps = sorted(k for k,v in self.xpubs)

    def serialize(self):
        # return a JSON-able object

        opts = dict()
        if self.addr_fmt != AF_P2SH:
            opts['ft'] = self.addr_fmt
        if self.chain_type != 'BTC':
            opts['ch'] = self.chain_type
        if self.path_prefix:
            opts['pp'] = self.path_prefix

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
                                    path_prefix=opts.get('pp', None),
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
        assert sorted(fingerprints) == self.xfps

    @classmethod
    def get_all(cls):
        from main import settings

        lst = settings.get('multisig', [])

        for idx, v in enumerate(lst):
            yield cls.deserialize(v, idx)

    @classmethod
    def exists(cls):
        from main import settings
        return bool(settings.get('multisig', False))

    @classmethod
    def get_by_idx(cls, nth):
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
                assert pubkey in subpaths, "Unexpected pubkey"
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
            for xp_idx, path in check_these:
                # matched fingerprint, try to make pubkey that needs to match
                xpub = self.xpubs[xp_idx][1]

                node = ch.deserialize_node(xpub, AF_P2SH); assert node
                dp = node.depth()
                if not (1 <= dp <= len(path)):
                    # obscure case: xpub isn't deep enough to represent
                    # indicated path... not wrong really.
                    print('path depth')
                    continue

                for sp in path[dp:]:
                    node.derive(sp)     # works in-place

                found_pk = node.public_key()

                # Document path(s) used. Not sure this is useful info to user tho.
                # - Do not show what we can't verify: we don't really know the hardeneded
                #   part of the path from fingerprint to here.
                here = '(m=%s)' % xfp2str(xfp)
                if dp != len(path):
                    here += ('/?'*dp) + path_to_str(path[-(len(path)-dp+1):], '/')

                if found_pk != pubkey:
                    # Not a match but not an error by itself, since might be 
                    # another dup xfp to look at still.

                    print('pk mismatch: %s => %s != %s' % (
                                    here, b2a_hex(found_pk), b2a_hex(pubkey)))
                    continue

                subpath_help.append(here)

                used.add(xp_idx)
                break
            else:
                msg = 'pk#%d wrong' % (pk_order+1)
                if here:
                    msg += ', tried: ' + here
                raise AssertionError(msg)

            if pk_order:
                # verify sorted order
                assert bytes(pubkey) > bytes(pubkeys[pk_order-1]), 'BIP67 violation'

        assert len(used) == self.N, 'not all keys used: %d of %d' % (len(used), self.N)

        return subpath_help

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
        xpubs = []
        M, N = -1, -1
        has_mine = False
        addr_fmt = AF_P2SH
        expect_chain = chains.current_chain().ctype

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
                    xfp = int(label, 16)
                except:
                    # complain?
                    #print("Bad xfp: " + ln)
                    continue

                # deserialize, update list and lots of checks
                xfp = cls.check_xpub(xfp, value, expect_chain, xpubs)

                if xfp == my_xfp:
                    # not conclusive, but enough for error catching.
                    has_mine = True

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

        # done. have all the parts
        return cls(name, (M, N), xpubs, addr_fmt=addr_fmt, chain_type=expect_chain)

    @classmethod
    def check_xpub(cls, xfp, xpub, expect_chain, xpubs):
        # Shared code: consider an xpub for inclusion into a wallet, if ok, append
        # to list: xpubs.

        try:
            # Note: addr_fmt_here detected here via SLIP-132 isn't useful
            node, chain, _ = import_xpub(xpub)
        except:
            print(xpub)
            raise AssertionError('unable to parse xpub')

        assert node.private_key() == None, 'no private keys plz'
        assert chain.ctype == expect_chain, 'wrong chain, expect: ' + expect_chain

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

        # serialize xpub w/ BIP32 standard now.
        # - this has effect of stripping SLIP-132 confusion away
        xpubs.append((xfp, chain.serialize_public(node, AF_P2SH)))

        return xfp

    async def export_wallet_file(self, mode="exported from", extra_msg=None):
        # create a text file with the details; ready for import to next Coldcard
        from main import settings
        my_xfp = xfp2str(settings.get('xfp'))

        fname_pattern = 'export-%s.txt' % self.name

        try:
            with CardSlot() as card:
                fname, nice = card.pick_filename(fname_pattern)

                # do actual write
                with open(fname, 'wt') as fp:
                    print("# Coldcard Multisig setup file (%s %s)\n#" % (mode, my_xfp), file=fp)
                    self.render_export(fp)

            msg = '''Multisig config file written:\n\n%s''' % nice
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
        print("name: %s\npolicy: %d of %d" % (self.name, self.M, self.N), file=fp)

        if self.addr_fmt != AF_P2SH:
            print("format: " + dict(self.FORMAT_NAMES)[self.addr_fmt], file=fp)

        print("", file=fp)

        for xfp, val in self.xpubs:
            print('%s: %s' % (xfp2str(xfp), val), file=fp)

    @classmethod
    def import_from_psbt(cls, M, N, xpubs_dict, fetcher):
        # given the raw data fro PSBT global header, offer the user
        # the details, and/or bypass that all and just trust the data.
        # - dict is a map from (xfp+path) => binary BIP32 xpub
        # - called fetcher to get bytes of xpub
        # - already know not in our records.
        from ustruct import unpack_from
        from main import settings
        import tcc

        trust_mode = cls.get_trust_policy()

        if trust_mode == TRUST_VERIFY:
            # already checked for existing import and wasn't found, so fail
            raise AssertionError("XPUBs in PSBT do not match any existing wallet")

        # build up an in-memory version of the wallet.

        assert N == len(xpubs_dict)
        assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
        my_xfp = settings.get('xfp')

        expect_chain = chains.current_chain().ctype
        xpubs = []
        has_mine = False

        for k, v in xpubs_dict.items():
            nonce, xfp, *path = unpack_from('<%dI' % (len(k)/4), k, 0)
            xpub = tcc.codecs.b58_encode(fetcher(v))
            xfp = cls.check_xpub(xfp, xpub, expect_chain, xpubs)
            if xfp == my_xfp:
                has_mine = True

        assert has_mine, 'my key not included'

        name = 'PSBT-%d-of-%d' % (M, N)

        ms = cls(name, (M, N), xpubs, chain_type=expect_chain)

        if trust_mode == TRUST_PSBT:
            # keep just in-memory version, no approval required
            return ms, False

        assert trust_mode == TRUST_OFFER

        # caller need to handle interact w.r.t new wallet
        print("Offering import")
        return ms, True

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

Press (1) to see extended public keys, \
OK to approve, X to cancel.'''.format(M=M, N=N, name=self.name, exp=exp)

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
with the co-signer public keys (XPUBs) that may \
be provided inside a PSBT file. Three choices:

- Verify Only. Do not import the xpubs found, but do \
verify the correct wallet already exists on the Coldcard.

- Offer Import. If it's a new multisig wallet, offer to import \
the details and store them as a new wallet in the Coldcard.

- Trust PSBT. Use the wallet data in the PSBT as a temporary,
multisig wallet, and do not import it. This permits some \
deniability and additional privacy.

When the XPUB data is not provided in the PSBT, regardless of the above, \
we require the appropriate multisig wallet to already be imported \
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
                            f=ms_wallet_detail, arg=ms.storage_idx))

        rv.append(MenuItem('Import from SD', f=import_multisig))
        rv.append(MenuItem('BIP45 Export', f=export_bip45_multisig))
        rv.append(MenuItem('Trust PSBT?', f=trust_psbt_menu))

        return rv

    def update_contents(self):
        # Reconstruct the list of wallets on this dynamic menu, because
        # we added or changed them and are showing that same menu again.
        tmp = self.construct()
        self.replace_items(tmp)


async def make_multisig_menu(*a):
    rv = MultisigMenu.construct()
    return MultisigMenu(rv)

async def ms_wallet_detail(menu, label, item):
    # show details of single multisig wallet, offer to delete
    import chains
    from menu import MenuItem

    ms = MultisigWallet.get_by_idx(item.arg)
    if not ms:
        return

    msg = uio.StringIO()

    msg.write('''
policy: {M} of {N}
blockchain: {ctype}

Press (1) to export this wallet to SD card, (6) to delete the wallet, OK or X to close. \
All keys listed below.

'''.format(name=ms.name, M=ms.M, N=ms.N, ctype=ms.chain_type))

    # concern: the order of keys here is non-deterministic
    for idx, (xfp, xpub) in enumerate(ms.xpubs):
        if idx:
            msg.write('\n')
        msg.write('%s:\n%s\n' % (xfp2str(xfp), xpub))

    # XXX TODO: add export as text file on (1) or something

    ch = await ux_show_story(msg, title=ms.name, escape='61')

    if ch == '6':
        # delete
        if not await ux_confirm("Delete this multisig wallet (%s)?\n\nFunds may be impacted."
                                                     % ms.name):
            await ux_dramatic_pause('Aborted.', 3)
            return

        ms.delete()

        await ux_dramatic_pause('Deleted.', 3)

        # update/hide from menu
        menu.update_contents()

    if ch == '1':
        # create a text file with the details; ready for import to next Coldcard
        await ms.export_wallet_file()

async def export_bip45_multisig(*a):
    # WAS: Create a single file with lots of docs, and all possible useful xpub values.
    #
    # - might be nice to offer some additional alternative values, for when you want
    #   to create multiple wallets using same coldcard but we should recommend
    #   BIP39 pw for that.
    # - bad idea: confusion and interop fails exposed
    #
    # NOW: Just create the one-liner xpub export value they need/want to support BIP45

    from main import settings
    xfp = xfp2str(settings.get('xfp', 0))
    chain = chains.current_chain()
    
    fname_pattern = 'bip45-%s.txt' % xfp

    msg = '''\
This feature creates a one-line text file containing \
the xpub (extended public key) you would need to join \
a multisig wallet based on BIP45 best practises.

The public key exported is:

   m/45'

OK to continue. X to abort.
'''
    resp = await ux_show_story(msg, title='BIP45 Export')
    if resp != 'y': return

    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wt') as fp:
                with stash.SensitiveValues() as sv:
                    node = sv.derive_path("m/45'")

                    xp = chain.serialize_public(node, AF_P2SH)
                    fp.write(xp + '\n')

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

async def ondevice_multisig_create():
    # collect all BIP45- exports on current SD card (must be > 1)
    # - ask for M value 
    # - create wallet, save and also export 
    # - maybe also create electrum skel to go with
    # - only expected to work with our BIP45 export files.
    from actions import file_picker
    import uos
    from utils import get_filesize
    from main import settings

    chain = chains.current_chain()
    my_xfp = settings.get('xfp')

    xpubs = {}
    files = []
    try:
        with CardSlot() as card:
            for path in card.get_paths():
                for fn, ftype, *var in uos.ilistdir(path):
                    if ftype == 0x4000:
                        # ignore subdirs
                        continue

                    if not fn.startswith('bip45-') or not fn.endswith('.txt'):
                        # wrong prefix/suffix
                        #print('fn ' + fn)
                        continue

                    full_fname = path + '/' + fn

                    # Conside file size
                    # sigh, OS/filesystem variations
                    file_size = var[1] if len(var) == 2 else get_filesize(full_fname)

                    if not (0 <= file_size <= 200):
                        # out of range size
                        #print('sz ' + fn)
                        continue

                    with open(full_fname, 'rt') as fp:
                        ln = fp.readline().strip()

                        if ln[1:4] != 'pub':
                            #print('contents ' + fn)
                            continue

                    try:
                        node, _, _ = import_xpub(ln)
                        xfp = swab32(node.fingerprint())

                        # keep it
                        xpubs[xfp] = chain.serialize_public(node, AF_P2SH)
                        files.append(fn)
                    except:
                        #print('parse ' + fn)
                        continue

    except CardMissingError:
        await needs_microsd()
        return

    if not xpubs or len(xpubs) == 1 and xpubs.get(my_xfp):
        await ux_show_story("Unable to find any BIP45-style exported keys on this card. Must have filename: bip45-....txt and contain a single line.")
        return
    
    # add myself if not included already
    if my_xfp not in xpubs:
        with stash.SensitiveValues() as sv:
            node = sv.derive_path("m/45'")
            xpubs[my_xfp] = chain.serialize_public(node, AF_P2SH)

    N = len(xpubs)

    if N > MAX_SIGNERS:
        await ux_show_story("Too many signers, max is %d." % MAX_SIGNERS)
        return

    # pick useful M value to start
    assert N >= 2
    M = (N - 1) if N < 4 else ((N//2)+1)

    while 1:
        msg = '''How many need to sign?\n       %d of %d

Press (7 or 9) to change M value, or OK \
to continue. If you expected more or less keys (N=%d #files=%d), \
then check card and file contents.''' % (M, N, N, len(files))

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
    ms = MultisigWallet(name, (M, N), xpubs, chain_type=chain.ctype)

    from auth import NewEnrollRequest, active_request

    active_request = NewEnrollRequest(ms, auto_export=True)

    # menu item case: add to stack
    from ux import the_ux
    the_ux.push(active_request)

# EOF
