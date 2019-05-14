# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# multisig.py - support code for multisig signing and p2sh in general.
#
import stash, chains, ustruct, ure
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, swab32
from ux import ux_show_story, ux_confirm, ux_dramatic_pause
from files import CardSlot, CardMissingError
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AFC_SCRIPT
from menu import MenuSystem, MenuItem

# Bitcoin limitation: max number of signatures in CHECK_MULTISIG
# - 520 byte redeem script limit <= 15*34 bytes per pubkey == 510 bytes 
MAX_SIGNERS = const(15)

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
        self.xpubs = xpubs
        self.path_prefix = path_prefix
        self.addr_fmt = addr_fmt        # not clear how useful that is.

    def serialize(self):
        # return a JSON-able object

        opts = dict()
        if self.addr_fmt != AF_P2SH:
            opts['ft'] = self.addr_fmt
        if self.chain_type != 'BTC':
            opts['ch'] = self.chain_type
        if self.path_prefix:
            opts['pp'] = self.path_prefix

        # - xpubs must be strings already by here.
        # - but JSON doesn't allow numeric keys, so convert into a list
        xp = list(self.xpubs.items())

        return (self.name, (self.M, self.N), xp, opts)

    @property
    def chain(self):
        return chains.get_chain(self.chain_type)

    @classmethod
    def deserialize(cls, vals, idx=-1):
        # take json object, make instance.
        name, m_of_n, xpubs, opts = vals

        xpubs = dict(xpubs)

        rv = cls(name, m_of_n, xpubs, addr_fmt=opts.get('ft', AF_P2SH),
                                    path_prefix=opts.get('pp', None),
                                    chain_type=opts.get('ch', 'BTC'))
        rv.storage_idx = idx

        return rv

    @classmethod
    def find_match(cls, M, N, fingerprints):
        # Find index of matching wallet. Don't de-serialize everything.
        # - returns index, or -1 if not found
        # - fingerprints are iterable of uint32's
        from main import settings
        lst = settings.get('multisig', [])

        fingerprints = frozenset(fingerprints)
        
        for idx, rec in enumerate(lst):
            name, m_of_n, xpubs, opts = rec
            if tuple(m_of_n) != (M, N): continue
            if len(xpubs) != len(fingerprints): continue
            if set(f for f,_ in xpubs) == fingerprints:
                return idx

        return -1

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
            # update
            assert v[self.storage_idx][2].keys() == self.xpubs.keys()
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

            raise RuntimeError


    def has_dup(self):
        # check if we already have a saved duplicate to this proposed wallet
        # - also, flag if it's a dangerous/fraudulent attempt to replace it.

        idx = MultisigWallet.find_match(self.M, self.N, list(self.xpubs.keys()))
        if idx == -1:
            # no matches
            return False, 0

        # see if the xpubs are changing, which is risky... other differences like
        # name are okay.
        o = self.get_by_idx(idx)
        diffs = 0
        for k in self.xpubs:
            if o.xpubs[k] != self.xpubs[k]:
                diffs += 1

        return o, diffs

    def delete(self):
        # remove saved entry
        # - important: not expecting more than one instance of this class in memory
        from main import settings

        assert self.storage_idx >= 0

        # safety check
        expect_idx = self.find_match(self.M, self.N, self.xpubs.keys())
        assert expect_idx == self.storage_idx

        lst = settings.get('multisig', [])
        del lst[self.storage_idx]
        settings.set('multisig', lst)
        settings.save()

        self.storage_idx = -1

    def generate_script(self, subpaths, expected_witdeem=None):
        # (re)construct the witness/redeem script
        # - also output a list of the subkey paths (text)
        # - applies BIP67 to establish ordering: lexi-sort over pubkeys
        # - subpaths is a dictionary of xfp to subpath binary
        # - do checking here, raise assertions.
        from psbt import path_to_str
        from main import settings

        assert len(subpaths) == self.N
        assert set(subpaths.keys()) == set(self.xpubs.keys())
        my_xfp = settings.get('xfp')
        assert my_xfp in subpaths

        pubkeys = []
        ch = self.chain
        subpath_help = []

        for k, path in subpaths.items():
            xpub = self.xpubs[k]
            node = ch.deserialize_node(xpub, AF_P2SH)
            assert node, 'unable deserialize'
            dp = node.depth()
            assert 1 <= dp <= len(path), 'path vs depth'

            # Document path(s) used. Not sure this is useful info to user tho.
            # - Do not show what we can't verify: we don't really know the hardeneded
            #   part of the path from fingerprint to here.
            here = '(m=%s)' % xfp2str(k)
            if dp != len(path):
                here += ('/?'*dp) + path_to_str(path[-(len(path)-dp+1):], '/')
            subpath_help.append(here)

            for sp in path[dp:]:
                node.derive(sp)     # works in-place

            pubkeys.append(node.public_key())

        # lexigraphic sort
        pubkeys.sort()

        # construct a standard multisig script
        from serializations import ser_push_int, ser_push_data
        from opcodes import OP_CHECKMULTISIG

        scr = ser_push_int(self.M) + b''.join(ser_push_data(pk) for pk in pubkeys) \
                + ser_push_int(self.N) + bytes([OP_CHECKMULTISIG])

        print("redeem: " + b2a_hex(scr).decode('ascii'))

        if expected_witdeem:
            assert expected_witdeem == scr, "didn't get expected redeem script"

        return scr, subpath_help
            

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

        xpubs = {}
        M, N = -1, -1
        addr_fmt = AF_P2SH
        expect_chain = chains.current_chain().ctype
        xpub_count = 0

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

                xpub = value
                try:
                    # Note: addr_fmt_here detected here via SLIP-132 isn't useful
                    node, chain, _ = import_xpub(xpub)
                except:
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

                # de-dup and organize at same time
                xpubs[xfp] = node
                xpub_count += 1

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
        assert N == xpub_count, 'wrong # of xpubs, expect %d' % N
        assert N == len(xpubs), 'duplicate master fingerprints'
        assert addr_fmt & AFC_SCRIPT, 'script style addr fmt'

        # check we're included... do not insert ourselves, even tho we
        # have enough info, simply because other signers need to know my xpubkey anyway
        my_xfp = settings.get('xfp')
        assert my_xfp in xpubs, 'my key not included: ' + ', '.join(xfp2str(k) for k in xpubs)

        # nodes are not strings, serialize them w/ BIP32 standard now.
        # - this has effect of stripping SLIP-132 confusion away
        xxpubs = {}
        for xfp, node in xpubs.items():
            xxpubs[xfp] = chain.serialize_public(node, AF_P2SH)

        # done. have all the parts
        return cls(name, (M, N), xxpubs, addr_fmt=addr_fmt, chain_type=expect_chain)

    async def export_wallet_file(self):
        # create a text file with the details; ready for import to next Coldcard
        from main import settings
        my_xfp = xfp2str(settings.get('xfp'))

        fname_pattern = 'export-%s.txt' % self.name

        try:
            with CardSlot() as card:
                fname, nice = card.pick_filename(fname_pattern)

                # do actual write
                with open(fname, 'wt') as fp:
                    print("# Coldcard Multisig setup file (exported from %s)\n#" % my_xfp, file=fp)
                    self.render_export(fp)

            msg = '''Multisig config file written:\n\n%s''' % nice
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

        for k, v in self.xpubs.items():
            print('%s: %s' % (xfp2str(k), v), file=fp)

async def no_ms_yet(*a):
    # action for 'no wallets yet' menu item
    await ux_show_story("You don't have any multisig wallets setup yet.")

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

        return rv

    def update_contents(self):
        # reconstruct the list of wallets on this dynamic menu, because
        # we added or changed them and are showing that same emenu
        tmp = self.construct()
        self.replace_items(tmp)


async def make_multisig_menu(*a):
    rv = MultisigMenu.construct()
    return MultisigMenu(rv)


async def ms_wallet_detail(menu, label, item):
    # show details of single multisig wallet, offer to delete
    import chains, uio
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
    for idx, (xfp, xpub) in enumerate(ms.xpubs.items()):
        if idx:
            msg.write('\n')
        msg.write('%s:\n%s\n' % (xfp2str(xfp), xpub))

    # XXX TODO: add export as text file on (1) or something

    ch = await ux_show_story(msg, title=ms.name, escape='61')

    if ch == '6':
        # delete
        if not await ux_confirm("Delete this multisig wallet (%s)? Funds may be impacted."
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

# EOF
