# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# multisig.py - support code for multisig signing and p2sh in general.
#
import stash, chains, ustruct, ure
from ubinascii import hexlify as b2a_hex
from utils import xfp2str
from ux import ux_show_story, ux_confirm, ux_dramatic_pause
from files import CardSlot, CardMissingError
from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH, AFC_SCRIPT

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

        # NOTE: xpubs must be strings already here.

        return (self.name, (self.M, self.N), self.xpubs, opts)

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
        from main import settings

        obj = self.serialize()

        v = settings.get('multisig', [])
        if not v or self.storage_idx == -1:
            # create
            self.storage_idx = len(v)
            v.append(obj)
        else:
            # update
            assert v[self.storage_idx][2].keys() == self.xpubs.keys()
            v[self.storage_idx] = obj

        settings.set('multisig', v)

    @classmethod
    def find_match(cls, M, N, fingerprints):
        # Find index of matching wallet. Don't de-serialize everything.
        # - return index, or -1 if not found
        from main import settings
        lst = settings.get('multisig', [])

        fingerprints = set(fingerprints)
        
        for idx, rec in enumerate(lst):
            name, m_of_n, xpubs, opts = rec
            if tuple(m_of_n) != (M, N): continue
            if len(xpubs) != len(fingerprints): continue
            if set(xpubs.keys()) == fingerprints:
                return idx

        return -1

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

    @classmethod
    def from_file(cls, config, name=None):
        # Return a simple text file, and parse contents.
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
        addr_fmt = None
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
                # complain?
                print("no colon: " + ln)
                continue

            label, value = ln.split(':')
            label = label.lower()
            value = value.strip()

            if label == 'name':
                name = value
            elif label == 'policy':
                try:
                    mat = ure.search(r'(\d+).*(\d+)', value)
                    assert mat
                    M = int(mat.group(1))
                    N = int(mat.group(2))
                except:
                    raise AssertionError('bad M of N line')

            elif len(label) == 8:
                try:
                    xfp = int(label, 16)
                except:
                    # complain?
                    print("Bad xfp: " + ln)
                    continue

                xpub = value
                try:
                    node, chain, addr_fmt_here = import_xpub(xpub)

                    # Note: addr_fmt_here isn't so useful unless SLIP-132 is used.
                    if not (addr_fmt_here & AFC_SCRIPT):
                        addr_fmt_here = AF_P2SH
                except:
                    raise AssertionError('unable to parse xpub')

                if not addr_fmt:
                    addr_fmt = addr_fmt_here
                else:
                    # want consistent address formats
                    assert addr_fmt == addr_fmt_here, 'addr fmt'

                assert chain.ctype == expect_chain, 'wrong chain, expect: ' + expect_chain

                # de-dup and organize at same time
                xpubs[xfp] = node
                xpub_count += 1
            else:
                pass
                print("Ignore: " + ln)

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

        assert 1 <= M <= N <= 20, 'M/N range'
        assert len(xpubs), 'need xpubs'
        assert N == xpub_count, 'wrong # of xpubs, expect %d' % N
        assert N == len(xpubs), 'duplicate master fingerprints found'
        assert addr_fmt & AFC_SCRIPT, 'not a script style addr fmt'

        my_xfp = settings.get('xfp')
        assert my_xfp in xpubs, 'my key not included: ' + ', '.join(xfp2str(k) for k in xpubs)

        # nodes are not strings, serialize them w/ BIP32 standard now.
        xxpubs = {}
        for xfp, node in xpubs.items():
            xxpubs[xfp] = chain.serialize_public(node, addr_fmt)

        # done. have all the parts
        return cls(name, (M, N), xxpubs, addr_fmt=addr_fmt, chain_type=expect_chain)

async def make_multisig_menu(*a):
    # Dynamic menu with user-defined names of wallets shown
    from menu import MenuSystem, MenuItem
    from actions import import_multisig

    if not MultisigWallet.exists():
        rv = [MenuItem('(none yet)')]
    else:
        rv = []
        for ms in MultisigWallet.get_all():
            rv.append(MenuItem('%d/%d: %s' % (ms.M, ms.N, ms.name),
                        f=open_ms_wallet, arg=ms.storage_idx))

    rv.append(MenuItem('Import from SD', f=import_multisig))
    rv.append(MenuItem('Export to SD', f=export_multisig))

    return MenuSystem(rv)

async def open_ms_wallet(menu, label, item):
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

'''.format(name=ms.name, M=ms.M, N=ms.N, ctype=ms.chain_type))

    # concern: the order of keys here is non-deterministic
    for idx, (xfp, xpub) in enumerate(ms.xpubs.items()):
        if idx:
            msg.write('\n')
        msg.write('#%d: %s =\n%s\n' % (idx+1, xfp2str(xfp), xpub))

    msg.write('''

Press (6) to delete this wallet, OK or X to close.''')

    ch = await ux_show_story(msg, title=ms.name, escape='6')

    if ch == '6':
        # delete
        if not await ux_confirm("Delete this multisig wallet (%s)? Funds may be impacted."
                                                     % ms.name):
            await ux_dramatic_pause('Aborted.', 3)
            return

        ms.delete()

        await ux_dramatic_pause('Deleted.', 3)

        # update/hide from menu
        tmp = await make_multisig_menu()
        menu.replace_items(tmp.items)

def export_multisig(*a):
    # Simply create a single file with docs, and all possible useful xpub values.
    #
    # - might be nice to offer some additional alternative values, for when you want
    #   to create multiple wallets using same coldcard but we should recommend
    #   BIP39 pw for that.
    #

    variants = [( "m/45'/0", 'BIP45 standard'),
                ( "m/48'/0'/0'/1'", 'Electrum (p2wsh-p2sh)'), 
                ( "m/48'/0'/0'/2'", 'Electrum (p2wsh)'),
                #( "m/48'", 'Copay (untested)'),        # pointless unless tested
               ]

    slip132 = [
        (AF_P2SH, 'Classic P2SH'),
        (AF_P2WSH, 'Segwit P2WSH'),
        (AF_P2WSH_P2SH, 'Segwit P2WSH wrapped with P2SH'),
    ]

    from main import settings
    xfp = xfp2str(settings.get('xfp', 0))
    chain = chains.current_chain()
    
    fname_pattern = 'ms-%s.txt' % xfp

    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wt') as fp:

                fp.write('''\
# xpub for use in multisig wallets
#
# IMPORTANT: 
# - Pick only one line from this file!
# - Key path needs to match the shared multisig wallet's expectations
# - PSBT used for signing will need to encode these same paths & fingerprints
#
# Master key fingerprint is the same for for all paths: %s
#
''' % xfp)

                with stash.SensitiveValues() as sv:
                    for path, label in variants:
                        node = sv.derive_path(path, register=False)

                        for addr_fmt, alabel in slip132:
                            xp = chain.serialize_public(node, addr_fmt)
                            fp.write('''
# {label} ({alabel})   {path} = 
{xfp}: {xp}

'''.format(label=label, path=path, alabel=alabel, xfp=xfp, xp=xp))

                        stash.blank_object(node)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''Multisig export file written:\n\n%s''' % nice
    await ux_show_story(msg)

def import_xpub(ln):
    # read and xpub/ypub and return BIP32 node and what chain it's on.
    # - can handle any garbage line
    # - returns (node, chain, addr_fmt)
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
