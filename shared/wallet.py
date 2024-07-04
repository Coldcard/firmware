# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# wallet.py - A place you find UTXO, addresses and descriptors.
#
import chains
from glob import settings
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2TR
from stash import SensitiveValues


MAX_BIP32_IDX = (2 ** 31) - 1

class WalletOutOfSpace(RuntimeError):
    pass


class WalletABC:
    # How to make this ABC useful without consuming memory/code space??
    # - be more of an "interface" than a base class
    
    #   name
    #   addr_fmt
    #   chain

    def yield_addresses(self, start_idx, count, change_idx=0):
        # TODO: returns various tuples, with at least (idx, address, ...)
        pass

    def render_address(self, change_idx, idx):
        # make one single address as text.

        tmp = list(self.yield_addresses(idx, 1, change_idx=change_idx))

        assert len(tmp) == 1
        assert tmp[0][0] == idx

        return tmp[0][1]

    def to_descriptor(self):
        pass

class MasterSingleSigWallet(WalletABC):
    # Refers to current seed phrase, whichever is loaded master or temporary
    def __init__(self, addr_fmt, path=None, account_idx=0, chain_name=None):
        # Construct a wallet based on current master secret, and chain.
        # - path is optional, and then we use standard path for addr_fmt
        # - path can be overriden when we come here via address explorer
        if addr_fmt == AF_P2TR:
            n = 'Taproot P2TR'
            prefix = path or 'm/86h/{coin_type}h/{account}h'
        elif addr_fmt == AF_P2WPKH:
            n = 'Segwit P2WPKH'
            prefix = path or 'm/84h/{coin_type}h/{account}h'
        elif addr_fmt == AF_CLASSIC:
            n = 'Classic P2PKH'
            prefix = path or 'm/44h/{coin_type}h/{account}h'
        elif addr_fmt == AF_P2WPKH_P2SH:
            n =  'P2WPKH-in-P2SH'
            prefix = path or 'm/49h/{coin_type}h/{account}h'
        else:
            raise ValueError(addr_fmt)

        if chain_name:
            self.chain = chains.get_chain(chain_name)
        else:
            self.chain = chains.current_chain()

        if account_idx != 0:
            n += ' Account#%d' % account_idx

        if self.chain.ctype == 'XTN':
            n += ' (Testnet)'
        if self.chain.ctype == 'XRT':
            n += ' (Regtest)'

        self.name = n
        self.addr_fmt = addr_fmt

        # Figure out the derivation path
        # - we want to store path w/o change and index part
        p = prefix.format(account=account_idx, coin_type=self.chain.b44_cointype,
                                                    change='C', idx='I')
        if p.endswith('/C/I'):
            p = p[:-4]
        if p.endswith('/I'):
            # custom path in addr explorer can get this
            p = p[:-2]

        self._path = p

    def yield_addresses(self, start_idx, count, change_idx=None):
        # Render a range of addresses. Slow to start, since accesses SE in general
        # - if count==1, don't derive any subkey, just do path.
        path = self._path
        if change_idx is not None:
            assert 0 <= change_idx <= 1
            path += '/%d' % change_idx

        with SensitiveValues() as sv:
            node = sv.derive_path(path)

            if count is None:  # special case - showing single, ignoring start_idx
                address = self.chain.address(node, self.addr_fmt)
                yield 0, address, path
                return

            path += '/'
            for idx in range(start_idx, start_idx+count):
                if idx > MAX_BIP32_IDX:
                    break
                try:
                    here = node.copy()
                    here.derive(idx, False)            # works in-place
                    address = self.chain.address(here, self.addr_fmt)
                finally:
                    here.blank()
                    del here

                yield idx, address, path+str(idx)

    def render_address(self, change_idx, idx):
        # Optimized for a single address.
        path = self._path + '/%d/%d' % (change_idx, idx)
        with SensitiveValues() as sv:
            node = sv.derive_path(path)
            return self.chain.address(node, self.addr_fmt)

    def render_path(self, change_idx, idx):
        # show the derivation path for an address
        return self._path + '/%d/%d' % (change_idx, idx)

    def to_descriptor(self):
        from glob import settings
        from descriptor import Descriptor, Key
        xfp = settings.get('xfp')
        xpub = settings.get('xpub')
        d = Descriptor(key=Key.from_cc_data(xfp, self._path, xpub))
        d.set_from_addr_fmt(self.addr_fmt)
        return d


class BaseStorageWallet(WalletABC):
    key_name = None

    def __init__(self, chain_type=None):
        self.storage_idx = -1
        self.chain_type = chain_type or 'BTC'

    @property
    def chain(self):
        return chains.get_chain(self.chain_type)

    @classmethod
    def none_setup_yet(cls, other_chain=False):
        return '(none setup yet)' + ("*" if other_chain else "")

    @classmethod
    def is_correct_chain(cls, o, curr_chain):
        if o[1] is None:
            # mainnet
            ch = "BTC"
        else:
            ch = o[1]

        if ch == curr_chain.ctype:
            return True
        return False

    @classmethod
    def exists(cls):
        # are there any wallets defined?
        exists = False
        exists_other_chain = False
        c = chains.current_key_chain()
        for o in settings.get(cls.key_name, []):
            if cls.is_correct_chain(o, c):
                exists = True
            else:
                exists_other_chain = True

        return exists, exists_other_chain

    @classmethod
    def get_all(cls):
        # return them all, as a generator
        return cls.iter_wallets()

    @classmethod
    def iter_wallets(cls):
        # - this is only place we should be searching this list, please!!
        lst = settings.get(cls.key_name, [])
        c = chains.current_key_chain()

        for idx, rec in enumerate(lst):
            if cls.is_correct_chain(rec, c):
                yield cls.deserialize(rec, idx)

    def serialize(self):
        raise NotImplemented

    @classmethod
    def deserialize(cls, c, idx=-1):
        raise NotImplemented

    @classmethod
    def get_by_idx(cls, nth):
        # instance from index number (used in menu)
        lst = settings.get(cls.key_name, [])
        try:
            obj = lst[nth]
        except IndexError:
            return None

        return cls.deserialize(obj, nth)

    def commit(self):
        # data to save
        # - important that this fails immediately when nvram overflows
        obj = self.serialize()

        v = settings.get(self.key_name, [])
        orig = v.copy()
        if not v or self.storage_idx == -1:
            # create
            self.storage_idx = len(v)
            v.append(obj)
        else:
            # update in place
            v[self.storage_idx] = obj

        settings.set(self.key_name, v)

        # save now, rather than in background, so we can recover
        # from out-of-space situation
        try:
            settings.save()
        except:
            # back out change; no longer sure of NVRAM state
            try:
                settings.set(self.key_name, orig)
                settings.save()
            except: pass        # give up on recovery

            raise WalletOutOfSpace

    def delete(self):
        # remove saved entry
        # - important: not expecting more than one instance of this class in memory
        assert self.storage_idx >= 0
        lst = settings.get(self.key_name, [])
        try:
            del lst[self.storage_idx]
            settings.set(self.key_name, lst)
            settings.save()
        except IndexError: pass
        self.storage_idx = -1

# EOF
